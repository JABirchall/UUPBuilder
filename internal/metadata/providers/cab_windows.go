package providers

import (
	"context"
	"io"
	"strings"
	"uupbuilder/internal/metadata"
)

// CAB selects metadata member candidates; semantic facts come from parsed XML.
type CAB struct{ Members []string }

// Intermediate cabinets are not XML documents. Bound their separate staging
// and allocation cost before extraction, even when the caller's XML budget is
// much smaller. InspectCAB independently caps each CAB member at 16 MiB.
const maxCABIntermediateTotal = 32 << 20

func (c CAB) Inspect(ctx context.Context, r metadata.LocalResource, limits metadata.Limits) (metadata.ProviderResult, error) {
	var out metadata.ProviderResult
	limit, err := documentLimit(limits)
	if err != nil {
		return out, err
	}
	if r.Identity.Size > metadata.MaxMetadataCABBytes {
		return out, metadata.ErrLimit
	}
	if len(c.Members) == 0 || len(c.Members) > 256 {
		return out, metadata.ErrInvalidInput
	}
	if limits.MaxDocuments > 0 && len(c.Members) > limits.MaxDocuments {
		return out, metadata.ErrLimit
	}
	f, err := verified(ctx, r)
	if err != nil {
		return out, err
	}
	body, readErr := io.ReadAll(contextReader{ctx, io.LimitReader(f, metadata.MaxMetadataCABBytes+1)})
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		return out, metadata.ErrIntegrity
	}
	table, err := metadata.InspectCAB(ctx, body)
	if err != nil {
		return out, err
	}
	var names []string
	var nested []bool
	maxTotal := limits.MaxTotalBytes
	if maxTotal == 0 {
		maxTotal = 32 << 20
	}
	var documentTotal, intermediateTotal int64
	seen := map[string]bool{}
	for _, candidate := range c.Members {
		key := strings.ToLower(candidate)
		if seen[key] {
			return out, metadata.ErrInvalidInput
		}
		seen[key] = true
		found := false
		for _, member := range table.Members {
			if strings.EqualFold(candidate, member.Name) {
				isNested := strings.HasSuffix(strings.ToLower(member.Name), ".xml.cab")
				if isNested {
					intermediateTotal += int64(member.Size)
					if intermediateTotal > maxCABIntermediateTotal {
						return out, metadata.ErrLimit
					}
				} else {
					if !strings.HasSuffix(strings.ToLower(member.Name), ".xml") {
						return out, metadata.ErrInvalidInput
					}
					documentTotal += int64(member.Size)
					if int64(member.Size) > limit || documentTotal > maxTotal {
						return out, metadata.ErrLimit
					}
				}
				names = append(names, member.Name)
				nested = append(nested, isNested)
				found = true
				break
			}
		}
		if !found {
			return out, ErrUnsupported
		}
	}
	decoded, err := metadata.ReadCABMetadata(ctx, body, names)
	if err != nil {
		return out, err
	}
	// Check every inner declaration against the remaining document budget
	// before any inner cabinet is expanded. A .xml.cab candidate must actually
	// be a cabinet; raw XML cannot bypass the smaller document budget via a name.
	inners := make([]string, len(names))
	for i, name := range names {
		data := decoded[name]
		isCAB := len(data) >= 4 && string(data[:4]) == "MSCF"
		if isCAB != nested[i] {
			return out, ErrUnsupported
		}
		if nested[i] {
			innerTable, e := metadata.InspectCAB(ctx, data)
			if e != nil {
				return out, e
			}
			if len(innerTable.Members) != 1 || !strings.HasSuffix(strings.ToLower(innerTable.Members[0].Name), ".xml") {
				return out, ErrUnsupported
			}
			documentTotal += int64(innerTable.Members[0].Size)
			if int64(innerTable.Members[0].Size) > limit || documentTotal > maxTotal {
				return out, metadata.ErrLimit
			}
			inners[i] = innerTable.Members[0].Name
		}
	}
	var total int64
	for i, name := range names {
		data, member := decoded[name], name
		if nested[i] {
			inner := inners[i]
			extracted, e := metadata.ReadCABMetadata(ctx, data, []string{inner})
			if e != nil {
				return out, e
			}
			data = extracted[inner]
			member += "/" + inner
		}
		total += int64(len(data))
		if int64(len(data)) > limit || total > maxTotal {
			return out, metadata.ErrLimit
		}
		out.Documents = append(out.Documents, metadata.MetadataDocument{Resource: metadata.ResourceReference{Payload: r.Identity, Member: member}, Format: metadata.FormatCompositionXML, Original: data, Provenance: "uupbuilder:installed-expand-compdb-v1"})
	}
	return out, ctx.Err()
}
