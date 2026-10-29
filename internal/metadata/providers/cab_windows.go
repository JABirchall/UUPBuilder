package providers

import (
	"context"
	"io"
	"strings"
	"uupbuilder/internal/metadata"
)

// CAB selects metadata member candidates; semantic facts come from parsed XML.
type CAB struct{ Members []string }

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
				names = append(names, member.Name)
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
	total := int64(0)
	maxTotal := limits.MaxTotalBytes
	if maxTotal == 0 {
		maxTotal = 32 << 20
	}
	if maxTotal < 0 || maxTotal > 32<<20 {
		return out, metadata.ErrLimit
	}
	for _, name := range names {
		data := decoded[name]
		member := name
		if len(data) >= 4 && string(data[:4]) == "MSCF" {
			nested, e := metadata.InspectCAB(ctx, data)
			if e != nil {
				return out, e
			}
			if len(nested.Members) != 1 || !strings.HasSuffix(strings.ToLower(nested.Members[0].Name), ".xml") {
				return out, ErrUnsupported
			}
			inner := nested.Members[0].Name
			if int64(nested.Members[0].Size) > limit {
				return out, metadata.ErrLimit
			}
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
