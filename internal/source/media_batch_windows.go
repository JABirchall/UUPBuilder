package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// A job may have many independent app/resource archives. The original Inspect
// limits still apply to every batch/container; retained original+decoded bytes
// remain bounded across the entire job. This separate finite count bounds the
// aggregate index, rather than treating 256 independent files as one archive.
const mediaInventoryDocumentLimit = 8192
const mediaInspectionBatchSize = 128

type mediaNamedProvider struct {
	provider metadata.ReadOnlyProvider
	name     string
}

func (p mediaNamedProvider) Inspect(ctx context.Context, r metadata.LocalResource, l metadata.Limits) (metadata.ProviderResult, error) {
	result, err := p.provider.Inspect(ctx, r, l)
	if err != nil {
		return result, fmt.Errorf("verified source payload %q (%T): %w", p.name, p.provider, err)
	}
	return result, nil
}

func mediaDocumentBytes(doc metadata.Document) (int, error) {
	if doc.Gzip {
		return 0, fmt.Errorf("%w: aggregate media inventory does not accept unaccounted compressed metadata", metadata.ErrInvalidEvidence)
	}
	if len(doc.Original) > mediaDocumentLimit {
		return 0, metadata.ErrLimit
	}
	decoded, err := decodeMediaText(string(doc.Original))
	if err != nil {
		return 0, err
	}
	cost := max(len(doc.Original), len(decoded))
	if cost > mediaDocumentLimit {
		return 0, metadata.ErrLimit
	}
	return cost, nil
}

func inspectMediaBatches(ctx context.Context, req metadata.InspectRequest) (metadata.Inventory, error) {
	inv := metadata.Inventory{Source: req.Source, Manifest: req.Manifest}
	inv.Manifest.Payloads = slices.Clone(req.Manifest.Payloads)
	inv.Manifest.Queries = model.CloneSourceQueries(req.Manifest.Queries)
	if len(req.Inspections) > mediaInventoryDocumentLimit {
		return inv, fmt.Errorf("source inventory has %d containers, limit %d: %w", len(req.Inspections), mediaInventoryDocumentLimit, metadata.ErrLimit)
	}
	for begin := 0; begin < len(req.Inspections); begin += mediaInspectionBatchSize {
		if err := ctx.Err(); err != nil {
			return inv, err
		}
		end := min(begin+mediaInspectionBatchSize, len(req.Inspections))
		total := 0
		for _, doc := range inv.Documents {
			cost, err := mediaDocumentBytes(doc)
			if err != nil {
				return inv, err
			}
			total += cost
		}
		remaining := mediaTotalDocumentLimit - total
		if remaining <= 0 {
			return inv, fmt.Errorf("source inventory exhausted 32 MiB after %d retained documents: %w", len(inv.Documents), metadata.ErrLimit)
		}
		batch := metadata.InspectRequest{Source: req.Source, Manifest: req.Manifest, Inspections: req.Inspections[begin:end], Limits: metadata.Limits{MaxTotalBytes: int64(remaining)}}
		part, err := metadata.Inspect(ctx, batch)
		if err != nil {
			return inv, fmt.Errorf("source metadata batch %d (containers %d..%d of %d; retained %d documents, %d bytes): %w", begin/mediaInspectionBatchSize+1, begin+1, end, len(req.Inspections), len(inv.Documents), total, err)
		}
		if err = mergeMediaInventory(&inv, part); err != nil {
			return inv, fmt.Errorf("source metadata batch %d merge: %w", begin/mediaInspectionBatchSize+1, err)
		}
	}
	if len(req.Inspections) == 0 {
		return metadata.Inspect(ctx, req)
	}
	reconcileMediaBatchGaps(&inv)
	return inv, nil
}

func mergeMediaInventory(inv *metadata.Inventory, part metadata.Inventory) error {
	if inv.Source != part.Source || inv.Manifest.Digest != part.Manifest.Digest {
		return metadata.ErrInvalidEvidence
	}
	// These read-only batches contain only WIM XML and Appx declarations. Do
	// not silently merge a future provider's unvalidated cross-container facts.
	if len(part.Updates)+len(part.Packages)+len(part.Compositions)+len(part.EditionBases)+len(part.Layouts)+len(part.Absences)+len(part.Apps.SelectionRules)+len(part.Apps.LicenseDocuments) > 0 || part.SourceEdge != nil {
		return fmt.Errorf("%w: unsupported semantic provider in media inspection batch", metadata.ErrInvalidEvidence)
	}
	for _, doc := range part.Documents {
		if err := retainMediaDocument(inv, doc); err != nil {
			return err
		}
	}
	for _, image := range part.Images {
		for _, old := range inv.Images {
			if old.Resource == image.Resource && old.Index == image.Index {
				return fmt.Errorf("%w: duplicate WIM image source/index", metadata.ErrConflictingMetadata)
			}
		}
		inv.Images = append(inv.Images, image)
	}
	for _, role := range part.Roles {
		for _, old := range inv.Roles {
			if old.Resource == role.Resource && old.ImageIndex == role.ImageIndex {
				return metadata.ErrConflictingMetadata
			}
		}
		inv.Roles = append(inv.Roles, role)
	}
	for _, app := range part.Apps.Packages {
		for _, old := range inv.Apps.Packages {
			if old.Identity == app.Identity {
				return fmt.Errorf("%w: duplicate Appx identity %s in independent source containers", metadata.ErrConflictingMetadata, metadata.AppFullName(app.Identity))
			}
		}
		inv.Apps.Packages = append(inv.Apps.Packages, app)
	}
	for _, bundle := range part.Apps.Bundles {
		for _, old := range inv.Apps.Bundles {
			if old.Identity == bundle.Identity {
				return fmt.Errorf("%w: duplicate app bundle identity %s", metadata.ErrConflictingMetadata, metadata.AppFullName(bundle.Identity))
			}
		}
		inv.Apps.Bundles = append(inv.Apps.Bundles, bundle)
	}
	for _, gap := range part.Gaps {
		duplicate := false
		for _, old := range inv.Gaps {
			sameDocument := old.Document == nil && gap.Document == nil || old.Document != nil && gap.Document != nil && *old.Document == *gap.Document
			if old.Code == gap.Code && old.Detail == gap.Detail && sameDocument {
				duplicate = true
				break
			}
		}
		if !duplicate {
			inv.Gaps = append(inv.Gaps, gap)
		}
	}
	return nil
}

func retainMediaDocument(inv *metadata.Inventory, doc metadata.Document) error {
	known := false
	for _, p := range inv.Manifest.Payloads {
		known = known || p.Identity == doc.Reference.Resource.Payload
	}
	if !known || doc.Provenance == "" {
		return metadata.ErrInvalidEvidence
	}
	if member := doc.Reference.Resource.Member; member != "" {
		if clean, err := model.ValidateRelativePath(member); err != nil || clean != member {
			return metadata.ErrInvalidEvidence
		}
	}
	sum := sha256.Sum256(doc.Original)
	if hex.EncodeToString(sum[:]) != doc.Reference.SHA256 {
		return metadata.ErrIntegrity
	}
	for _, old := range inv.Documents {
		if old.Reference.Resource == doc.Reference.Resource {
			if old.Reference != doc.Reference || old.Format != doc.Format || old.Gzip != doc.Gzip || !bytes.Equal(old.Original, doc.Original) {
				return metadata.ErrConflictingMetadata
			}
			return nil
		}
	}
	if err := mediaDocumentBudget(inv, []metadata.Document{doc}); err != nil {
		return err
	}
	inv.Documents = append(inv.Documents, doc)
	return nil
}

func reconcileMediaBatchGaps(inv *metadata.Inventory) {
	present := map[metadata.Role]bool{}
	for _, role := range inv.Roles {
		present[role.Role] = true
	}
	var gaps []metadata.Gap
	for _, gap := range inv.Gaps {
		if gap.Code == "role-unresolved" {
			role, _, _ := strings.Cut(gap.Detail, " ")
			if present[metadata.Role(role)] {
				continue
			}
		}
		if gap.Code == "app-inventory-unresolved" && len(inv.Apps.Packages) > 0 {
			continue
		}
		gaps = append(gaps, gap)
	}
	inv.Gaps = gaps
	inv.Classification = metadata.ClassificationMetadataIncomplete
	for _, gap := range gaps {
		if gap.Code == "unsupported-format" || gap.Code == "unsupported-schema" {
			inv.Classification = metadata.ClassificationImplementationGap
		}
	}
}
