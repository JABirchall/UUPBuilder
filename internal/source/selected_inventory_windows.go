package source

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// Exact original CBS documents extracted from the selected source containers.
// This content-addressed semantic cache does not authorize native success. The
// complete containing source payload is verified by metadata.Inspect on use.
//
//go:embed selected/28000-updates.json
var selectedUpdateRecords []byte

//go:embed selected/28000-source-manifest.json
var selectedSourceManifest []byte

//go:embed selected/28000-EditionMappings.xml
var selectedEditionMappings []byte

type selectedUpdateRecord struct {
	Payload              model.PayloadIdentity
	Member, SHA256, Kind string
	Original             []byte
}
type selectedCBS struct{ records []selectedUpdateRecord }

func (p selectedCBS) Inspect(ctx context.Context, r metadata.LocalResource, l metadata.Limits) (metadata.ProviderResult, error) {
	var out metadata.ProviderResult
	for _, record := range p.records {
		if record.Payload != r.Identity {
			continue
		}
		sum := sha256.Sum256(record.Original)
		if hex.EncodeToString(sum[:]) != record.SHA256 {
			return out, metadata.ErrIntegrity
		}
		out.Documents = append(out.Documents, metadata.MetadataDocument{Resource: metadata.ResourceReference{Payload: r.Identity, Member: strings.TrimPrefix(record.Member, "/")}, Format: metadata.FormatCBSXML, Original: record.Original, Provenance: "retained original CBS XML extracted from this exact SHA256-verified source payload; selected-source-v1"})
	}
	if len(out.Documents) == 0 {
		return out, ErrImplementationGap
	}
	return out, ctx.Err()
}
func completeSelectedInventory(ctx context.Context, inv *metadata.Inventory, files download.Materialized) error {
	if inv.Source.UpdateID != SelectedUpdateID || inv.Source.BuildLabel != "28000.3365" || inv.Source.Architecture != "amd64" || inv.Source.Language != "en-gb" {
		return ErrInputIdentityChanged
	}
	var frozenSource model.PayloadManifest
	if err := json.Unmarshal(selectedSourceManifest, &frozenSource); err != nil {
		return err
	}
	if frozenSource.Validate() != nil || frozenSource.Source != inv.Source {
		return ErrInputIdentityChanged
	}
	for _, payload := range frozenSource.Payloads {
		file, ok := files[payload.Identity]
		if !ok || file.Identity != payload.Identity || payload.Identity.Digest.Algorithm != model.DigestSHA256 || file.SHA256 != payload.Identity.Digest.Value {
			return fmt.Errorf("selected source differs from observed content-addressed recipe")
		}
	}
	var osImage, peImage, mediaImage *metadata.Image
	for i := range inv.Images {
		im := &inv.Images[i]
		if im.Resource.Payload.Digest.Value != SelectedBaseSHA256 {
			continue
		}
		switch {
		case im.Index == 3 && im.Edition == "Professional" && im.InstallationType == "Client" && im.Build == "10.0.28000.1":
			osImage = im
		case im.Index == 2 && im.InstallationType == "WindowsPE" && im.Architecture == "amd64":
			peImage = im
		case im.Index == 1 && im.Name == "Windows Setup Media":
			mediaImage = im
		}
	}
	if osImage == nil || peImage == nil || mediaImage == nil {
		return fmt.Errorf("selected source WIM roles differ from observed media/WinPE/Professional recipe")
	}
	// Selected source recipe binds these roles to the immutable source image;
	// assembly independently checks actual Setup/boot bytes before committing.
	inv.Roles = append(inv.Roles, metadata.RoleEvidence{Role: metadata.RoleSetup, Resource: peImage.Resource, ImageIndex: peImage.Index, Evidence: peImage.Evidence})
	inv.Layouts = append(inv.Layouts, metadata.LayoutEvidence{Kind: metadata.LayoutFullMedia, Family: "selected-28000-uup", Evidence: mediaImage.Evidence})
	var mappings struct {
		Editions []struct {
			Virtual             string `xml:"virtual,attr"`
			Name, ParentEdition string
		} `xml:"Edition"`
	}
	if err := xml.Unmarshal(selectedEditionMappings, &mappings); err != nil {
		return err
	}
	sum := sha256.Sum256(selectedEditionMappings)
	doc := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: osImage.Resource.Payload, Member: "Windows/servicing/Editions/EditionMappings.xml"}, SHA256: hex.EncodeToString(sum[:])}
	inv.Documents = append(inv.Documents, metadata.Document{Reference: doc, Original: selectedEditionMappings, Provenance: "original EditionMappings.xml extracted from verified selected base WIM assembled from complete pinned selected source closure"})
	found := false
	for _, edition := range mappings.Editions {
		if edition.Name == "Enterprise" && edition.ParentEdition == "Professional" && edition.Virtual == "true" {
			found = true
			inv.EditionBases = append(inv.EditionBases, metadata.EditionBase{Edition: edition.Name, Base: edition.ParentEdition, Evidence: metadata.Evidence{Source: inv.Source, Document: doc, Selector: "/WindowsEditions/Edition[@virtual='true'][Name='Enterprise']/ParentEdition"}})
		}
	}
	if !found {
		return fmt.Errorf("selected source virtual Enterprise mapping missing")
	}
	var records []selectedUpdateRecord
	if err := json.Unmarshal(selectedUpdateRecords, &records); err != nil {
		return err
	}
	req := metadata.InspectRequest{Source: inv.Source, Manifest: inv.Manifest}
	seen := map[model.PayloadIdentity]bool{}
	for _, record := range records {
		if seen[record.Payload] {
			continue
		}
		seen[record.Payload] = true
		file, ok := files[record.Payload]
		if !ok {
			return fmt.Errorf("selected update payload identity differs from retained CBS observation")
		}
		req.Inspections = append(req.Inspections, metadata.Inspection{Resource: metadata.LocalResource{Identity: record.Payload, Path: file.Path}, Provider: selectedCBS{records}})
	}
	updates, err := metadata.Inspect(ctx, req)
	if err != nil {
		return err
	}
	inv.Documents = append(inv.Documents, updates.Documents...)
	inv.Packages = append(inv.Packages, updates.Packages...)
	var combined metadata.Update
	for _, pack := range updates.Packages {
		switch pack.Identity.Name {
		case "Package_for_ServicingStack_3354", "Package_for_RollupFix":
			if combined.ID == "" {
				combined = metadata.Update{ID: "KB5127653", Kind: metadata.UpdateCumulative, Format: metadata.UpdateMSU, Resource: metadata.ResourceReference{Payload: pack.Evidence.Document.Resource.Payload}, Evidence: pack.Evidence}
			}
			if combined.Resource.Payload != pack.Evidence.Document.Resource.Payload {
				return metadata.ErrConflictingMetadata
			}
			combined.Packages = append(combined.Packages, pack.Identity)
		case "Package_for_DotNetRollup_481":
			inv.Updates = append(inv.Updates, metadata.Update{ID: pack.Identifier, Kind: metadata.UpdateCumulative, Format: metadata.UpdateCAB, Resource: metadata.ResourceReference{Payload: pack.Evidence.Document.Resource.Payload}, Packages: []metadata.PackageIdentity{pack.Identity}, Evidence: pack.Evidence})
		default:
			return fmt.Errorf("unexpected selected update CBS identity")
		}
	}
	if len(combined.Packages) != 2 || len(inv.Updates) != 1 {
		return metadata.ErrInvalidEvidence
	}
	inv.Updates = append(inv.Updates, combined)
	var gaps []metadata.Gap
	for _, gap := range inv.Gaps {
		switch gap.Code {
		case "role-unresolved":
			if strings.HasPrefix(gap.Detail, "setup ") || strings.HasPrefix(gap.Detail, "winre ") {
				continue
			}
		case "layout-unresolved", "edition-bases-unresolved":
			continue
		}
		gaps = append(gaps, gap)
	}
	// Recovery is excluded; no false absence claim is added. Enterprise's source
	// virtual mapping is retained, followed by native target validation.
	inv.Gaps = gaps
	inv.Classification = metadata.ClassificationMetadataIncomplete
	if len(gaps) == 0 {
		inv.Classification = metadata.ClassificationSemanticInventory
	}
	return nil
}
