//go:build windows

package source

import (
	"context"
	"errors"
	"testing"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/providers"
	"uupbuilder/internal/model"
)

// Bootstrap discovery must retain the complete upstream response for replay,
// while selecting only metadata bytes and never guessing a downloadable base.
func TestDiscoveryBindsMetadataWithoutBroadeningPayloadClosure(t *testing.T) {
	meta := sourcePayload("id.aggregatedmetadata.cab", "a")
	other := sourcePayload("unselected.esd", "b")
	c := &fixtureCatalog{sets: map[string]catalog.FileSet{"professional": sourceSet(meta, other)}, editions: []catalog.Edition{{ID: "professional"}}}
	s, _ := selectionAndSettings(t)
	s.Editions = []string{"professional"}
	d := &Discovery{Catalog: c}
	got, err := d.Metadata(context.Background(), s)
	if err != nil || len(got.Inputs) != 1 || got.Inputs[0].Identity != meta.Identity || got.Inputs[0].Provider == nil || len(got.Sets) != 1 || len(got.Sets[0].Files.Payloads) != 2 || len(got.Sets[0].Query.Projection) != 1 {
		t.Fatalf("discovery: %+v %v", got, err)
	}
	frozen, _, err := unionSets(got.Source, got.Sets)
	if err != nil || len(frozen.Payloads) != 1 {
		t.Fatalf("bootstrap closure: %+v %v", frozen, err)
	}
	bad := sourceSet(meta)
	bad.Source.UpdateID = "another-revision"
	c.sets["professional"] = bad
	if _, err := d.Metadata(context.Background(), s); !errors.Is(err, ErrInputIdentityChanged) {
		t.Fatalf("mismatched provenance: %v", err)
	}
	c.sets["professional"] = sourceSet(other)
	if _, err := d.Metadata(context.Background(), s); !errors.Is(err, ErrImplementationGap) || errors.Is(err, ErrPayloadUnavailable) {
		t.Fatalf("unsupported discovery schema marked absent upstream: %v", err)
	}
}

type unavailableContainerOperation struct{}

func (unavailableContainerOperation) Inspect(context.Context, metadata.LocalResource, metadata.Limits) (metadata.ProviderResult, error) {
	return metadata.ProviderResult{}, providers.ErrUnsupported
}

func TestUnsupportedContainerOperationRemainsImplementationGap(t *testing.T) {
	r, _ := configuredResolver(t)
	prior := r.Discover
	r.Discover = func(ctx context.Context, s model.Selection) (MetadataPlan, error) {
		p, e := prior(ctx, s)
		p.Inputs[0].Provider = unavailableContainerOperation{}
		return p, e
	}
	s, settings := selectionAndSettings(t)
	got, err := r.Resolve(context.Background(), s, settings)
	if !errors.Is(err, ErrImplementationGap) || errors.Is(err, ErrPayloadUnavailable) || got.Classification != metadata.ClassificationImplementationGap {
		t.Fatalf("missing algorithm confused with absent upstream bytes: %s %v", got.Classification, err)
	}
}

func TestAppDiscoveryDoesNotInventLicenseOrPostAssemblyEvidence(t *testing.T) {
	s, _ := selectionAndSettings(t)
	inv := metadata.Inventory{Source: sourceIdentity(), Manifest: manifestFor(t, sourcePayload("metadata.cab", "a"))}
	p := sourcePayload("unknown-name.msix", "b")
	d := &Discovery{}
	got, err := d.Apps(context.Background(), s, inv, []SourceSet{{Query: query("APP"), Files: sourceSet(p)}})
	if err != nil || len(got.Inputs) != 1 || got.Inputs[0].Provider == nil || got.Evidence != nil || got.Phase != metadata.PhaseUnknown {
		t.Fatalf("unproved app authority: %+v %v", got, err)
	}
	projected := query("APP")
	projected.Projection = []model.Payload{p}
	got, err = d.Apps(context.Background(), s, inv, []SourceSet{{Query: projected, Files: sourceSet(p, sourcePayload("unselected.msix", "c"))}})
	if err != nil || len(got.Inputs) != 1 || got.Inputs[0].Identity != p.Identity {
		t.Fatalf("app inspection broadened exact query projection: %+v %v", got, err)
	}
	e := metadata.Evidence{Source: sourceIdentity(), Document: metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: inv.Manifest.Payloads[0].Identity}, SHA256: inv.Manifest.Payloads[0].Identity.Digest.Value}, Selector: "/image/provisioned-apps"}
	inv.Documents = []metadata.Document{{Reference: e.Document}}
	inv.Apps.Packages = []metadata.AppPackage{{Phase: metadata.PhasePostAssembly, PhaseEvidence: &e}}
	got, err = d.Apps(context.Background(), s, inv, nil)
	if err != nil || got.Phase != metadata.PhasePostAssembly || got.Evidence == nil || *got.Evidence != e {
		t.Fatalf("post-assembly binding: %+v %v", got, err)
	}
	e.Source.UpdateID = "wrong"
	if _, err := d.Apps(context.Background(), s, inv, nil); !errors.Is(err, metadata.ErrInvalidEvidence) {
		t.Fatalf("foreign post-assembly evidence: %v", err)
	}
}

// Older canonical sources carry image metadata in an ESD, not an aggregated CAB.
// The routed filename supplies no image role; only the verified WIM XML can.
func TestDiscoveryRoutesSelectedWIMWithoutInventingMediaRoles(t *testing.T) {
	p := sourcePayload("professional_en-us.esd", "a")
	c := &fixtureCatalog{sets: map[string]catalog.FileSet{"professional": sourceSet(p, sourcePayload("reference.esd", "b"))}, editions: []catalog.Edition{{ID: "professional"}}}
	s, _ := selectionAndSettings(t)
	s.Editions = []string{"professional"}
	d := &Discovery{Catalog: c}
	plan, err := d.Metadata(context.Background(), s)
	if err != nil || len(plan.Inputs) != 1 || plan.Inputs[0].Identity != p.Identity || plan.Inputs[0].Provider == nil || len(plan.Sets[0].Query.Projection) != 1 {
		t.Fatalf("canonical WIM discovery unavailable: %+v %v", plan, err)
	}
}
