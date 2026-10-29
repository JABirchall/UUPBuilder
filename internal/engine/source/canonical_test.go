package source

import (
	"context"
	"errors"
	"strings"
	"testing"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// A name, a boot index, and a familiar UUID cannot turn PE into an OS recipe.
func TestCanonicalMatchesSemanticImageAndKeepsBaseline(t *testing.T) {
	inv := metadata.Inventory{Source: model.SourceIdentity{UpdateID: "other-source", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}}
	inv.Images = []metadata.Image{{Index: 7, Architecture: "x86", Edition: "Professional", InstallationType: "Client", Build: "10.0.19041.1"}}
	m, e := (Canonical{}).Match(inv)
	if e != nil || !m.Matched || m.ImageIndex != 7 || m.BaselineVersion != "10.0.19041.1" {
		t.Fatal(m, e)
	}
	inv.Images[0].InstallationType = "WindowsPE"
	if m, e = (Canonical{}).Match(inv); e != nil || m.Matched {
		t.Fatal("PE inferred from name/index", m, e)
	}
	inv.Images[0].InstallationType = "Client"
	inv.Images[0].Architecture = "arm64"
	if m, _ = (Canonical{}).Match(inv); m.Matched {
		t.Fatal("foreign target accepted")
	}
}

func TestCanonicalPreflightsProjectedAndSourceStrings(t *testing.T) {
	for _, in := range []Inputs{{Manifest: model.PayloadManifest{Source: model.SourceIdentity{UpdateID: strings.Repeat("x", 4097)}}}, {Manifest: model.PayloadManifest{Queries: []model.SourceQuery{{Projection: []model.Payload{{Identity: model.PayloadIdentity{Provenance: model.PackageProvenance{Name: strings.Repeat("x", 1<<20)}}}}}}}}} {
		if r, e := BindCanonical(context.Background(), in, Limits{}); r != nil || !errors.Is(e, ErrLimit) {
			t.Fatal("raw unbound fields reached validation", e)
		}
	}
}

func TestCanonicalReferencesRejectWrongOrMissingBase(t *testing.T) {
	if r, e := BindCanonical(context.Background(), Inputs{}, Limits{}); e == nil || r != nil {
		t.Fatal("zero production parents minted recipe")
	}
	if r, e := BindCanonical(nil, Inputs{}, Limits{}); e == nil || r != nil {
		t.Fatal("nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, e := BindCanonical(ctx, Inputs{}, Limits{}); e != context.Canceled || r != nil {
		t.Fatal(e)
	}
}

func TestResourceLineageIncludesOriginalByteAndReferenceIdentity(t *testing.T) {
	a := []boundResource{{ResourceIdentity{"original", "sha256", "provenance", 7, 2}, 4}}
	before := digest(a)
	a[0].identity.SHA256 = "changed"
	if digest(a) == before {
		t.Fatal("resource proof ignored byte identity")
	}
}
