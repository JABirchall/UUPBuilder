package engine

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"uupbuilder/internal/engine/source"
	"uupbuilder/internal/jobstore"
)

func TestPreservationProofRejectsZeroForeignClosedAndAssertedAuthority(t *testing.T) {
	if (&PreservationProof{}).Descriptor().Digest != "" {
		t.Fatal("zero descriptor authority")
	}
	ctx := context.Background()
	if p, e := BindPreservationProof(ctx, &source.BoundRecipe{}, &Artifact{}, PreservationLimits{}); p != nil || e == nil {
		t.Fatal("zero authority accepted", e)
	}
	in, _, close := preservationFixture(t, false)
	r, e := source.BindCanonical(ctx, in, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	a, e := Reconstruct(ctx, r, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	foreign, _, _ := preservationFixture(t, false)
	other, e := source.BindCanonical(ctx, foreign, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	if p, e := BindPreservationProof(ctx, other, a, PreservationLimits{}); p != nil || e == nil {
		t.Fatal("foreign live source accepted", e)
	}
	if p, e := BindPreservationProof(ctx, r, a, PreservationLimits{MaxResultBytes: 1}); p != nil || !errors.Is(e, ErrLimit) {
		t.Fatal("proof budget bypass", e)
	}
	p, e := BindPreservationProof(ctx, r, a, PreservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	d := p.Descriptor()
	if d.Source.RecipeDigest != r.Descriptor().RecipeDigest || d.WIMSHA256 != a.Receipt().SHA256 || d.OutputImage.Index != 1 || d.MetadataExpectationsComplete {
		t.Fatal(d)
	}
	d.Source.Expected[0].Path = "mutated"
	d.Actions[0] = "mutated"
	d.Resources[0].SHA256 = "mutated"
	if fresh := p.Descriptor(); fresh.Source.Expected[0].Path == "mutated" || fresh.Actions[0] == "mutated" || fresh.Resources[0].SHA256 == "mutated" {
		t.Fatal("caller mutated authority")
	}
	if p, e := BindPreservationProof(ctx, r, &Artifact{receipt: a.Receipt()}, PreservationLimits{}); p != nil || e == nil {
		t.Fatal("receipt minted authority", e)
	}
	close()
	if e = p.CheckLive(); !errors.Is(e, os.ErrClosed) {
		t.Fatal("revoked source usable", e)
	}
}

type preservationInventory struct{}

func (preservationInventory) Inspect(context.Context, string) (jobstore.MountSnapshot, error) {
	return jobstore.MountSnapshot{Complete: true}, nil
}

func TestPreservationNextRequestBindsExactWIMIntentAndOwnedDestination(t *testing.T) {
	ctx := context.Background()
	in, _, _ := preservationFixture(t, false)
	r, e := source.BindCanonical(ctx, in, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	a, e := Reconstruct(ctx, r, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	p, e := BindPreservationProof(ctx, r, a, PreservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	// This is a synthetic lower-level transaction fixture, never worker graph,
	// provider proof, real mount inventory or native application authorization.
	s, e := jobstore.Create(t.TempDir(), "fixture", preservationInventory{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	intent := jobstore.MutationIntent{JobID: "fixture", PlanDigest: strings.Repeat("1", 64), ConfigDigest: strings.Repeat("2", 64), StageID: "synthetic-prerequisites", Inputs: []jobstore.NamedDigest{{Name: "preservation-proof", Digest: p.Descriptor().Digest}, {Name: "wim", Digest: a.Receipt().SHA256}}, Tools: []jobstore.VersionedIdentity{{Name: "synthetic-fixture-writer", Version: "1", Digest: strings.Repeat("3", 64)}}, Rules: []jobstore.VersionedIdentity{{Name: "prerequisites", Version: "1", Digest: p.Descriptor().Digest}}, OwnedPaths: []string{"unused.wim"}}
	tx, e := s.Begin(ctx, intent)
	if e != nil {
		t.Fatal(e)
	}
	c, e := ClaimSyntheticPreservationTree(ctx, p, tx)
	if e != nil {
		t.Fatal(e)
	}
	req, e := NewNativeApplicationRequest(ctx, p, c)
	if e != nil {
		t.Fatal(e)
	}
	spec := req.Specification()
	if spec.InputWIMSHA256 != a.Receipt().SHA256 || spec.ProofDigest != p.Descriptor().Digest || spec.Destination.Root != c.Tree().Identity().Root || spec.TransactionIntentDigest != c.IntentDigest() || len(spec.MissingPrerequisites) < 7 {
		t.Fatal(spec)
	}
	spec.MissingPrerequisites[0] = "caller assertion"
	if req.Specification().MissingPrerequisites[0] == "caller assertion" {
		t.Fatal("mutable request")
	}
	id, reader, e := p.OriginalMetadata()
	if e != nil || id.SHA256 != p.Descriptor().Resources[0].SHA256 {
		t.Fatal(id, e)
	}
	if _, e = reader.ReadAt(make([]byte, 65537), 0); !errors.Is(e, ErrLimit) {
		t.Fatal("unbounded original metadata read", e)
	}
	a2, e := Reconstruct(ctx, r, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer a2.Close()
	other, e := BindPreservationProof(ctx, r, a2, PreservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	if wrong, e := NewNativeApplicationRequest(ctx, other, c); wrong != nil || e == nil {
		t.Fatal("different generated WIM accepted for destination", e)
	}
	if e = c.Tree().Cleanup(ctx); e != nil {
		t.Fatal(e)
	}
	if e = c.Release(ctx); e != nil {
		t.Fatal(e)
	}
	if req, e := NewNativeApplicationRequest(ctx, p, c); req != nil || e == nil {
		t.Fatal("released destination accepted", e)
	}
	a.Close()
	if _, e = reader.ReadAt(make([]byte, 1), 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed generated authority reader live", e)
	}
}
