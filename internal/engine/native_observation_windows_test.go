package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uupbuilder/internal/jobstore"
	platform "uupbuilder/internal/platform/windows"
)

func sourceObservationClaim(t *testing.T, p *PreservationProof) *jobstore.DirectoryClaim {
	t.Helper()
	ctx := context.Background()
	s, e := jobstore.Create(t.TempDir(), "fixture", preservationInventory{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	intent := jobstore.MutationIntent{JobID: "fixture", PlanDigest: strings.Repeat("1", 64), ConfigDigest: strings.Repeat("2", 64), StageID: "read-only-observation", Inputs: []jobstore.NamedDigest{{Name: "preservation-proof", Digest: p.state.Digest}}, Tools: []jobstore.VersionedIdentity{{Name: "synthetic-fixture", Version: "1", Digest: strings.Repeat("3", 64)}}, Rules: []jobstore.VersionedIdentity{{Name: "observation-only", Version: "1", Digest: p.state.Digest}}, OwnedPaths: []string{"unused"}}
	tx, e := s.Begin(ctx, intent)
	if e != nil {
		t.Fatal(e)
	}
	c, e := tx.ClaimDirectory(ctx, p.state.Digest)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

// This catches accepting caller descriptors/foreign producers, missing original
// source lifetimes, ledger adoption, and bypassing the comparison inventory.
func TestSourceNativeObservationBindsSealedExpectationsAndLiveClaim(t *testing.T) {
	ctx := context.Background()
	p, closeSource := expectationFixture(t, true)
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	c := sourceObservationClaim(t, p)
	if s, e := newSourceNativeObservation(ctx, &SourceExpectations{}, c, platform.NativeObservationLimits{}); s != nil || e == nil {
		t.Fatal("counterfeit source", e)
	}
	foreign, _ := expectationFixture(t, true)
	fx, e := BindSourceExpectations(ctx, foreign, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	if s, e := newSourceNativeObservation(ctx, fx, c, platform.NativeObservationLimits{}); s != nil || e == nil {
		t.Fatal("foreign source", e)
	}
	if s, e := newSourceNativeObservation(ctx, x, c, platform.NativeObservationLimits{MaxEntries: 1}); s != nil || !errors.Is(e, platform.ErrTreeLimit) {
		t.Fatal("preflight count", e)
	}
	if bounded, e := newSourceNativeObservation(ctx, x, c, platform.NativeObservationLimits{MaxResultBytes: 500 << 10}); bounded != nil || !errors.Is(e, platform.ErrTreeLimit) {
		if bounded != nil {
			bounded.Close()
		}
		t.Fatal("source wrapper accepted impossible fixed metadata result profile", e)
	}
	s, e := newSourceNativeObservation(ctx, x, c, platform.NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	id := c.Tree().Identity()
	root := filepath.Join(id.Workspace.Path, filepath.FromSlash(id.RelativePath))
	if e = os.WriteFile(filepath.Join(root, "unknown"), []byte("independent"), 0600); e != nil {
		t.Fatal(e)
	}
	comparison, e := comparePreservation(ctx, x, s, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := comparison.Evidence(ctx, 32<<20)
	if e != nil {
		t.Fatal(e)
	}
	if v.Complete || !hasComparisonField(v, "path") || v.Source.Oracle != x.state.Oracle {
		t.Fatal("unknown/missing accepted or source changed", v)
	}
	closeSource()
	if e = s.beginMetadataPass(ctx); e == nil {
		t.Fatal("metadata pass survived source closure")
	}
	if e = s.CheckObservationLive(ctx); e == nil {
		t.Fatal("revoked source usable")
	}
	if _, e = comparison.Evidence(ctx, 32<<20); e == nil {
		t.Fatal("comparison survived source closure")
	}
}

func TestSourceNativeObservationOutputAndRootRevocation(t *testing.T) {
	for _, kind := range []string{"output", "root"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			p, _ := expectationFixture(t, true)
			x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
			if e != nil {
				t.Fatal(e)
			}
			c := sourceObservationClaim(t, p)
			s, e := newSourceNativeObservation(ctx, x, c, platform.NativeObservationLimits{})
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if kind == "output" {
				p.artifact.Close()
			} else {
				c.Tree().Close()
			}
			if _, e = s.ObserveInventory(ctx, platform.TreeLimits{}); e == nil {
				t.Fatal("closed parent usable")
			}
		})
	}
}
