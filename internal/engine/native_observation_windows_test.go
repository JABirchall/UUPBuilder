package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
	"uupbuilder/internal/engine/source"

	"uupbuilder/internal/jobstore"
	platform "uupbuilder/internal/platform/windows"
)

// Count the fixed call sequence independently: borrow + two inventory pairs,
// construction/invocation, two pass starts, comparison/post-comparison checks,
// two serialization checks, two metadata passes, and one content pass.
func fixedSourceReadBudget(t *testing.T, x *SourceExpectations, c *jobstore.DirectoryClaim) (uint64, uint64) {
	t.Helper()
	s, e := newSourceNativeObservation(context.Background(), x, c, platform.NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := s.session.Evidence(context.Background(), 16<<10)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	calls := uint64(13 + 8*len(x.entries))
	for _, en := range x.entries {
		if en.Original.Attributes&16 != 0 {
			calls += 2
		}
		for j, stream := range en.Content {
			if en.Original.Streams[j].Kind == "data" || en.Original.Streams[j].Kind == "named-data" {
				calls += 4 * ((stream.Size + 65535) / 65536)
			}
		}
	}
	// Construction performs exactly two native validations; measure their
	// actual root-parent charge rather than assuming a workspace depth.
	unit := v.ValidationAllowanceBytes / 2
	b := v.Preflight
	return b.ContentBytes + b.MetadataCapacityBytes + b.DirectoryCapacityBytes + b.IdentityQueryBytes + calls*unit, calls * unit
}

func TestSourceNativeObservationCompleteSequenceFitsComposedBudget(t *testing.T) {
	ctx := context.Background()
	in, _, _ := preservationFixtureStorageData(t, false, 7, "", 0, false, true, bytes.Repeat([]byte{0x5a}, 4<<20), true)
	recipe, e := source.BindCanonical(ctx, in, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	a, e := Reconstruct(ctx, recipe, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	p, e := BindPreservationProof(ctx, recipe, a, PreservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	c := sourceObservationClaim(t, p)
	id := c.Tree().Identity()
	root := filepath.Join(id.Workspace.Path, filepath.FromSlash(id.RelativePath))
	buf := make([]byte, 64<<10)
	for i, en := range x.entries {
		name := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(en.Original.Path, "/")))
		if en.Original.Attributes&16 != 0 {
			if e = os.MkdirAll(name, 0700); e != nil {
				t.Fatal(e)
			}
			continue
		}
		if e = os.WriteFile(name, nil, 0600); e != nil {
			t.Fatal(e)
		}
		for j, stream := range en.Content {
			if en.Original.Streams[j].Kind != "data" && en.Original.Streams[j].Kind != "named-data" {
				continue
			}
			path := name
			if en.Original.Streams[j].Kind == "named-data" {
				path += ":" + string(utf16.Decode(en.Original.Streams[j].Name))
			}
			f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if e != nil {
				t.Fatal(e)
			}
			for off := uint64(0); off < stream.Size; {
				n := min(uint64(len(buf)), stream.Size-off)
				if _, e = x.ReadOriginalAt(ctx, i, j, buf[:n], int64(off)); e != nil {
					t.Fatal(e)
				}
				if _, e = f.Write(buf[:n]); e != nil {
					t.Fatal(e)
				}
				off += n
			}
			if e = f.Close(); e != nil {
				t.Fatal(e)
			}
		}
	}
	read, validation := fixedSourceReadBudget(t, x, c)
	s, e := newSourceNativeObservation(ctx, x, c, platform.NativeObservationLimits{MaxReadBytes: read})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.CheckObservationLive(ctx); e != nil {
		t.Fatal(e)
	} // invocation
	if _, e = s.ObserveInventory(ctx, platform.TreeLimits{}); e != nil {
		t.Fatal(e)
	}
	for pass := 0; pass < 2; pass++ {
		if e = s.beginMetadataPass(ctx); e != nil {
			t.Fatal(e)
		}
		for _, en := range x.entries {
			name := strings.TrimPrefix(en.Original.Path, "/")
			if name == "" {
				name = "."
			}
			if _, e = s.Observe(ctx, name, platform.MetadataLimits{}); e != nil {
				t.Fatalf("metadata pass %d %s: %v", pass, name, e)
			}
			if pass != 0 {
				continue
			}
			for j, stream := range en.Content {
				if en.Original.Streams[j].Kind != "data" && en.Original.Streams[j].Kind != "named-data" {
					continue
				}
				ads := ""
				if en.Original.Streams[j].Kind == "named-data" {
					ads = string(utf16.Decode(en.Original.Streams[j].Name))
				}
				for off := uint64(0); off < stream.Size; {
					n := min(uint64(len(buf)), stream.Size-off)
					if _, e = s.ReadOwnedAt(ctx, name, ads, buf[:n], int64(off)); e != nil {
						t.Fatalf("content %s offset %d: %v", name, off, e)
					}
					off += n
				}
			}
		}
	}
	if _, e = s.ObserveInventory(ctx, platform.TreeLimits{}); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 4; i++ {
		if e = s.CheckObservationLive(ctx); e != nil {
			t.Fatal(e)
		}
	} // comparison, post-comparison, serialization pair
	v, e := s.session.Evidence(ctx, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if v.ValidationAllowanceBytes != validation || v.Preflight.ExpectedReadBytes != read || v.ReadBytes > read || v.ContentReadBytes != v.Preflight.ContentBytes {
		t.Fatalf("composed charge mismatch: actual validations=%d planned=%d actual read=%d declared=%d preflight=%+v", v.ValidationAllowanceBytes, validation, v.ReadBytes, read, v.Preflight)
	}
	t.Logf("entries=%d content=%d actualRead=%d declaredRead=%d actualValidation=%d plannedValidation=%d calls=%d result=%d", len(x.entries), v.ContentReadBytes, v.ReadBytes, read, v.ValidationAllowanceBytes, validation, v.Preflight.ValidationCalls, v.AccountedBytes)
}

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
