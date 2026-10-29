package engine

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"uupbuilder/internal/engine/source"
	platform "uupbuilder/internal/platform/windows"
)

func cabExpectationFixture(t *testing.T, clean ...bool) (*PreservationProof, func()) {
	t.Helper()
	ctx := context.Background()
	if len(clean) == 0 {
		clean = []bool{true}
	}
	in, _, close := preservationFixtureStorage(t, false, 7, "", 0, true, clean...)
	r, e := source.BindCanonical(ctx, in, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	a, e := Reconstruct(ctx, r, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := a.Close(); e != nil {
			t.Error(e)
		}
	})
	p, e := BindPreservationProof(ctx, r, a, PreservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	return p, close
}

// Rejecting an original unknown WIM size, using its zero as the resolved size,
// or erasing its historical gap breaks this live CAB-only producer regression.
func TestSourceExpectationsResolveCABOnlyStreamsWithoutRewritingOriginal(t *testing.T) {
	ctx := context.Background()
	p, closeSource := cabExpectationFixture(t)
	original, _, e := p.recipe.OriginalEntryAt(3, 1<<20)
	if e != nil || original.Streams[0].SizeKnown || original.Streams[0].Size != 0 {
		t.Fatal("fixture must reproduce the original missing-WIM-size state", original, e)
	}
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal("live CAB-resolved original rejected", e)
	}
	for _, tc := range []struct {
		entry, stream int
		data          string
	}{{3, 0, "shared original"}, {8, 1, "named bytes"}, {10, 0, "opaque reparse bytes"}} {
		en, e := x.EntryAt(ctx, tc.entry, 1<<20)
		if e != nil || en.Original.Streams[tc.stream].SizeKnown || en.Original.Streams[tc.stream].Size != 0 || en.Content[tc.stream].Size != uint64(len(tc.data)) || en.Content[tc.stream].SHA1 != en.Original.Streams[tc.stream].SHA1 || en.Content[tc.stream].ProvenanceDigest == "" {
			t.Fatal("original/resolved identities lost", tc, en, e)
		}
		b := make([]byte, len(tc.data))
		if n, e := x.ReadOriginalAt(ctx, tc.entry, tc.stream, b, 0); e != nil || n != len(b) || string(b) != tc.data {
			t.Fatal("CAB original reader", tc, n, e)
		}
		if tc.entry == 10 && string(en.ReparseData) != tc.data {
			t.Fatal("CAB reparse bytes omitted", en.ReparseData)
		}
	}
	d := x.Descriptor()
	if d.Oracle != p.state.Source.Oracle || d.Oracle.MetadataComplete || !d.ComparableComplete || d.OriginalGaps != 4 || d.Unresolved != 0 || d.ReadBytes != p.state.Source.Metadata.Size*2+20 {
		t.Fatal("resolved expectations changed original completeness/gaps or read charge", d)
	}
	missing := 0
	for n := 0; n < d.OriginalGaps; n++ {
		g, e := x.OriginalGapAt(ctx, n, 1<<20)
		if e != nil {
			t.Fatal(e)
		}
		if g.Kind == "missing-stream-reference" {
			missing++
		}
	}
	if missing != 3 {
		t.Fatal("original missing-WIM-reference gaps disappeared", missing)
	}
	if bounded, e := BindSourceExpectations(ctx, p, ComparisonLimits{MaxReadBytes: d.ReadBytes - 1}); bounded != nil || !errors.Is(e, ErrLimit) || !strings.Contains(e.Error(), "reparse") {
		t.Fatal("CAB reparse read budget or diagnostic lost", e)
	}
	closeSource()
	if _, e := x.ReadOriginalAt(ctx, 3, 0, make([]byte, 15), 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("CAB source closure did not revoke expectation reads", e)
	}
}

func TestSourceNativeObservationBudgetsResolvedCABStreamSizes(t *testing.T) {
	ctx := context.Background()
	p, _ := cabExpectationFixture(t)
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
	v, e := s.session.Evidence(ctx, 16<<10)
	if e != nil || v.Preflight.ContentBytes != 86 {
		t.Fatal("CAB default/named bytes omitted from source preflight", v.Preflight, e)
	}
	if bounded, e := newSourceNativeObservation(ctx, x, c, platform.NativeObservationLimits{MaxReadBytes: v.Preflight.ExpectedReadBytes - 1}); bounded != nil || !errors.Is(e, platform.ErrTreeLimit) {
		if bounded != nil {
			bounded.Close()
		}
		t.Fatal("resolved CAB content bypassed lowered native budget", e)
	}
	p.artifact.Close()
	if e := s.CheckObservationLive(ctx); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed output left CAB observation live", e)
	}
}

func TestPreservationComparisonUsesResolvedCABStreamSizes(t *testing.T) {
	ctx := context.Background()
	p, _ := cabExpectationFixture(t)
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"equal", "default-content", "named-content", "size", "reparse"} {
		t.Run(kind, func(t *testing.T) {
			native := &syntheticPreservationPort{id: platform.TreeIdentity{SourceDigest: p.state.Digest, OperationID: "synthetic-cab-comparison", Root: platform.FileIdentity{VolumeSerial: 1, FileIndex: 1}}}
			native.content = func(name, stream string, b []byte) []byte {
				if kind == "default-content" && name == "Windows/System32/ntoskrnl.exe" || kind == "named-content" && stream == "ads" {
					b[0] ^= 1
				}
				return b
			}
			native.mutate = func(name string, o *platform.MetadataObservation) {
				if kind == "size" && name == "Windows/System32/ntoskrnl.exe" {
					o.NamedStreams[0].Size--
				}
				if kind == "reparse" && name == "Windows/System32/reparse" {
					o.Reparse.Raw[8] ^= 1
				}
			}
			r, e := comparePreservation(ctx, x, native, ComparisonLimits{})
			if e != nil {
				t.Fatal(e)
			}
			v, e := r.Evidence(ctx, 32<<20)
			if e != nil || v.Source.Oracle != x.state.Oracle {
				t.Fatal("original oracle lost", e)
			}
			if kind == "equal" {
				// Two independent inventory reads each report 128 bytes.
				if !v.Complete || v.StreamsCompared != 7 || len(v.Mismatches) != 0 || len(v.Unresolved) != 0 || v.ReadBytes != p.state.Source.Metadata.Size*2+86+256 {
					t.Fatal("CAB-resolved bytes not fully compared/charged", v.Complete, v.StreamsCompared, v.ReadBytes, v.Mismatches, v.Unresolved)
				}
				if _, e := comparePreservation(ctx, x, native, ComparisonLimits{MaxReadBytes: v.ReadBytes - 1}); !errors.Is(e, ErrLimit) {
					t.Fatal("resolved CAB bytes bypassed lowered comparison read budget", e)
				}
			} else if v.Complete || len(v.Mismatches) == 0 {
				t.Fatal("independent CAB-backed difference accepted", kind, v)
			}
		})
	}
}

func TestSourceExpectationsResolveOnlyExactLiveOriginalReferenceGap(t *testing.T) {
	ctx := context.Background()
	p, closeSource := cabExpectationFixture(t)
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	g := x.gaps[1] // The first missing-stream-reference, after the callback ACE gap.
	if g.Kind != "missing-stream-reference" || g.Entry != 3 {
		t.Fatal("unexpected hand-built source gap", g)
	}
	if resolved, e := x.resolvesOriginalReferenceGap(g); !resolved || e != nil {
		t.Fatal("exact live CAB reference did not resolve consumer requirement", e)
	}
	for _, kind := range []string{"kind", "entry", "offset", "hash"} {
		v := g
		switch kind {
		case "kind":
			v.Kind = "conflicting-stream-size"
		case "entry":
			v.Entry++
		case "offset":
			v.Offset++
		case "hash":
			v.Detail = strings.Repeat("f", 40)
		}
		if resolved, e := x.resolvesOriginalReferenceGap(v); resolved || e != nil {
			t.Fatal("nonmatching original gap discharged", kind, e)
		}
	}
	for _, kind := range []string{"provenance", "sha256", "size", "reference", "missing-resource", "foreign-proof"} {
		t.Run(kind, func(t *testing.T) {
			old := x.entries[g.Entry].Content[0]
			ref := x.entries[g.Entry].Original.Streams[0].Reference
			proof := x.proof
			switch kind {
			case "provenance":
				x.entries[g.Entry].Content[0].ProvenanceDigest = strings.Repeat("f", 64)
			case "sha256":
				x.entries[g.Entry].Content[0].SHA256 = strings.Repeat("f", 64)
			case "size":
				x.entries[g.Entry].Content[0].Size++
			case "reference":
				x.entries[g.Entry].Original.Streams[0].Reference++
			case "missing-resource":
				x.entries[g.Entry].Original.Streams[0].Reference = len(p.state.Resources)
			case "foreign-proof":
				x.proof, _ = cabExpectationFixture(t)
			}
			resolved, e := x.resolvesOriginalReferenceGap(g)
			x.entries[g.Entry].Content[0] = old
			x.entries[g.Entry].Original.Streams[0].Reference = ref
			x.proof = proof
			if resolved || !(errors.Is(e, ErrInput) || errors.Is(e, source.ErrInput)) {
				t.Fatal("foreign sealed-reference identity discharged gap", kind, e)
			}
		})
	}
	closeSource()
	if resolved, e := x.resolvesOriginalReferenceGap(g); resolved || !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed source discharged original gap", e)
	}
}

func TestSourceExpectationsCABResolutionRetainsOtherUnknownRequirements(t *testing.T) {
	p, _ := cabExpectationFixture(t, false)
	x, e := BindSourceExpectations(context.Background(), p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	if x.state.ComparableComplete || len(x.requirements) != 1 || x.requirements[0].Field != "source.tag-semantics" || x.state.OriginalGaps != 5 || x.state.Oracle.MetadataComplete {
		t.Fatal("CAB resource resolution discharged unrelated source semantics", x.state, x.requirements)
	}
}
