package engine

import (
	"context"
	"errors"
	"os"
	"testing"

	"uupbuilder/internal/engine/source"
)

func expectationFixture(t *testing.T, clean ...bool) (*PreservationProof, func()) {
	t.Helper()
	ctx := context.Background()
	in, _, close := preservationFixture(t, false, clean...)
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

func TestSourceExpectationsRequireLiveOriginalAndRetainEveryRecord(t *testing.T) {
	ctx := context.Background()
	if x, e := BindSourceExpectations(ctx, &PreservationProof{}, ComparisonLimits{}); x != nil || e == nil {
		t.Fatal("zero proof accepted", e)
	}
	p, close := expectationFixture(t)
	if x, e := BindSourceExpectations(ctx, p, ComparisonLimits{MaxEntries: 1}); x != nil || !errors.Is(e, ErrLimit) {
		t.Fatal("count bound", e)
	}
	if x, e := BindSourceExpectations(ctx, p, ComparisonLimits{MaxResultBytes: 1}); x != nil || !errors.Is(e, ErrLimit) {
		t.Fatal("result bound", e)
	}
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	d := x.Descriptor()
	if d.Entries != 11 || d.Security != 1 || d.Oracle.MetadataComplete || d.ComparableComplete || d.ProofDigest != p.state.Digest {
		t.Fatal(d)
	}
	entry, e := x.EntryAt(ctx, 3, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if entry.Original.Path != "/Windows/System32/ntoskrnl.exe" || entry.ExpectedLinks != 2 || entry.Original.CreationTime != 123 || entry.Original.AccessTime != 456 || entry.Original.WriteTime != 789 || entry.Content[0].Size != 15 {
		t.Fatal(entry)
	}
	entry.Original.Name[0] = 'X'
	entry.Content[0].SHA256 = "mutated"
	entry, e = x.EntryAt(ctx, 3, 1<<20)
	if e != nil || entry.Original.Name[0] != 'n' || entry.Content[0].SHA256 == "mutated" {
		t.Fatal("mutable expectations", e)
	}
	if _, e = x.EntryAt(ctx, 3, 0); !errors.Is(e, ErrLimit) {
		t.Fatal("exhausted accessor", e)
	}
	security, e := x.SecurityAt(ctx, 0, 1<<20)
	if e != nil || len(security.Raw) != 64 || string(security.Raw[60:64]) != string([]byte{0xde, 0xad, 0xca, 0xfe}) {
		t.Fatal("raw callback body missing", security, e)
	}
	security.Raw[60] = 0
	security, e = x.SecurityAt(ctx, 0, 1<<20)
	if e != nil || security.Raw[60] != 0xde {
		t.Fatal("security expectation mutation", e)
	}
	gap, e := x.OriginalGapAt(ctx, 0, 4096)
	if e != nil || gap.Kind != "ace-semantics" {
		t.Fatal("original gap changed", gap, e)
	}
	if _, e = x.SecurityAt(ctx, 0, 0); !errors.Is(e, ErrLimit) {
		t.Fatal("security residual", e)
	}
	var b [15]byte
	if n, e := x.ReadOriginalAt(ctx, 3, 0, b[:], 0); e != nil || n != 15 || string(b[:]) != "shared original" {
		t.Fatal(n, e, b)
	}
	close()
	if _, e = x.EntryAt(ctx, 3, 1<<20); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed source accessor", e)
	}
	if _, e = x.ReadOriginalAt(ctx, 3, 0, b[:], 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed source reader", e)
	}
	if x, e := BindSourceExpectations(ctx, p, ComparisonLimits{}); x != nil || !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed binding", e)
	}
}

func TestSourceExpectationsChargeBothOriginalMetadataRereads(t *testing.T) {
	p, _ := expectationFixture(t, true)
	if x, e := BindSourceExpectations(context.Background(), p, ComparisonLimits{MaxReadBytes: p.state.Source.Metadata.Size*2 - 1}); x != nil || !errors.Is(e, ErrLimit) {
		t.Fatal("original metadata rereads not precharged", e)
	}
}
