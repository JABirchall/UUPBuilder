package cabindex

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRetainedCandidateCannotBeReplacedByEqualBytes(t *testing.T) {
	s, e := newPrivateStore()
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	f, name, e := s.create(2)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write([]byte("xx")); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(s.store.Path(), name)); e != nil {
		t.Fatal(e)
	}
	replacement, e := os.OpenFile(filepath.Join(s.store.Path(), name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	replacement.Write([]byte("xx"))
	replacement.Close()
	a, e := s.retain(name, Witness{Size: 2})
	if e == nil {
		a.close()
		t.Fatal("equal replacement bypassed output file identity")
	}
	// This replacement was created by this test; the production store refuses
	// to adopt or delete its changed identity.
	if e := os.Remove(filepath.Join(s.store.Path(), name)); e != nil {
		t.Fatal(e)
	}
	s.remove(name)
}
func TestNativeAndAggregateLimitsDiscardWholeBatch(t *testing.T) {
	b := cabinet([]string{"a", "b"}, [][]byte{[]byte("xx"), []byte("xx")})
	m, fs, o := input(t, [][]byte{b}, [][]byte{[]byte("xx"), []byte("missing")})
	for _, l := range []Limits{{MaxReferences: 1}, {MaxMembers: 1}, {MaxWitnesses: 1}, {MaxDiskBytes: 2}, {MaxNativeAllocations: 1}, {MaxManifestBytes: 1}} {
		r, e := Build(context.Background(), m, fs, o, l)
		if e == nil || r != nil {
			if r != nil {
				r.Close()
			}
			t.Fatalf("lower aggregate count/budget bypassed: %+v", l)
		}
	}
	nested := cabinet([]string{"inner.cab"}, [][]byte{[]byte("MSCFnested")})
	m, fs, o = input(t, [][]byte{nested}, [][]byte{[]byte("MSCFnested")})
	r, e := Build(context.Background(), m, fs, o, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	v := r.Catalog().Snapshot()
	if len(v.Gaps) != 1 || len(v.Unresolved) != 1 || len(v.Witnesses) != 0 || v.Gaps[0].Kind != "nested-cabinet-not-decoded" {
		t.Fatal("nested material erased unresolved gap")
	}
}
func TestUnexpectedPrivateEntryPreventsPublicationAndCleanupIsReported(t *testing.T) {
	b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, fs, o := input(t, [][]byte{b}, [][]byte{[]byte("xx")})
	var p *faultyProvider
	factory := func(ctx context.Context) (dataProvider, error) {
		base, e := openFDI(ctx)
		p = &faultyProvider{dataProvider: base, mode: "extra-output"}
		return p, e
	}
	r, e := build(context.Background(), m, fs, o, Limits{}, factory)
	if r != nil {
		r.Close()
	}
	defer func() {
		if p != nil && p.scope != "" {
			cleanTestRetainedScope(t, p.scope)
		}
	}()
	if e == nil || r != nil || !errors.Is(e, ErrIntegrity) {
		t.Fatal("unexpected owned data did not gate verified publication", e)
	}
}

func TestClosePreservesCleanupFailureAfterRevokingReaders(t *testing.T) {
	b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, fs, o := input(t, [][]byte{b}, [][]byte{[]byte("xx")})
	r, e := Build(context.Background(), m, fs, o, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	scope := r.store.store.Path()
	defer cleanTestRetainedScope(t, scope)
	f, e := os.OpenFile(filepath.Join(r.store.store.Path(), "unexpected"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	first := r.Close()
	if !errors.Is(first, ErrIntegrity) {
		t.Fatal("cleanup error lost", first)
	}
	if !errors.Is(r.Close(), ErrIntegrity) {
		t.Fatal("repeated Close hid retained cleanup failure")
	}
	if _, e := r.Content(0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("cleanup failure left borrowed contents live", e)
	}
}
