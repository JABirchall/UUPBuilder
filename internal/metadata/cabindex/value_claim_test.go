package cabindex

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestContentValueClaimsGateCopiesAndClosedParent(t *testing.T) {
	b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, fs, o := input(t, [][]byte{b}, [][]byte{[]byte("xx")})
	r, e := Build(context.Background(), m, fs, o, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	c, e := r.Binding()
	if e != nil || !c.Verified || c.Witnesses != 1 || c.Oracle != o.Claim() {
		t.Fatal(c, e)
	}
	w, ok := r.Catalog().WitnessAt(0)
	if !ok {
		t.Fatal("missing witness")
	}
	w.SHA1 = "changed"
	v, _ := r.Catalog().WitnessAt(0)
	if v.SHA1 == w.SHA1 {
		t.Fatal("mutable witness")
	}
	r.Close()
	if _, e = r.Binding(); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed parent binding", e)
	}
	var zero Result
	if _, e = zero.Binding(); e == nil {
		t.Fatal("zero parent granted binding")
	}
}
func TestClosedCABArtifactAlsoRevokesEmptyReads(t *testing.T) {
	b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, fs, o := input(t, [][]byte{b}, [][]byte{[]byte("xx")})
	r, e := Build(context.Background(), m, fs, o, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	a, e := r.Content(0)
	if e != nil {
		t.Fatal(e)
	}
	r.Close()
	if _, e = a.ReadAt(nil, 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed empty read remained usable", e)
	}
}
