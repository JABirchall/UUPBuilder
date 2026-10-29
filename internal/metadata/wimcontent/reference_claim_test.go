package wimcontent

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestReferenceValueClaimsDoNotCloneOrGrantLifetime(t *testing.T) {
	var zero *ReferenceView
	if zero.Claim().Verified {
		t.Fatal("nil verified")
	}
	if _, ok := zero.ReferenceAt(0); ok {
		t.Fatal("nil reference")
	}
	r, _, _, o, c := referenceFixture(t)
	v, e := BindReferences(context.Background(), r, o, c, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	q := v.Claim()
	if !q.Verified || q.References != 3 || q.Digest != v.Digest() {
		t.Fatal(q)
	}
	for n := 0; n < q.References; n++ {
		ref, ok := v.ReferenceAt(n)
		if !ok {
			t.Fatal(n)
		}
		for j := 0; j < ref.WIMWitnesses; j++ {
			w, ok := v.WIMWitnessAt(n, j)
			if !ok || w.SHA1 != ref.Original.SHA1 {
				t.Fatal(n, j)
			}
			w.SHA1 = "changed"
			again, _ := v.WIMWitnessAt(n, j)
			if again.SHA1 == w.SHA1 {
				t.Fatal("mutable witness")
			}
		}
	}
	if _, ok := v.ReferenceAt(-1); ok {
		t.Fatal("negative")
	}
	if _, ok := v.CABWitnessAt(0, 999); ok {
		t.Fatal("range")
	}
	c.Close()
	if e = v.CheckLive(); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed parent", e)
	}
	if !v.Claim().Verified {
		t.Fatal("historical receipt erased")
	}
}
