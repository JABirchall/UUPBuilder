package cabindex

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestBorrowedContentCarriesImmutableOriginalBindingAndRevokesReads(t *testing.T) {
	for _, a := range []*ContentArtifact{nil, {}} {
		if c := a.Binding(); c.Verified || c.Digest != "" {
			t.Fatal("unpublished artifact granted original binding")
		}
	}
	b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, fs, o := input(t, [][]byte{b}, [][]byte{[]byte("xx")})
	r, e := Build(context.Background(), m, fs, o, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	a, e := r.Content(0)
	if e != nil {
		t.Fatal(e)
	}
	want := o.Claim()
	got := a.Binding()
	if got != want || got.Receipt.ManifestDigest != m.Digest || got.Receipt.IndexDigest == "" || got.Receipt.SHA1 == "" || got.Receipt.SHA256 == "" {
		t.Fatal("borrowed artifact lost original source/manifest/index/metadata/oracle binding")
	}
	got.Receipt.Source.BuildLabel = "caller mutation"
	got.Receipt.Payload.Provenance.Name = "caller mutation"
	if a.Binding() != want {
		t.Fatal("binding accessor aliases authority")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if a.Binding() != want {
		t.Fatal("Close erased historical binding")
	}
	if _, e := a.ReadAt(make([]byte, 1), 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("historical binding retained readable content", e)
	}
}
