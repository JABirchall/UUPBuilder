package wimindex

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestContentClaimsBoundReparseAndKeepIndexImmutable(t *testing.T) {
	m, fs, idx, _ := metadataInputs(t, nil)
	c := idx.ContentClaim()
	if !c.Verified || c.Containers != 1 || c.Entries != 1 || c.Source != m.Source || c.ManifestDigest != m.Digest {
		t.Fatal("content claim absent", c)
	}
	h, ok := idx.ContentContainerAt(0)
	if !ok || h.Entries != 1 {
		t.Fatal(h)
	}
	e, ok := idx.ContentEntryAt(0, 0)
	if !ok || e.Kind != "metadata" {
		t.Fatal(e)
	}
	e.SHA1 = "changed"
	fresh, _ := idx.ContentEntryAt(0, 0)
	if fresh.SHA1 == e.SHA1 {
		t.Fatal("mutable entry")
	}
	f, er := os.Open(fs[0].Path)
	if er != nil {
		t.Fatal(er)
	}
	defer f.Close()
	if er = idx.CompareContentContainer(context.Background(), 0, f, 1); er != nil {
		t.Fatal(er)
	}
	if er = idx.CompareContentContainer(context.Background(), 0, f, 0); !errors.Is(er, ErrLimit) {
		t.Fatal("zero allowance became default", er)
	}
	b, er := os.ReadFile(fs[0].Path)
	if er != nil {
		t.Fatal(er)
	}
	b[24] ^= 1
	f.Close()
	os.WriteFile(fs[0].Path, b, 0600)
	f, er = os.Open(fs[0].Path)
	if er != nil {
		t.Fatal(er)
	}
	defer f.Close()
	if er = idx.CompareContentContainer(context.Background(), 0, f, 1); !errors.Is(er, ErrIntegrity) {
		t.Fatal("false live header accepted", er)
	}
	var zero Index
	if zero.ContentClaim().Verified {
		t.Fatal("zero index gave authority")
	}
}
