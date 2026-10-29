package localsource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"uupbuilder/internal/model"
)

func TestRetainedSourceChecksOriginalHashAndPathIdentity(t *testing.T) {
	b := []byte("original")
	h := sha256.Sum256(b)
	id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(h[:])}, Size: 8, Provenance: model.PackageProvenance{Source: "test", Name: "a.cab"}}
	path := filepath.Join(t.TempDir(), "a.cab")
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	f, initial, e := Open(path, id)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	got, e := Verify(context.Background(), f, path, id, initial)
	if e != nil || got != id.Digest.Value {
		t.Fatalf("exact source not verified: %s %v", got, e)
	}
	wrong := id
	wrong.Digest.Value = string(make([]byte, 64))
	if _, e := Verify(context.Background(), f, path, wrong, initial); e == nil {
		t.Fatal("wrong original digest accepted")
	}
	other := filepath.Join(t.TempDir(), "same.cab")
	if e := os.WriteFile(other, b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Verify(context.Background(), f, other, id, initial); e == nil {
		t.Fatal("same bytes at another path substituted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Verify(ctx, nil, path, id, initial); e != context.Canceled {
		t.Fatal(e)
	}
}
