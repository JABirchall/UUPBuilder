package probes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"uupbuilder/internal/model"
)

// Custody tests exercise real files. Their abc bytes are synthetic and never
// establish a provider/source gate.
func TestArtifactCustodyVerifiesAndRetainsExactBytes(t *testing.T) {
	source, target := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "fixture"), []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(source)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w, err := os.OpenRoot(target)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	a := Artifact{"input", "payload", model.Digest{Algorithm: model.DigestSHA256, Value: unitHash}, 3, "synthetic abc fixture"}
	got, err := retainFixture(context.Background(), r, w, "fixture", "retained.bin", a)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(target, "retained.bin"))
	if err != nil || string(b) != "abc" || got.SHA256 != unitHash || got.Path != "retained.bin" || got.Artifact != a {
		t.Fatalf("retained custody=%+v bytes=%q err=%v", got, b, err)
	}
	// Reopening an existing destination must not overwrite prior evidence.
	if _, err := retainFixture(context.Background(), r, w, "fixture", "retained.bin", a); err == nil {
		t.Fatal("existing evidence overwritten")
	}
}

func TestArtifactCustodyRejectsWrongBytesSizeEscapeAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name, path, digest string
		size               int64
		cancelled          bool
	}{
		{"wrong digest", "fixture", unitBeforeHash, 3, false},
		{"truncated", "fixture", unitHash, 4, false},
		{"oversize", "fixture", unitHash, 2, false},
		{"escape", "../fixture", unitHash, 3, false},
		{"cancelled", "fixture", unitHash, 3, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, target := t.TempDir(), t.TempDir()
			if err := os.WriteFile(filepath.Join(source, "fixture"), []byte("abc"), 0600); err != nil {
				t.Fatal(err)
			}
			r, err := os.OpenRoot(source)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			w, err := os.OpenRoot(target)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancelled {
				cancel()
			}
			a := Artifact{"input", "payload", model.Digest{Algorithm: model.DigestSHA256, Value: test.digest}, test.size, "synthetic custody negative"}
			if _, err := retainFixture(ctx, r, w, test.path, "retained.bin", a); err == nil {
				t.Fatal("unverified bytes accepted")
			} else if test.cancelled && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation identity lost: %v", err)
			}
			if _, err := os.Stat(filepath.Join(target, "retained.bin")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unverified output retained as verified: %v", err)
			}
		})
	}
}
