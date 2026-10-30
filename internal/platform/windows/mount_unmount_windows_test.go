package windows

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnmountRejectsUnprovedDirectoryTransitions(t *testing.T) {
	for _, kind := range []string{"before-substitution", "provider-failure", "nonempty", "reparse", "stream", "missing"} {
		t.Run(kind, func(t *testing.T) {
			w, err := CreateWorkspace(t.TempDir(), "unmount-transition")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			mount, err := w.ClaimMount("mount", "service-image")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(w.Path(), "mount")
			replace := func() error {
				if err := os.Rename(path, path+"-old"); err != nil {
					return err
				}
				return os.Mkdir(path, 0700)
			}
			if kind == "before-substitution" {
				if err := replace(); err != nil {
					t.Fatal(err)
				}
			}
			outside := t.TempDir()
			sentinel := filepath.Join(outside, "keep")
			if err := os.WriteFile(sentinel, []byte("external"), 0600); err != nil {
				t.Fatal(err)
			}
			providerErr := errors.New("provider failed after replacing mount")
			called := false
			updated, err := w.Unmount(mount, func() error {
				called = true
				if err := replace(); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "provider-failure":
					return providerErr
				case "nonempty":
					if err := os.WriteFile(filepath.Join(path, "keep"), []byte("retained"), 0600); err != nil {
						t.Fatal(err)
					}
				case "reparse":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					createJunction(t, path, outside)
				case "stream":
					if err := os.WriteFile(path+":unexpected", []byte("retained"), 0600); err != nil {
						t.Fatal(err)
					}
				case "missing":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			})
			if err == nil || updated != (OwnedMount{}) {
				t.Fatalf("unsafe transition acquired ownership: %+v, %v", updated, err)
			}
			if kind == "before-substitution" && called {
				t.Fatal("provider called with a substituted mount")
			}
			if kind == "provider-failure" && !errors.Is(err, providerErr) {
				t.Fatalf("provider error lost: %v", err)
			}
			if body, err := os.ReadFile(sentinel); err != nil || string(body) != "external" {
				t.Fatalf("external data changed: %q, %v", body, err)
			}
			if kind == "nonempty" {
				if body, err := os.ReadFile(filepath.Join(path, "keep")); err != nil || string(body) != "retained" {
					t.Fatalf("unexpected mount contents removed: %q, %v", body, err)
				}
			}
		})
	}
}
