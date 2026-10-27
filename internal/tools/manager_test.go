//go:build windows

package tools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uupbuilder/internal/download"
	"uupbuilder/internal/model"
	windows "uupbuilder/internal/platform/windows"
)

type fetchFunc func(context.Context, model.Payload, model.Locator, model.Emit) (download.CachedFile, error)

func (f fetchFunc) FetchOne(c context.Context, p model.Payload, l model.Locator, e model.Emit) (download.CachedFile, error) {
	return f(c, p, l, e)
}

func testManager(t *testing.T, manifest TrustedManifest, fetch Fetcher) *Manager {
	t.Helper()
	w, err := windows.CreateWorkspace(t.TempDir(), "synthetic-tool-acquisition")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	})
	m, err := NewManager(Options{Manifest: manifest, Workspace: w, Fetcher: fetch})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	return m
}

func neverFetch(t *testing.T) Fetcher {
	return fetchFunc(func(context.Context, model.Payload, model.Locator, model.Emit) (download.CachedFile, error) {
		t.Error("unverified candidate reached network acquisition")
		return download.CachedFile{}, errors.New("forbidden fixture fetch")
	})
}

func TestEnsureRejectsManifestDigestMismatch(t *testing.T) {
	manifest := trustedFixture(t, fixtureDocument())
	m := testManager(t, manifest, neverFetch(t))
	req := testRequirement(strings.Repeat("0", 64))
	chain, err := m.Ensure(context.Background(), req, nil)
	if !errors.Is(err, ErrManifestDigest) || len(chain.Files()) != 0 {
		t.Fatalf("mismatched frozen manifest was used: %+v %v", chain, err)
	}
}

func TestEnsureRefusesUnprovenCandidatesBeforeAcquisition(t *testing.T) {
	manifest := trustedFixture(t, fixtureDocument())
	m := testManager(t, manifest, neverFetch(t))
	chain, err := m.Ensure(context.Background(), testRequirement(manifest.Digest()), nil)
	var blocked *BlockedError
	if !errors.As(err, &blocked) || !errors.Is(err, ErrUnverified) || len(chain.Files()) != 0 || len(chain.Operations()) != 0 {
		t.Fatalf("candidate exposed operational readiness: %+v %v", chain, err)
	}
	if blocked.Selection.Requirement.Target != "x86" || !hasBlocker(blocked.Selection.Candidates[0].Blockers, "runtime-unverified") {
		t.Fatalf("lost exact blocker: %+v", blocked)
	}
}

func TestAcquisitionNeverRequiresManualADK(t *testing.T) {
	manifest, err := DefaultManifest()
	if err != nil {
		t.Fatal(err)
	}
	m := testManager(t, manifest, neverFetch(t))
	for _, native := range []model.Architecture{"x86", "amd64", "arm64"} {
		for _, target := range []model.Architecture{"x86", "amd64", "arm64", "future-cpu"} {
			req := testRequirement(manifest.Digest())
			req.Host.NativeArchitecture = native
			req.Host.ProcessArchitecture = native
			req.Target = target
			req.Operations = []Operation{Service, MasterISO}
			chain, err := m.Ensure(context.Background(), req, nil)
			var blocked *BlockedError
			if !errors.As(err, &blocked) || len(chain.Files()) != 0 || blocked.Selection.Requirement.Target != target {
				t.Fatalf("%s/%s: missing visible blocked result: %v", native, target, err)
			}
			found := false
			for _, c := range blocked.Selection.Candidates {
				found = found || hasBlocker(c.Blockers, "managed-acquisition-unverified")
			}
			if !found {
				t.Fatalf("%s/%s: no concrete application-managed prerequisite blocker: %+v", native, target, blocked)
			}
		}
	}
}

func TestManagerLeasesWorkspaceAndCloseDoesNotDeleteIt(t *testing.T) {
	manifest := trustedFixture(t, fixtureDocument())
	m := testManager(t, manifest, neverFetch(t))
	if _, err := NewManager(Options{Manifest: manifest, Workspace: m.workspace, Fetcher: neverFetch(t)}); !errors.Is(err, ErrInUse) {
		t.Fatalf("second manager shared publication root: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(context.Background(), testRequirement(manifest.Digest()), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed manager accepted work: %v", err)
	}
	f, err := m.workspace.OpenFile("caller-still-owns.txt", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if !filepath.IsAbs(m.workspace.Path()) {
		t.Fatal("lost caller workspace")
	}
	next, err := NewManager(Options{Manifest: manifest, Workspace: m.workspace, Fetcher: neverFetch(t)})
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}
