//go:build windows

package tools

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"uupbuilder/internal/download"
	"uupbuilder/internal/model"
)

type zipEntry struct {
	name, content string
	mode          os.FileMode
}

func syntheticArchive(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		w, err := z.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func goodEntries() []zipEntry {
	return []zipEntry{{name: "tool.exe", content: "tool"}, {name: "companion.dll", content: "dll"}, {name: "COPYING.txt", content: "notice\n"}}
}
func archiveFixture(t *testing.T, entries []zipEntry) (TrustedManifest, []byte) {
	t.Helper()
	raw := syntheticArchive(t, entries)
	doc := fixtureDocument()
	doc.Providers[0].Packages[0].SHA256 = testSHA(raw)
	doc.Providers[0].Packages[0].Size = int64(len(raw))
	return trustedFixture(t, doc), raw
}
func archiveFetcher(t *testing.T, manifest TrustedManifest, raw []byte) Fetcher {
	t.Helper()
	p := filepath.Join(t.TempDir(), "synthetic.zip")
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return fetchFunc(func(ctx context.Context, payload model.Payload, locator model.Locator, _ model.Emit) (download.CachedFile, error) {
		pin := manifest.providers[0].Packages[0]
		if payload.Identity.Digest.Value != pin.SHA256 || payload.Identity.Size != pin.Size || payload.Identity.Provenance.Source != pin.URL || locator.URL != pin.URL {
			t.Error("FetchOne lost frozen package identity/origin")
		}
		return download.CachedFile{Path: p, SHA256: pin.SHA256, Identity: payload.Identity}, ctx.Err()
	})
}

func TestZIPAcquisitionRejectsDigestMismatch(t *testing.T) {
	manifest, raw := archiveFixture(t, goodEntries())
	changed := bytes.Clone(raw)
	changed[len(changed)-1] ^= 1
	m := testManager(t, manifest, archiveFetcher(t, manifest, changed))
	if _, err := m.materializeZIP(context.Background(), manifest.providers[0], nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("changed archive accepted: %v", err)
	}
}

func TestZIPAcquisitionVerifiesCompanionDLLsAndNotices(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []zipEntry
	}{
		{"missing-dll", []zipEntry{{name: "tool.exe", content: "tool"}, {name: "COPYING.txt", content: "notice\n"}}},
		{"changed-dll", []zipEntry{{name: "tool.exe", content: "tool"}, {name: "companion.dll", content: "BAD"}, {name: "COPYING.txt", content: "notice\n"}}},
		{"missing-notice", goodEntries()[:2]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest, raw := archiveFixture(t, tc.entries)
			m := testManager(t, manifest, archiveFetcher(t, manifest, raw))
			if _, err := m.materializeZIP(context.Background(), manifest.providers[0], nil); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("incomplete provider published: %v", err)
			}
		})
	}
}

func TestZIPAcquisitionRejectsUnsafeEntries(t *testing.T) {
	for _, entry := range []zipEntry{
		{name: "../escape", content: "x"}, {name: "C:/escape", content: "x"}, {name: "tool.exe:evil", content: "x"},
		{name: "TOOL.EXE", content: "tool"}, {name: "tool.exe/nested", content: "x"}, {name: "link", content: "outside", mode: os.ModeSymlink | 0777},
		{name: "directory-link/", mode: os.ModeSymlink | 0777},
	} {
		t.Run(entry.name, func(t *testing.T) {
			manifest, raw := archiveFixture(t, append(goodEntries(), entry))
			m := testManager(t, manifest, archiveFetcher(t, manifest, raw))
			if _, err := m.materializeZIP(context.Background(), manifest.providers[0], nil); !errors.Is(err, ErrArchive) {
				t.Fatalf("unsafe archive accepted: %v", err)
			}
		})
	}
}

func TestProviderVersionsCoexist(t *testing.T) {
	manifest, raw := archiveFixture(t, goodEntries())
	m := testManager(t, manifest, archiveFetcher(t, manifest, raw))
	a, err := m.materializeZIP(context.Background(), manifest.providers[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	second := manifest.providers[0]
	second.Version = "2.0"
	b, err := m.materializeZIP(context.Background(), second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 3 || len(b) != 3 || a[0].Path == b[0].Path {
		t.Fatalf("versions overwrote provider directory: %+v %+v", a, b)
	}
	for _, files := range [][]VerifiedFile{a, b} {
		for _, f := range files {
			got, err := os.ReadFile(f.Path)
			if err != nil || testSHA(got) != f.SHA256 {
				t.Fatalf("bad published bytes: %s %v", f.Path, err)
			}
		}
	}
	if err := os.WriteFile(a[1].Path, []byte("BAD"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.materializeZIP(context.Background(), manifest.providers[0], nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("changed published DLL reused: %v", err)
	}
}

func TestZIPAcquisitionRequiresPinnedCompleteNoticeAndDependencySet(t *testing.T) {
	manifest, raw := archiveFixture(t, goodEntries())
	p := manifest.providers[0]
	p.Files = p.Files[:2]
	m := testManager(t, manifest, archiveFetcher(t, manifest, raw))
	if _, err := m.materializeZIP(context.Background(), p, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unpinned notice accepted: %v", err)
	}
	p = manifest.providers[0]
	p.Files[0].Dependencies = []string{"missing.dll"}
	if _, err := m.materializeZIP(context.Background(), p, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unknown companion accepted: %v", err)
	}
}

func TestZIPAcquisitionPublishesOnlyPinnedFilesAndRejectsAddedDLL(t *testing.T) {
	manifest, raw := archiveFixture(t, append(goodEntries(), zipEntry{name: "unused.cmd", content: "invented non-executable test data"}))
	m := testManager(t, manifest, archiveFetcher(t, manifest, raw))
	files, err := m.materializeZIP(context.Background(), manifest.providers[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("unrequested archive files published: %+v", files)
	}
	dir := filepath.Dir(files[0].Path)
	if _, err := os.Stat(filepath.Join(dir, "unused.cmd")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("archive script copied: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "added.dll"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.materializeZIP(context.Background(), manifest.providers[0], nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("side-loaded DLL accepted: %v", err)
	}
}

func TestZIPAcquisitionNestedFilesAndCancellation(t *testing.T) {
	entries := []zipEntry{{name: "bin/tool.exe", content: "tool"}, {name: "bin/companion.dll", content: "dll"}, {name: "legal/COPYING.txt", content: "notice\n"}}
	raw := syntheticArchive(t, entries)
	doc := fixtureDocument()
	p := &doc.Providers[0]
	p.Packages[0].Size = int64(len(raw))
	p.Packages[0].SHA256 = testSHA(raw)
	p.Files[0].Path = "bin/tool.exe"
	p.Files[0].Dependencies = []string{"bin/companion.dll"}
	p.Files[1].Path = "bin/companion.dll"
	p.Files[2].Path = "legal/COPYING.txt"
	p.Notices = []string{"legal/COPYING.txt"}
	manifest := trustedFixture(t, doc)
	m := testManager(t, manifest, archiveFetcher(t, manifest, raw))
	files, err := m.materializeZIP(context.Background(), manifest.providers[0], nil)
	if err != nil || len(files) != 3 {
		t.Fatalf("nested pinned files lost: %+v %v", files, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.materializeZIP(ctx, manifest.providers[0], nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cache verification ignored: %v", err)
	}
}

func TestManagerCloseCancelsAndQuiescesAcquisition(t *testing.T) {
	manifest, _ := archiveFixture(t, goodEntries())
	entered := make(chan struct{})
	m := testManager(t, manifest, fetchFunc(func(ctx context.Context, _ model.Payload, _ model.Locator, _ model.Emit) (download.CachedFile, error) {
		close(entered)
		<-ctx.Done()
		return download.CachedFile{}, ctx.Err()
	}))
	done := make(chan error, 1)
	go func() { _, err := m.materializeZIP(context.Background(), manifest.providers[0], nil); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("acquisition did not enter FetchOne")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Close did not cancel acquisition: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("acquisition did not return after Close")
	}
}

func TestStageCleanupReportsUnexpectedContentWithoutRecursiveDelete(t *testing.T) {
	manifest := trustedFixture(t, fixtureDocument())
	m := testManager(t, manifest, neverFetch(t))
	if err := m.workspace.MkdirAll("staging/synthetic"); err != nil {
		t.Fatal(err)
	}
	f, err := m.workspace.OpenFile("staging/synthetic/unknown.txt", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := m.removeStage("staging/synthetic", manifest.providers[0]); !errors.Is(err, ErrStorage) {
		t.Fatalf("incomplete cleanup was silently accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.workspace.Path(), "staging", "synthetic", "unknown.txt")); err != nil {
		t.Fatalf("unowned staging content removed: %v", err)
	}
}
