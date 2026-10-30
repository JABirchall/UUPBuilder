package output

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This fixture exercises publication after verification, not ISO parsing.
func publicationFixture(t *testing.T) VerifiedArtifact {
	t.Helper()
	p := filepath.Join(t.TempDir(), "verified.iso")
	b := []byte("independently verified ISO fixture bytes")
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return VerifiedArtifact{&verifiedState{path: p, size: int64(len(b)), sha256: hex.EncodeToString(h[:]), planDigest: strings.Repeat("a", 64)}}
}

func TestPublishCopiesAndDigestsDestinationWithoutOverwrite(t *testing.T) {
	v := publicationFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Windows.iso"), []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := Publish(context.Background(), v, dir, "Windows.iso")
	if err != nil {
		t.Fatal(err)
	}
	if a.Path == filepath.Join(dir, "Windows.iso") || a.SHA256 != v.state.sha256 || a.Size != v.state.size || a.PlanDigest != v.state.planDigest {
		t.Fatalf("wrong artifact: %+v", a)
	}
	for _, p := range []string{a.Path, a.VerificationPath, a.ReportPath, v.state.path} {
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "Windows.iso"))
	if string(b) != "unrelated" {
		t.Fatal("overwrote collision")
	}
	b, _ = os.ReadFile(a.VerificationPath)
	if !strings.Contains(string(b), a.SHA256) {
		t.Fatal("checksum missing")
	}
	b, _ = os.ReadFile(a.ReportPath)
	if !strings.Contains(string(b), "excluded") {
		t.Fatal("excluded checks missing")
	}
}

func TestPublishRejectsChangedBytesAndRetainsLocalISO(t *testing.T) {
	v := publicationFixture(t)
	if err := os.WriteFile(v.state.path, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := Publish(context.Background(), v, dir, "Windows.iso"); err == nil {
		t.Fatal("changed verified file published")
	}
	if _, err := os.Stat(v.state.path); err != nil {
		t.Fatal("local ISO removed")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 {
		t.Fatal("failed publication left output")
	}
}

func TestPublishRejectsZeroTokenAndUnsafeFilename(t *testing.T) {
	for _, name := range []string{"../escape.iso", "C:\\escape.iso", "Windows.iso:other", "", "Windows.wim"} {
		if _, err := Publish(context.Background(), publicationFixture(t), t.TempDir(), name); err == nil {
			t.Fatalf("unsafe name accepted: %s", name)
		}
	}
	if _, err := Publish(context.Background(), VerifiedArtifact{}, t.TempDir(), "Windows.iso"); err == nil {
		t.Fatal("zero verification token accepted")
	}
}

func TestPublishSidecarCollisionAndWriteFailureRetainSource(t *testing.T) {
	v := publicationFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Windows.iso.report.json"), []byte("unrelated report"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := Publish(context.Background(), v, dir, "Windows.iso")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(a.Path) != "Windows (1).iso" {
		t.Fatalf("sidecar collision ignored: %s", a.Path)
	}
	if _, err = Publish(context.Background(), v, filepath.Join(dir, "missing-directory"), "Windows.iso"); err == nil {
		t.Fatal("destination write failure ignored")
	}
	if _, err = os.Stat(v.state.path); err != nil {
		t.Fatal("verified source removed after destination failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Publish(ctx, v, dir, "cancelled.iso"); err == nil {
		t.Fatal("cancelled copy accepted")
	}
}
