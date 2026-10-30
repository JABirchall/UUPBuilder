package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"uupbuilder/internal/download"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/tools"
)

type edgeToolInputs string

func (s edgeToolInputs) FetchOne(_ context.Context, p model.Payload, _ model.Locator, _ model.Emit) (download.CachedFile, error) {
	path := filepath.Join(string(s), "managed-tools", p.Identity.Provenance.Name)
	if p.Identity.Provenance.Name == "wimlib.zip" {
		path = filepath.Join(string(s), "managed-tools/wimlib/wimlib-1.14.5-windows-x86_64-bin.zip")
	}
	return download.CachedFile{Path: path, Identity: p.Identity, SHA256: p.Identity.Digest.Value}, nil
}
func TestActualSourceEdgeProviderAndReadbackSamples(t *testing.T) {
	root := os.Getenv("UUP_BUILDER_U09_PLAN_WORKSPACE")
	if root == "" {
		t.Skip("actual selected source inputs required")
	}
	ctx := context.Background()
	w, err := platform.CreateWorkspace(t.TempDir(), "edge-observation")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	runtime, err := tools.AcquireSelected(ctx, w, edgeToolInputs(root), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err = runtime.AcquireSourceEdge(ctx, observedSourceImage(t, filepath.Join(root, "native-images/install-base-with-cabs.wim"))); err != nil {
		t.Fatal(err)
	}
	d, err := NewManagedDISM(ctx, w, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	samples, err := d.sourceEdgeSamples(ctx, filepath.Join(root, "native-images/inputs/edge.wim"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 4 {
		t.Fatal("incomplete original Edge observations")
	}
	for name, digest := range samples {
		t.Logf("original EdgeContent member %s sha256=%s", name, digest)
	}
	t.Log("provider acquisition and original byte observations only; no Add-Edge or mount executed")
}

func TestSourceEdgeSamplesDiscoverObservedVersionDirectories(t *testing.T) {
	listing := "/Edge\n/Edge/Application\n/Edge/Application/msedge.exe\n/EdgeCore/155.0.1.9/msedge.exe\n/EdgeUpdate/MicrosoftEdgeUpdate.exe\n/EdgeWebView/Application/155.0.1.9/msedgewebview2.exe\n"
	names, err := edgeSamplePaths(listing)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 4 || names[1] != "EdgeCore/155.0.1.9/msedge.exe" || names[3] != "EdgeWebView/Application/155.0.1.9/msedgewebview2.exe" {
		t.Fatalf("source-observed directories not retained: %v", names)
	}
	// Edge-only sources must not acquire unrelated roots. Every offered root still
	// needs a representative browser/updater executable for readback.
	names, err = edgeSamplePaths("/Edge\n/Edge/Application/msedge.exe\n")
	if err != nil || len(names) != 1 {
		t.Fatalf("single offered root rejected: %v %v", names, err)
	}
	for _, listing := range []string{"/EdgeCore\n/EdgeCore/155.0.1.9/resources.pak\n", "/EdgeCore/../../msedge.exe\n", "/Unrelated/msedge.exe\n"} {
		if _, err := edgeSamplePaths(listing); err == nil {
			t.Fatalf("unverifiable content accepted: %q", listing)
		}
	}
}

func observedSourceImage(t *testing.T, path string) tools.SourceImage {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		t.Fatal(err)
	}
	return tools.SourceImage{Path: path, Size: size, SHA256: hex.EncodeToString(h.Sum(nil)), Architecture: model.ArchitectureAMD64}
}
