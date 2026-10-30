package service

import (
	"context"
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
	if err = runtime.AcquireSourceEdge(ctx, filepath.Join(root, "native-images/install-base-with-cabs.wim")); err != nil {
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
