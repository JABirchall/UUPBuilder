//go:build providerproof

package probes

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"
)

// This is actual-source parser replay with a synthetic decompression port.
// Researcher's independently decompressed retained reference bytes exercise
// parser framing/hash custody without calling a DLL or proving any provider.
func TestSourceObservedWIMReferenceReplay(t *testing.T) {
	rootPath := os.Getenv("P1_OBSERVATION_ROOT")
	if rootPath == "" {
		t.Fatal("explicit P1_OBSERVATION_ROOT required")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	read := func(name string) []byte {
		t.Helper()
		f, err := root.Open("p1-source-research/raw/" + name)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil || len(b) > 1<<20 {
			t.Fatalf("bounded reference %s: %v", name, err)
		}
		return b
	}
	body := read("microsoft-windows-foundation-package.esd")
	h := sha1.Sum(body)
	if len(body) != 21506 || hex.EncodeToString(h[:]) != "4004898a7fd7f2521fb2a8069a599ecf1fa6bbe3" {
		t.Fatal("actual-source reference identity changed")
	}
	metadata, solid := read("foundation-image-metadata.bin"), read("foundation-solid-resource.bin")
	port := func(ctx context.Context, input []byte, size int) ([]byte, error) {
		h := sha256.Sum256(input)
		var reference []byte
		switch hex.EncodeToString(h[:]) {
		case "03e63237a97d2f561895ffef6f030ca8ba460c53c523b02decad6722f8471c00":
			reference = metadata
		case "b56db3363ad64e765b5eac2023c5309e4cbd9aad8049f60e98c34f420068fde0":
			reference = solid
		default:
			return nil, errors.New("parser passed an unknown compressed source resource")
		}
		if len(reference) != size {
			return nil, errors.New("parser passed wrong reference output extent")
		}
		return reference, nil
	}
	got, err := extractObservedWIM(context.Background(), body, "update.mum", port)
	if err != nil || got.ExpectedSHA256 != "b7025d5086ea128d3af5fbe8148d3d0d5c6555cd4e0acd9c6db869be52d4b508" || got.MemberSHA1 != "01c1b33cc46f133a9427abc308bf7cf25e7b90e2" || len(got.Content) != 916 || got.ContentBlobs != 9 {
		t.Fatalf("actual-source reference replay failed: %+v %v", got, err)
	}
	t.Log("actual-source parser replay passed with synthetic decompression port; no native provider or Gate P/S proof")
}
