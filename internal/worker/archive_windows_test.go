package worker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointArchiveChecksContentsAndPaths(t *testing.T) {
	sum := sha256.Sum256([]byte("abc"))
	entries := []ArchiveEntry{{Path: "sources/setup.exe", Size: 3, SHA256: hex.EncodeToString(sum[:])}}
	makeArchive := func(name, body string) []byte {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(body)), Mode: 0600, Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
		tw.Close()
		return b.Bytes()
	}
	root := filepath.Join(t.TempDir(), "good")
	if err := extractCheckpointArchive(context.Background(), bytes.NewReader(makeArchive(entries[0].Path, "abc")), root, entries); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "sources/setup.exe"))
	if err != nil || string(data) != "abc" {
		t.Fatal(err)
	}
	for _, bad := range []struct{ name, body string }{{"../escaped", "abc"}, {"sources/setup.exe", "abd"}, {"sources/SETUP.exe", "abc"}, {"sources/setup.exe", "ab"}} {
		if err := extractCheckpointArchive(context.Background(), bytes.NewReader(makeArchive(bad.name, bad.body)), filepath.Join(t.TempDir(), "bad"), entries); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}
