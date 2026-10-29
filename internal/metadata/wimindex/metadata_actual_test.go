package wimindex

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

func TestPreparedStandardMetadataDecoding(t *testing.T) {
	root := os.Getenv("UUP_WIM_METADATA_PREPARED_ROOT")
	if root == "" {
		t.Skip("exact private prepared metadata descriptor not configured")
	}
	var prepared struct {
		Manifest model.PayloadManifest
		Files    []struct {
			Path, SHA256 string
			Identity     model.PayloadIdentity
		}
	}
	body, err := os.ReadFile(filepath.Join(root, "actual-preparation", "prepared-source.json"))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(body, &prepared) != nil {
		t.Fatal("invalid private prepared descriptor")
	}
	m := prepared.Manifest
	if m.Validate() != nil || m.Digest != "675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9" || m.Source != (model.SourceIdentity{UpdateID: "3d12aa3e-806a-46c9-900e-bf7613959273", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}) {
		t.Fatal("frozen prepared identity changed")
	}
	var original struct {
		ManifestDigest, IndexDigest string
		Containers                  []struct {
			Payload             model.PayloadIdentity
			SHA256              string
			ResourceDescriptors []Entry
		}
	}
	body, err = os.ReadFile(filepath.Join(root, "task-6b1-actual-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(body, &original) != nil || original.ManifestDigest != m.Digest || original.IndexDigest != "ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a" || len(original.Containers) != 13 {
		t.Fatal("original descriptor index changed")
	}
	var files []metadata.LocalResource
	type key struct {
		Payload model.PayloadIdentity
		Ordinal uint32
	}
	expected := map[key]Entry{}
	for _, c := range original.Containers {
		found := false
		for _, f := range prepared.Files {
			if f.Identity == c.Payload {
				if found || f.SHA256 != c.SHA256 {
					t.Fatal("prepared witness changed")
				}
				found = true
				files = append(files, metadata.LocalResource{Identity: f.Identity, Path: f.Path})
			}
		}
		if !found {
			t.Fatal("missing original source reference")
		}
		for _, e := range c.ResourceDescriptors {
			if e.Kind == "metadata" {
				expected[key{c.Payload, e.Ordinal}] = e
			}
		}
	}
	if len(expected) != 15 {
		t.Fatalf("original metadata count=%d", len(expected))
	}
	idx, err := Open(context.Background(), m, files, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if idx.Digest() != original.IndexDigest {
		t.Fatalf("reproduced index digest changed: %s", idx.Digest())
	}
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	artifacts, err := DecodeMetadata(context.Background(), m, files, idx, DecodeLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, a := range artifacts {
			if err := a.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	if len(artifacts) != 15 {
		t.Fatalf("decoded=%d want=15", len(artifacts))
	}
	var receipts []MetadataReceipt
	type retained struct {
		RelativePath string
		Receipt      MetadataReceipt
	}
	var retainedEvidence []retained
	if err := os.MkdirAll(filepath.Join(root, "task-6b2-decoded"), 0700); err != nil {
		t.Fatal(err)
	}
	selected := false
	var total uint64
	for _, a := range artifacts {
		r := a.Receipt()
		e, ok := expected[key{r.Payload, r.Entry.Ordinal}]
		if !ok || r.Entry != e || r.SHA1 != e.SHA1 || r.Size != e.LogicalSize || !r.SourceRehashed || r.IndexDigest != original.IndexDigest || r.ManifestDigest != m.Digest || r.Source != m.Source {
			t.Fatal("receipt lost original frozen binding")
		}
		delete(expected, key{r.Payload, r.Entry.Ordinal})
		// Independent complete reader pass compares every artifact to B1's
		// original records, rather than trusting codec returns or receipts.
		h1, h256 := sha1.New(), sha256.New()
		n, err := io.CopyBuffer(io.MultiWriter(h1, h256), io.NewSectionReader(a, 0, int64(r.Size)), make([]byte, 64<<10))
		if err != nil || uint64(n) != e.LogicalSize || hex.EncodeToString(h1.Sum(nil)) != e.SHA1 || hex.EncodeToString(h256.Sum(nil)) != r.SHA256 {
			t.Fatal("independent decoded hash/size comparison failed", err)
		}
		relative := filepath.Join("task-6b2-decoded", r.SHA256+".metadata")
		retainDecodedEvidence(t, filepath.Join(root, relative), a, r)
		retainedEvidence = append(retainedEvidence, retained{relative, r})
		if r.Codec.Name != "cabinet.dll" || len(r.Codec.SHA256) != 64 || r.Codec.Size <= 0 {
			t.Fatal("unmeasured native codec")
		}
		if r.Payload.Provenance.Name == "professional_en-us.esd" && r.Entry.ImageIndex == 3 {
			if r.SHA1 != "29256693076c5877942412848136d702889e3141" || r.Entry.Descriptor != (Descriptor{Offset: 334736484, Size: 3228184, Original: 18731096, Flags: 6}) || r.Size != 18731096 {
				t.Fatal("selected original metadata identity changed")
			}
			var prefix [32]byte
			if _, err := a.ReadAt(prefix[:], 0); err != nil {
				t.Fatal(err)
			}
			t.Logf("selected-raw-prefix=%x (format sanity only; no semantic interpretation)", prefix)
			selected = true
		}
		total += r.Size
		receipts = append(receipts, r)
		t.Logf("metadata=%s image=%d entry=%d original-sha1=%s size=%d decoded-sha256=%s source-rehashed=%v", r.Payload.Provenance.Name, r.Entry.ImageIndex, r.Entry.Ordinal, r.SHA1, r.Size, r.SHA256, r.SourceRehashed)
	}
	if len(expected) != 0 || !selected {
		t.Fatal("missing original metadata proof")
	}
	s := idx.Snapshot()
	if s.ContentVerified || s.ConversionSupported {
		t.Fatal("metadata decoding changed whole-index capability")
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	report := struct {
		ManifestDigest, IndexDigest                   string
		Receipts                                      []MetadataReceipt
		Resources                                     int
		DecodedBytes                                  uint64
		ProcessArchitecture                           string
		GoHeapAlloc, GoHeapSys, GoTotalAllocatedDelta uint64
		ContentVerified, ConversionSupported          bool
	}{m.Digest, idx.Digest(), receipts, len(receipts), total, runtime.GOARCH, after.HeapAlloc, after.HeapSys, after.TotalAlloc - before.TotalAlloc, false, false}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "task-6b2-actual-metadata.json"), append(out, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	privateLocations, err := json.MarshalIndent(retainedEvidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "task-6b2-private-decoded.json"), append(privateLocations, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("verified=%d bytes=%d index=%s provider=%+v Go-heap-alloc=%d Go-heap-sys=%d Go-total-allocated-delta=%d content-verified=false conversion-supported=false", len(receipts), total, idx.Digest(), receipts[0].Codec, after.HeapAlloc, after.HeapSys, after.TotalAlloc-before.TotalAlloc)
}

// Private evidence only. The production API exposes no runtime location. An
// existing content-addressed output is checked, never silently overwritten.
func retainDecodedEvidence(t *testing.T, path string, a *MetadataArtifact, r MetadataReceipt) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		n, copyErr := io.CopyBuffer(f, io.NewSectionReader(a, 0, int64(r.Size)), make([]byte, 64<<10))
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil || uint64(n) != r.Size {
			os.Remove(path)
			t.Fatal("private evidence retention failed", copyErr, closeErr)
		}
	} else if !os.IsExist(err) {
		t.Fatal(err)
	}
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h1, h256 := sha1.New(), sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(h1, h256), f, make([]byte, 64<<10))
	if err != nil || uint64(n) != r.Size || hex.EncodeToString(h1.Sum(nil)) != r.SHA1 || hex.EncodeToString(h256.Sum(nil)) != r.SHA256 {
		t.Fatal("retained private evidence differs from verified artifact", err)
	}
}
