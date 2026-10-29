package wimcontent

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/cabindex"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

// Necessary live B1/B2/B3/B4 integration preparation. Historical JSON receipts
// cannot substitute for production authorities and retained readable artifacts.
func TestPreparedContentDecodingAndSelectedUnion(t *testing.T) {
	root := os.Getenv("UUP_WIM_CONTENT_PREPARED_ROOT")
	if root == "" {
		t.Skip("exact private prepared WIM content source not configured")
	}
	ctx := context.Background()
	var p struct {
		Manifest model.PayloadManifest
		Files    []struct {
			Path, SHA256 string
			Identity     model.PayloadIdentity
		}
	}
	b, e := os.ReadFile(filepath.Join(root, "actual-preparation", "prepared-source.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &p); e != nil {
		t.Fatal(e)
	}
	if p.Manifest.Validate() != nil || p.Manifest.Digest != "675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9" || p.Manifest.Source != (model.SourceIdentity{UpdateID: "3d12aa3e-806a-46c9-900e-bf7613959273", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}) {
		t.Fatal("frozen source identity changed")
	}
	var wims, cabs []metadata.LocalResource
	expected := map[model.PayloadIdentity]string{}
	for _, f := range p.Files {
		expected[f.Identity] = f.SHA256
		n := strings.ToLower(f.Identity.Provenance.Name)
		r := metadata.LocalResource{Identity: f.Identity, Path: f.Path}
		if strings.HasSuffix(n, ".esd") {
			wims = append(wims, r)
		} else if strings.HasSuffix(n, ".cab") && !strings.HasPrefix(n, "ssu-") && !strings.HasPrefix(n, "windows10.0-") {
			cabs = append(cabs, r)
		}
	}
	if len(wims) != 13 || len(cabs) != 22 {
		t.Fatal("membership changed")
	}
	idx, e := wimindex.Open(ctx, p.Manifest, wims, wimindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	if idx.Digest() != "ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a" {
		t.Fatal("original descriptor index changed")
	}
	before, _ := idx.MarshalJSON()
	t.Log("live original index prepared", idx.ContentClaim())
	r, e := Decode(ctx, p.Manifest, wims, idx, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	s := r.Catalog().Snapshot()
	t.Logf("decoded sources=%d backings=%d witnesses=%d active=%d inactive=%d output=%d reads=%d accounted=%d provider=%+v", len(s.Sources), len(s.Backings), len(s.Witnesses), s.ActiveNonMetadata, s.InactiveNonMetadata, s.DecodedBytes, s.ReadBytes, s.AccountedBytes, s.Provider)
	if len(s.Witnesses) != 54694 || !s.NonMetadataVerified || s.ContentVerified || s.ConversionSupported {
		t.Fatal("file-content proof incomplete")
	}
	solidCount, compressed, stored := 0, 0, 0
	var solidBytes uint64
	for _, back := range s.Backings {
		if back.Entry.Kind == "solid-resource" {
			solidCount++
			solidBytes += back.Size
			if back.Entry.Location.ChunkSize != 64<<20 || back.Entry.Location.Compression != 3 {
				t.Fatal("reviewed native block declaration changed")
			}
		}
		compressed += back.CompressedChunks
		stored += back.StoredChunks
		t.Logf("backing=%s entry=%d kind=%s chunks=%d compressed=%d stored=%d bytes=%d sha256=%s", back.Payload.Provenance.Name, back.Entry.Ordinal, back.Entry.Kind, back.Chunks, back.CompressedChunks, back.StoredChunks, back.Size, back.SHA256)
	}
	if solidCount != 15 || solidBytes != 6518144764 || compressed == 0 {
		t.Fatal("real larger-block proof absent", solidCount, solidBytes, compressed)
	}
	var independentlyRead uint64
	for n, w := range s.Witnesses {
		a, e := r.Content(n)
		if e != nil {
			t.Fatal(e)
		}
		h1, h256 := sha1.New(), sha256.New()
		size, e := io.CopyBuffer(io.MultiWriter(h1, h256), io.NewSectionReader(a, 0, int64(w.Size)), make([]byte, 64<<10))
		if e != nil || uint64(size) != w.Size || hex.EncodeToString(h1.Sum(nil)) != w.SHA1 || hex.EncodeToString(h256.Sum(nil)) != w.SHA256 || w.SourceSHA256 != expected[w.Payload] {
			t.Fatal("independent decoded witness mismatch", n, e)
		}
		independentlyRead += uint64(size)
	}
	t.Log("independent retained WIM witness bytes", independentlyRead)
	as, e := wimindex.DecodeMetadata(ctx, p.Manifest, wims, idx, wimindex.DecodeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		for _, a := range as {
			if e := a.Close(); e != nil {
				t.Error(e)
			}
		}
	}()
	if len(as) != 15 {
		t.Fatal("metadata membership changed")
	}
	composition, e := ComposeMetadata(ctx, r, idx, as, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	var o *wimmeta.Oracle
	for _, a := range as {
		w := a.Receipt()
		if w.Payload.Provenance.Name == "professional_en-us.esd" && w.Entry.ImageIndex == 3 {
			o, e = wimmeta.Parse(ctx, a, idx, wimmeta.Limits{})
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	if o == nil || o.Digest() != "55c616fbf48127e824365337ad8a509a92b43b1a79043378a20dfa417d46b019" {
		t.Fatal("original oracle changed")
	}
	cab, e := cabindex.Build(ctx, p.Manifest, cabs, o, cabindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := cab.Close(); e != nil {
			t.Error(e)
		}
	}()
	union, e := BindReferences(ctx, r, o, cab, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer union.Close()
	u := union.Snapshot()
	cs := cab.Catalog().Snapshot()
	if !u.ReferenceClosure || len(u.Unresolved) != 0 || len(cs.Witnesses) != 871 || len(u.References) != 39471 {
		t.Fatal("selected union incomplete", len(u.Unresolved), len(cs.Witnesses), len(u.References))
	}
	for _, f := range wims {
		file, e := os.Open(f.Path)
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.New()
		size, e := io.CopyBuffer(h, file, make([]byte, 64<<10))
		ce := file.Close()
		if e != nil || ce != nil || size != f.Identity.Size || hex.EncodeToString(h.Sum(nil)) != expected[f.Identity] {
			t.Fatal("independent final original source mismatch", f.Identity.Provenance.Name, e)
		}
	}
	after, _ := idx.MarshalJSON()
	if string(before) != string(after) {
		t.Fatal("original index mutated")
	}
	if e = composition.CheckLive(); e != nil {
		t.Fatal(e)
	}
	for _, out := range []struct {
		name string
		data any
	}{{"task-6b5-actual-content.json", r.Catalog()}, {"task-6b5-actual-union.json", union}, {"task-6b5-actual-metadata-composition.json", composition.Snapshot()}} {
		body, e := json.Marshal(out.data)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(root, out.name), body, 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Logf("source=%s manifest=%s index=%s content=%s oracle=%s cab=%s union=%s", p.Manifest.Source.UpdateID, p.Manifest.Digest, idx.Digest(), r.Catalog().Digest(), o.Digest(), cab.Catalog().Digest(), union.Digest())
	t.Logf("solid=%d solid-bytes=%d compressed-chunks=%d stored-chunks=%d selected-refs=%d cab-witnesses=%d unresolved=%d whole-index-bytes=%t conversion=%t original-metadata-complete=%t original-semantic-gaps=%d", solidCount, solidBytes, compressed, stored, len(u.References), len(cs.Witnesses), len(u.Unresolved), composition.Snapshot().ContentVerified, u.ConversionSupported, u.Oracle.MetadataComplete, u.Oracle.Summary.Gaps)
}
