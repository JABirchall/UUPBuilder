package cabindex

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
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

// This configured test creates the necessary live B1/B2/B3 production input.
// It is integration preparation, not a re-run of earlier standalone proofs.
func TestPreparedCABReferenceClosure(t *testing.T) {
	root := os.Getenv("UUP_CAB_REFERENCE_PREPARED_ROOT")
	if root == "" {
		t.Skip("exact private frozen 40-payload source not configured")
	}
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
	if p.Manifest.Validate() != nil || p.Manifest.Digest != "675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9" {
		t.Fatal("frozen manifest changed")
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
		t.Fatal("frozen preparation membership changed", len(wims), len(cabs))
	}
	idx, e := wimindex.Open(context.Background(), p.Manifest, wims, wimindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	if idx.Digest() != "ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a" {
		t.Fatal("original index changed")
	}
	as, e := wimindex.DecodeMetadata(context.Background(), p.Manifest, wims, idx, wimindex.DecodeLimits{})
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
	var oracle *wimmeta.Oracle
	for _, a := range as {
		r := a.Receipt()
		if r.Payload.Provenance.Name == "professional_en-us.esd" && r.Entry.ImageIndex == 3 {
			oracle, e = wimmeta.Parse(context.Background(), a, idx, wimmeta.Limits{})
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	if oracle == nil || oracle.Digest() != "55c616fbf48127e824365337ad8a509a92b43b1a79043378a20dfa417d46b019" {
		t.Fatal("reviewed image-3 oracle changed")
	}
	r, e := Build(context.Background(), p.Manifest, cabs, oracle, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	s := r.Catalog().Snapshot()
	missing := 0
	for _, ref := range s.References {
		if ref.Original.Witnesses == 0 {
			missing++
		}
	}
	if missing != 774 {
		t.Fatal("reviewed missing-hash inventory changed", missing)
	}
	var retained uint64
	for n, w := range s.Witnesses {
		a, e := r.Content(n)
		if e != nil {
			t.Fatal(e)
		}
		h1, h256 := sha1.New(), sha256.New()
		size, e := io.CopyBuffer(io.MultiWriter(h1, h256), io.NewSectionReader(a, 0, int64(w.Size)), make([]byte, 64<<10))
		if e != nil || uint64(size) != w.Size || hex.EncodeToString(h1.Sum(nil)) != w.SHA1 || hex.EncodeToString(h256.Sum(nil)) != w.SHA256 || w.SourceSHA256 != expected[w.Payload] || w.Member.Size != w.Size || w.Ordinal < 1 {
			t.Fatal("independent retained member check failed", n, e)
		}
		retained += uint64(size)
	}
	for _, f := range cabs {
		file, e := os.Open(f.Path)
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.New()
		size, e := io.CopyBuffer(h, file, make([]byte, 64<<10))
		ce := file.Close()
		if e != nil || ce != nil || size != f.Identity.Size || hex.EncodeToString(h.Sum(nil)) != expected[f.Identity] {
			t.Fatal("independent final CAB source check failed", f.Identity.Provenance.Name, e)
		}
	}
	serialized, e := r.Catalog().MarshalJSON()
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(serialized)
	if hex.EncodeToString(h[:]) != r.Catalog().Digest() {
		t.Fatal("catalog digest mismatch")
	}
	if e = os.WriteFile(filepath.Join(root, "task-6b4-actual-cab-witnesses.json"), serialized, 0600); e != nil {
		t.Fatal(e)
	}
	t.Logf("source=%s manifest=%s index=%s oracle=%s", p.Manifest.Source.UpdateID, p.Manifest.Digest, idx.Digest(), oracle.Digest())
	t.Logf("provider=%+v", s.Provider)
	for _, row := range s.Sources {
		t.Logf("source=%s status=%s members=%d decoded=%d matches=%d bytes=%d sha256=%s", row.Payload.Provenance.Name, row.Status, row.Members, row.DecodedMembers, row.Matches, row.DecodedBytes, row.SourceSHA256)
	}
	t.Logf("required=%d original-missing=%d resolved=%d unresolved=%d witnesses=%d retained-bytes=%d catalog=%s", len(s.References), missing, missing-len(s.Unresolved), len(s.Unresolved), len(s.Witnesses), retained, r.Catalog().Digest())
	t.Logf("declared=%d observed=%d provider-read=%d native-peak=%d native-total=%d accounted=%d gaps=%d content-verified=%t conversion-supported=%t", s.DeclaredBytes, s.ObservedBytes, s.ProviderReadBytes, s.NativePeakBytes, s.NativeTotalBytes, s.AccountedBytes, len(s.Gaps), s.ContentVerified, s.ConversionSupported)
}
