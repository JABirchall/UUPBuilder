package wimcontent

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/cabindex"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

func referenceFixture(t *testing.T) (*Result, *wimindex.Index, []*wimindex.MetadataArtifact, *wimmeta.Oracle, *cabindex.Result) {
	t.Helper()
	_, fs, _, _ := fixture(t, nil)
	b, e := os.ReadFile(fs[0].Path)
	if e != nil {
		t.Fatal(e)
	}
	meta := make([]byte, 40)
	le.PutUint32(meta, 40)
	le.PutUint32(meta[4:], 1)
	le.PutUint64(meta[8:], 20)
	meta[16] = 1
	le.PutUint16(meta[18:], 0x8000)
	root := make([]byte, 104)
	le.PutUint64(root, 104)
	le.PutUint32(root[8:], 16)
	le.PutUint64(root[16:], 152)
	meta = append(meta, root...)
	meta = append(meta, make([]byte, 8)...)
	for n, d := range [][]byte{[]byte("AAtail!"), []byte("cabdata"), []byte("missing")} {
		en := make([]byte, 112)
		le.PutUint64(en, 112)
		le.PutUint32(en[8:], 32)
		le.PutUint16(en[100:], 2)
		le.PutUint16(en[102:], uint16('a'+n))
		h := sha1.Sum(d)
		copy(en[64:], h[:])
		meta = append(meta, en...)
	}
	meta = append(meta, make([]byte, 8)...)
	copy(b[256:], meta)
	le.PutUint32(b[44:], 1)
	desc(b[48:], 350, 4096, 350, 2)
	desc(b[4396:], uint64(len(meta)), 256, uint64(len(meta)), 2)
	le.PutUint16(b[4420:], 1)
	le.PutUint32(b[4422:], 1)
	h := sha1.Sum(meta)
	copy(b[4426:], h[:])
	u := utf16.Encode([]rune(`<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>0</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`))
	for n, v := range u {
		le.PutUint16(b[6000+n*2:], v)
	}
	desc(b[72:], uint64(len(u)*2), 6000, uint64(len(u)*2), 2)
	cab := make([]byte, 44+18+8+7)
	copy(cab, "MSCF")
	le.PutUint32(cab[8:], uint32(len(cab)))
	le.PutUint32(cab[16:], 44)
	cab[24] = 3
	cab[25] = 1
	le.PutUint16(cab[26:], 1)
	le.PutUint16(cab[28:], 1)
	le.PutUint32(cab[36:], 62)
	le.PutUint16(cab[40:], 1)
	le.PutUint32(cab[44:], 7)
	cab[60] = 'a'
	le.PutUint16(cab[66:], 7)
	le.PutUint16(cab[68:], 7)
	copy(cab[70:], "cabdata")
	var payloads []model.Payload
	var files []metadata.LocalResource
	for n, data := range [][]byte{b, cab} {
		name := []string{"fixture.esd", "fixture.cab"}[n]
		sum := sha256.Sum256(data)
		id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, Size: int64(len(data)), Provenance: model.PackageProvenance{Source: "uupdump:get.php:fixture", Name: name}}
		path := filepath.Join(t.TempDir(), name)
		if e = os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		payloads = append(payloads, model.Payload{Identity: id, Destination: name})
		files = append(files, metadata.LocalResource{Identity: id, Path: path})
	}
	m, e := model.NewPayloadManifest(model.SourceIdentity{UpdateID: "fixture", BuildLabel: "1", Architecture: "x86", Language: "en-us"}, payloads)
	if e != nil {
		t.Fatal(e)
	}
	idx, e := wimindex.Open(context.Background(), m, files[:1], wimindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	as, e := wimindex.DecodeMetadata(context.Background(), m, files[:1], idx, wimindex.DecodeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	o, e := wimmeta.Parse(context.Background(), as[0], idx, wimmeta.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	c, e := cabindex.Build(context.Background(), m, files[1:], o, cabindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	r, e := decode(context.Background(), m, files[:1], idx, Limits{}, func(context.Context, Limits) (codec, error) { return &syntheticCodec{}, nil })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		r.Close()
		c.Close()
		for _, a := range as {
			a.Close()
		}
	})
	return r, idx, as, o, c
}
func TestBoundUnionRetainsOriginalGapsAllProvenanceAndParentLifetime(t *testing.T) {
	r, _, _, o, c := referenceFixture(t)
	v, e := BindReferences(context.Background(), r, o, c, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	s := v.Snapshot()
	if len(s.References) != 3 || len(s.Unresolved) != 1 || s.ReferenceClosure || s.ConversionSupported || s.Oracle != o.Claim() {
		t.Fatal("original claims/gaps erased", s)
	}
	found := false
	for n, ref := range s.References {
		if len(ref.WIM) == 2 {
			found = true
			if !ref.Ambiguous {
				t.Fatal("duplicate provenance hidden")
			}
			a, e := v.Content(n, 0)
			if e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 7)
			if _, e = a.ReadAt(b, 0); e != nil || !bytes.Equal(b, []byte("AAtail!")) {
				t.Fatal(e)
			}
			c.Close()
			if _, e = a.ReadAt(b, 0); !errors.Is(e, os.ErrClosed) {
				t.Fatal("view survived bound parent closure", e)
			}
		}
	}
	if !found {
		t.Fatal("WIM witnesses lost")
	}
}
func TestUnionRefusesUnboundClosedAndLowerBudgets(t *testing.T) {
	r, _, _, o, c := referenceFixture(t)
	for _, l := range []Limits{{MaxReadBytes: 1}, {MaxResultBytes: 1}, {MaxEntries: 1}} {
		if v, e := BindReferences(context.Background(), r, o, c, l); e == nil || v != nil {
			t.Fatal("lower binding budget bypassed", l, e)
		}
	}
	if v, e := BindReferences(context.Background(), r, nil, c, Limits{}); v != nil || e == nil {
		t.Fatal("nil oracle")
	}
	if v, e := BindReferences(context.Background(), r, o, &cabindex.Result{}, Limits{}); v != nil || e == nil {
		t.Fatal("zero CAB authority")
	}
	r.Close()
	if v, e := BindReferences(context.Background(), r, o, c, Limits{}); v != nil || !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
}
func TestWholeIndexByteCompositionNeedsEveryLiveOriginalMetadataArtifact(t *testing.T) {
	r, idx, as, _, _ := referenceFixture(t)
	if v, e := ComposeMetadata(context.Background(), r, idx, nil, Limits{}); v != nil || e == nil {
		t.Fatal("metadata assumed from nonmetadata")
	}
	if v, e := ComposeMetadata(context.Background(), r, idx, []*wimindex.MetadataArtifact{as[0], as[0]}, Limits{}); v != nil || e == nil {
		t.Fatal("duplicate metadata")
	}
	v, e := ComposeMetadata(context.Background(), r, idx, as, Limits{})
	if e != nil || !v.Snapshot().ContentVerified || v.Snapshot().ConversionSupported {
		t.Fatal("whole-byte composition absent", e)
	}
	as[0].Close()
	if e = v.CheckLive(); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed metadata evidence stayed live", e)
	}
}
func TestUnionSnapshotBorrowerRevocationAndForeignParents(t *testing.T) {
	r, _, _, o, c := referenceFixture(t)
	v, e := BindReferences(context.Background(), r, o, c, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	s := v.Snapshot()
	var a *ReferenceArtifact
	for n, ref := range s.References {
		if len(ref.CAB) > 0 {
			a, e = v.Content(n, 0)
			if e != nil {
				t.Fatal(e)
			}
			s.References[n].CAB[0].SHA256 = "caller mutation"
			if v.Snapshot().References[n].CAB[0].SHA256 == "caller mutation" {
				t.Fatal("nested union alias")
			}
		}
	}
	if a == nil {
		t.Fatal("CAB borrower missing")
	}
	v.Close()
	if _, e = a.ReadAt(make([]byte, 1), 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	if e = r.live(); e != nil {
		t.Fatal("view Close closed parent", e)
	}
	other, _, _, foreignOracle, foreignCAB := referenceFixture(t)
	other.catalog.state.Index.IndexDigest = "different exact index"
	if v, e = BindReferences(context.Background(), other, foreignOracle, foreignCAB, Limits{}); v != nil || e == nil {
		t.Fatal("foreign exact-index binding accepted")
	}
}
func TestMetadataCompositionReadResultAndClosedLimits(t *testing.T) {
	r, idx, as, _, _ := referenceFixture(t)
	for _, l := range []Limits{{MaxReadBytes: 1}, {MaxResultBytes: 1}, {MaxEntries: 1}, {MaxBufferBytes: 1}} {
		if c, e := ComposeMetadata(context.Background(), r, idx, as, l); e == nil || c != nil {
			t.Fatal("composition lower bound bypassed", l, e)
		}
	}
	as[0].Close()
	if c, e := ComposeMetadata(context.Background(), r, idx, as, Limits{}); c != nil || e == nil {
		t.Fatal("closed metadata accepted")
	}
}
