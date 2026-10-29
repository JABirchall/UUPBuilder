package cabindex

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

var le = binary.LittleEndian

func cabinet(names []string, data [][]byte) []byte {
	table := 44
	for _, n := range names {
		table += 17 + len(n)
	}
	total := 0
	for _, b := range data {
		total += len(b)
	}
	b := make([]byte, table+8+total)
	copy(b, "MSCF")
	le.PutUint32(b[8:], uint32(len(b)))
	le.PutUint32(b[16:], 44)
	b[24] = 3
	b[25] = 1
	le.PutUint16(b[26:], 1)
	le.PutUint16(b[28:], uint16(len(names)))
	le.PutUint32(b[36:], uint32(table))
	le.PutUint16(b[40:], 1)
	p, off := 44, 0
	for i, n := range names {
		le.PutUint32(b[p:], uint32(len(data[i])))
		le.PutUint32(b[p+4:], uint32(off))
		copy(b[p+16:], n)
		copy(b[table+8+off:], data[i])
		p += 17 + len(n)
		off += len(data[i])
	}
	le.PutUint16(b[table+4:], uint16(total))
	le.PutUint16(b[table+6:], uint16(total))
	return b
}
func identity(name string, b []byte) model.PayloadIdentity {
	h := sha256.Sum256(b)
	return model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(h[:])}, Size: int64(len(b)), Provenance: model.PackageProvenance{Source: "uupdump:get.php:fixture", Name: name}}
}

// The hand-built original WIM goes through public B1/B2/B3 producers. No test
// accessor, asserted receipt, serialized oracle or path can construct authority.
func input(t *testing.T, contents [][]byte, required [][]byte) (model.PayloadManifest, []metadata.LocalResource, *wimmeta.Oracle) {
	t.Helper()
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
	for i, d := range required {
		e := make([]byte, 112)
		le.PutUint64(e, 112)
		le.PutUint32(e[8:], 32)
		le.PutUint16(e[100:], 2)
		le.PutUint16(e[102:], uint16('a'+i))
		h := sha1.Sum(d)
		copy(e[64:], h[:])
		meta = append(meta, e...)
	}
	meta = append(meta, make([]byte, 8)...)
	w := make([]byte, 8192)
	copy(w, "MSWIM\x00\x00\x00")
	le.PutUint32(w[8:], 208)
	le.PutUint32(w[12:], 0xe00)
	le.PutUint16(w[40:], 1)
	le.PutUint16(w[42:], 1)
	le.PutUint32(w[44:], 1)
	desc := func(p int, n, off uint64, flags byte) {
		le.PutUint64(w[p:], n)
		w[p+7] = flags
		le.PutUint64(w[p+8:], off)
		le.PutUint64(w[p+16:], n)
	}
	desc(48, 50, 4096, 2)
	desc(4096, uint64(len(meta)), 256, 2)
	le.PutUint16(w[4120:], 1)
	le.PutUint32(w[4122:], 1)
	h := sha1.Sum(meta)
	copy(w[4126:], h[:])
	copy(w[256:], meta)
	u := utf16.Encode([]rune(`<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>0</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`))
	x := make([]byte, len(u)*2)
	for i, v := range u {
		le.PutUint16(x[i*2:], v)
	}
	desc(72, uint64(len(x)), 6000, 2)
	copy(w[6000:], x)
	var ps []model.Payload
	var fs []metadata.LocalResource
	all := append([][]byte{w}, contents...)
	for i, b := range all {
		name := "a.esd"
		if i > 0 {
			name = string(rune('a'+i)) + ".cab"
		}
		id := identity(name, b)
		ps = append(ps, model.Payload{Identity: id, Destination: name})
		path := filepath.Join(t.TempDir(), name)
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		fs = append(fs, metadata.LocalResource{Identity: id, Path: path})
	}
	m, e := model.NewPayloadManifest(model.SourceIdentity{UpdateID: "fixture", BuildLabel: "1", Architecture: "x86", Language: "en-us"}, ps)
	if e != nil {
		t.Fatal(e)
	}
	idx, e := wimindex.Open(context.Background(), m, fs[:1], wimindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	as, e := wimindex.DecodeMetadata(context.Background(), m, fs[:1], idx, wimindex.DecodeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer as[0].Close()
	o, e := wimmeta.Parse(context.Background(), as[0], idx, wimmeta.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	return m, fs[1:], o
}
func TestBuildRetainsExactBytesAllDuplicateProvenanceAndMissingReferences(t *testing.T) {
	data := []byte("verified member")
	b := cabinet([]string{"one.dll", "different.dll", "wrong.dll"}, [][]byte{data, data, []byte("unrelated")})
	m, fs, o := input(t, [][]byte{b}, [][]byte{data, []byte("missing")})
	r, e := Build(context.Background(), m, fs, o, Limits{})
	if e != nil {
		t.Fatalf("source-bound CAB bytes unavailable: %v", e)
	}
	defer r.Close()
	s := r.Catalog().Snapshot()
	t.Logf("native-provider=%+v", s.Provider)
	if len(s.Witnesses) != 2 || len(s.Unresolved) != 1 || s.ReferenceClosure || s.ContentVerified || s.ConversionSupported {
		t.Fatalf("wrong closure %+v", s)
	}
	for n, w := range s.Witnesses {
		if w.Size != 15 || w.SHA1 != "157a327afe34c619fe8d414fd181ab03c17607c1" {
			t.Fatal("wrong actual member identity", w)
		}
		a, e := r.Content(n)
		if e != nil {
			t.Fatal(e)
		}
		actual, e := io.ReadAll(io.NewSectionReader(a, 0, int64(w.Size)))
		if e != nil || !bytes.Equal(actual, data) {
			t.Fatal("not actual retained bytes", e)
		}
		h := sha256.Sum256(actual)
		if w.SHA256 != hex.EncodeToString(h[:]) || w.Payload != fs[0].Identity || w.SourceSHA256 != fs[0].Identity.Digest.Value {
			t.Fatal("lost exact source provenance")
		}
	}
	serialized, _ := r.Catalog().MarshalJSON()
	if bytes.Contains(serialized, []byte(fs[0].Path)) || !json.Valid(serialized) {
		t.Fatal("location leaked")
	}
	s.Witnesses[0].SHA1 = "mutated"
	s.Unresolved[0].SHA1 = "mutated"
	if r.Catalog().Snapshot().Witnesses[0].SHA1 == "mutated" {
		t.Fatal("mutable catalog")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	a, e := r.Content(0)
	if e == nil {
		if _, e = a.ReadAt(make([]byte, 1), 0); !errors.Is(e, os.ErrClosed) {
			t.Fatal("closed output readable")
		}
	}
}
func TestBuildRejectsAuthorityAndBudgetsBeforeProvider(t *testing.T) {
	b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, fs, o := input(t, [][]byte{b}, [][]byte{[]byte("xx")})
	for _, oracle := range []*wimmeta.Oracle{nil, {}} {
		if r, e := Build(context.Background(), m, fs, oracle, Limits{}); e == nil || r != nil {
			t.Fatal("asserted oracle accepted")
		}
	}
	wrong := m
	wrong.Source.BuildLabel = "different"
	wrong, _ = model.NewPayloadManifest(wrong.Source, wrong.Payloads, wrong.Queries...)
	if r, e := Build(context.Background(), wrong, fs, o, Limits{}); e == nil || r != nil {
		t.Fatal("different source accepted")
	}
	for _, l := range []Limits{{MaxSourceBytes: 1}, {MaxResultBytes: 1}, {MaxDeclaredBytes: 1}, {MaxMetadataBytes: 1}, {MaxReferences: 1, MaxResultBytes: 128}} {
		if r, e := Build(context.Background(), m, fs, o, l); e == nil || r != nil {
			t.Fatalf("lower limit bypassed %+v", l)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Build(ctx, m, fs, o, Limits{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e := os.WriteFile(fs[0].Path, bytes.Repeat([]byte("z"), len(b)), 0600); e != nil {
		t.Fatal(e)
	}
	if r, e := Build(context.Background(), m, fs, o, Limits{}); e == nil || r != nil {
		t.Fatal("changed source accepted")
	}
}

func TestManifestAndReferenceCountsAreBoundBeforeValidationCopies(t *testing.T) {
	b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, fs, o := input(t, [][]byte{b}, [][]byte{[]byte("xx"), []byte("missing")})
	// An intentionally invalid enlarged manifest still has the original asserted
	// digest. Count refusal must precede canonical manifest serialization/cloning.
	m.Payloads = append(m.Payloads, m.Payloads[0])
	if _, e := Build(context.Background(), m, fs, o, Limits{MaxManifestPayloads: 2}); !errors.Is(e, ErrLimit) {
		t.Fatalf("manifest lower count did not gate validation: %v", e)
	}
}

func TestVariableNamesAndDirectoryCountsGateBeforeNativeConstruction(t *testing.T) {
	b := cabinet([]string{"aa"}, [][]byte{[]byte("xx")})
	m, fs, o := input(t, [][]byte{b, b}, [][]byte{[]byte("xx"), []byte("missing")})
	for _, l := range []Limits{{MaxVariableBytes: 1}, {MaxNameBytes: 1}, {MaxFolders: 1}, {MaxBlocks: 1}} {
		if r, e := Build(context.Background(), m, fs, o, l); e == nil || r != nil {
			if r != nil {
				r.Close()
			}
			t.Fatalf("variable/directory budget bypassed: %+v", l)
		}
	}
}
