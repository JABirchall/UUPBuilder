package source

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/cabindex"
	"uupbuilder/internal/metadata/wimcontent"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

type testNode struct {
	name      string
	attrs     uint32
	link      uint64
	hash, ads []byte
	tag       bool
	children  []testNode
}

func boundFixture(t *testing.T, emptyKernel bool) (Inputs, []byte, func()) {
	t.Helper()
	ctx := context.Background()
	le := binary.LittleEndian
	data, ads, reparse := []byte("shared original"), []byte("named bytes"), []byte("opaque reparse bytes")
	h1, h2, h3 := sha1.Sum(data), sha1.Sum(ads), sha1.Sum(reparse)
	kernel := h1[:]
	if emptyKernel {
		kernel = nil
	}
	nodes := testNode{attrs: 16, children: []testNode{{name: "Windows", attrs: 16, children: []testNode{{name: "System32", attrs: 16, children: []testNode{{name: "ntoskrnl.exe", attrs: 32, hash: kernel, link: 7}, {name: "kernel.link", attrs: 32, hash: kernel, link: 7}, {name: "config", attrs: 16, children: []testNode{{name: "SOFTWARE", attrs: 32, hash: h1[:]}, {name: "SYSTEM", attrs: 32, hash: h1[:]}}}, {name: "named", attrs: 32, hash: h1[:], ads: h2[:], tag: true}, {name: "empty", attrs: 32}, {name: "reparse", attrs: 0x420, hash: h3[:]}}}}}}}
	// One literal self-relative descriptor with a bounded callback ACE. Its
	// application data is opaque to the oracle and must remain byte-identical.
	meta := make([]byte, 80)
	le.PutUint32(meta, 80)
	le.PutUint32(meta[4:], 1)
	le.PutUint64(meta[8:], 60)
	meta[16] = 1
	le.PutUint16(meta[18:], 0x8004)
	le.PutUint32(meta[32:], 32)
	meta[48] = 2
	le.PutUint16(meta[50:], 28)
	le.PutUint16(meta[52:], 1)
	meta[56] = 9
	le.PutUint16(meta[58:], 20)
	le.PutUint32(meta[60:], 0x120089)
	meta[64] = 1
	meta[65] = 1
	meta[71] = 5
	le.PutUint32(meta[72:], 32)
	var list func([]testNode) uint64
	list = func(nodes []testNode) uint64 {
		start := uint64(len(meta))
		var positions []int
		for _, n := range nodes {
			positions = append(positions, len(meta))
			u := utf16.Encode([]rune(n.name))
			length := 104
			if len(u) > 0 {
				length = (102 + len(u)*2 + 2 + 7) &^ 7
			}
			extra := 0
			if n.tag {
				extra = 16
			}
			b := make([]byte, length+extra)
			le.PutUint64(b, uint64(len(b)))
			le.PutUint32(b[8:], n.attrs)
			le.PutUint64(b[40:], 123)
			le.PutUint64(b[48:], 456)
			le.PutUint64(b[56:], 789)
			copy(b[64:], n.hash)
			if n.attrs&0x400 != 0 {
				le.PutUint32(b[88:], 0xa0000003)
			} else {
				le.PutUint64(b[88:], n.link)
			}
			le.PutUint16(b[100:], uint16(len(u)*2))
			for j, v := range u {
				le.PutUint16(b[102+j*2:], v)
			}
			if n.tag {
				le.PutUint32(b[length:], 0xffff)
				le.PutUint32(b[length+4:], 3)
				copy(b[length+8:], []byte{9, 8, 7})
			}
			if n.ads != nil {
				le.PutUint16(b[96:], 1)
			}
			meta = append(meta, b...)
			if n.ads != nil {
				s := make([]byte, 48)
				le.PutUint64(s, 48)
				copy(s[16:], n.ads)
				le.PutUint16(s[36:], 6)
				le.PutUint16(s[38:], 'a')
				le.PutUint16(s[40:], 'd')
				le.PutUint16(s[42:], 's')
				meta = append(meta, s...)
			}
		}
		meta = append(meta, make([]byte, 8)...)
		for j, n := range nodes {
			if len(n.children) > 0 {
				off := list(n.children)
				le.PutUint64(meta[positions[j]+16:], off)
			}
		}
		return start
	}
	list([]testNode{nodes})
	xml := encodeXML(`<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>0</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>19041</BUILD><SPBUILD>1</SPBUILD></VERSION></WINDOWS><OPAQUE>carry</OPAQUE></IMAGE></WIM>`)
	blobs := [][]byte{meta, data, ads, reparse}
	total := 208 + len(xml) + len(blobs)*50
	for _, v := range blobs {
		total += len(v)
	}
	wim := make([]byte, total)
	copy(wim, "MSWIM\x00\x00\x00")
	le.PutUint32(wim[8:], 208)
	le.PutUint32(wim[12:], 0x10d00)
	le.PutUint32(wim[16:], 0x80)
	le.PutUint16(wim[40:], 1)
	le.PutUint16(wim[42:], 1)
	le.PutUint32(wim[44:], 1)
	table := 208
	for _, v := range blobs {
		table += len(v)
	}
	writeDesc := func(b []byte, size, off int, flag byte) {
		le.PutUint64(b, uint64(size))
		b[7] = flag
		le.PutUint64(b[8:], uint64(off))
		le.PutUint64(b[16:], uint64(size))
	}
	writeDesc(wim[48:], len(blobs)*50, table, 2)
	writeDesc(wim[72:], len(xml), table+len(blobs)*50, 2)
	copy(wim[table+len(blobs)*50:], xml)
	off := 208
	for n, v := range blobs {
		copy(wim[off:], v)
		r := wim[table+n*50:]
		flag := byte(0)
		if n == 0 {
			flag = 2
		}
		writeDesc(r, len(v), off, flag)
		le.PutUint16(r[24:], 1)
		le.PutUint32(r[26:], 1)
		sum := sha1.Sum(v)
		copy(r[30:], sum[:])
		off += len(v)
	}
	sum := sha256.Sum256(wim)
	id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, Size: int64(len(wim)), Provenance: model.PackageProvenance{Source: "fixture", Name: "not-an-os.esd"}}
	path := filepath.Join(t.TempDir(), "misleading-name")
	if e := os.WriteFile(path, wim, 0600); e != nil {
		t.Fatal(e)
	}
	m, e := model.NewPayloadManifest(model.SourceIdentity{UpdateID: "fixture", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}, []model.Payload{{Identity: id, Destination: "opaque.esd"}})
	if e != nil {
		t.Fatal(e)
	}
	files := []metadata.LocalResource{{Identity: id, Path: path}}
	idx, e := wimindex.Open(ctx, m, files, wimindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	as, e := wimindex.DecodeMetadata(ctx, m, files, idx, wimindex.DecodeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	o, e := wimmeta.Parse(ctx, as[0], idx, wimmeta.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	content, e := wimcontent.Decode(ctx, m, files, idx, wimcontent.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	cab, e := cabindex.Build(ctx, m, nil, o, cabindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	view, e := wimcontent.BindReferences(ctx, content, o, cab, wimcontent.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	close := func() {
		for _, e := range []error{view.Close(), content.Close(), cab.Close(), as[0].Close()} {
			if e != nil {
				t.Error(e)
			}
		}
	}
	t.Cleanup(close)
	return Inputs{m, files, idx, as[0], o, view}, meta, close
}

func TestBoundRecipePreservesRawOpaqueSecurityStreamsAndDistinctFiles(t *testing.T) {
	in, meta, close := boundFixture(t, false)
	r, e := BindCanonical(context.Background(), in, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	d := r.Descriptor()
	if d.Resources != 4 || d.Recipe.ImageIndex != 1 || d.Oracle.MetadataComplete {
		t.Fatal("wrong authority/opaque semantics", d.Resources, d.Oracle.MetadataComplete)
	}
	id, a, e := r.Resource(0)
	b := make([]byte, id.Size)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.ReadAt(b, 0); e != nil || !bytes.Equal(b, meta) {
		t.Fatal("raw metadata changed", e)
	}
	shared := sha1.Sum([]byte("shared original"))
	found := false
	for n := 1; n < d.Resources; n++ {
		id, _, e := r.Resource(n)
		if e != nil {
			t.Fatal(e)
		}
		if id.SHA1 == hex.EncodeToString(shared[:]) {
			found = true
			if id.References != 5 {
				t.Fatal("hardlinks or identical-byte separate files lost", id.References)
			}
		}
	}
	if !found {
		t.Fatal("shared stream missing")
	}
	d.Expected[0].Path = "caller mutation"
	if r.Descriptor().Expected[0].Path == "caller mutation" {
		t.Fatal("mutable descriptor")
	}
	in.Manifest.Payloads[0].Destination = "mutated"
	if r.Descriptor().Recipe.ManifestDigest != d.Recipe.ManifestDigest {
		t.Fatal("caller changed bound recipe")
	}
	close()
	if _, _, e = r.Resource(0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed parent", e)
	}
}
func TestCanonicalRejectsEmptyCriticalOSPath(t *testing.T) {
	in, _, _ := boundFixture(t, true)
	if r, e := BindCanonical(context.Background(), in, Limits{}); r != nil || e == nil {
		t.Fatal("empty kernel granted install role", e)
	}
}

func TestCanonicalRejectsForeignReferencesChangedOriginalAndClosedMetadata(t *testing.T) {
	in, _, _ := boundFixture(t, false)
	foreign, _, _ := boundFixture(t, true)
	wrong := in
	wrong.References = foreign.References
	if r, e := BindCanonical(context.Background(), wrong, Limits{}); r != nil || !errors.Is(e, ErrInput) {
		t.Fatal("foreign references", e)
	}
	f, e := os.OpenFile(in.Files[0].Path, os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteAt([]byte{1}, 24); e != nil {
		t.Fatal(e)
	}
	f.Close()
	if r, e := BindCanonical(context.Background(), in, Limits{}); r != nil || !errors.Is(e, ErrIntegrity) {
		t.Fatal("changed original", e)
	}
	in.Metadata.Close()
	if r, e := BindCanonical(context.Background(), in, Limits{}); r != nil || !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed metadata", e)
	}
}
