package engine

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
	"uupbuilder/internal/engine/source"
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
	tagCode   uint32
	tagData   []byte
	children  []testNode
}

func preservationFixture(t *testing.T, emptyKernel bool, clean ...bool) (source.Inputs, []byte, func()) {
	return preservationFixtureWithHardlinkGroup(t, emptyKernel, 7, clean...)
}

func preservationFixtureWithHardlinkGroup(t *testing.T, emptyKernel bool, hardlinkGroup uint64, clean ...bool) (source.Inputs, []byte, func()) {
	return preservationFixtureRecords(t, emptyKernel, hardlinkGroup, "", clean...)
}

func preservationFixtureRecords(t *testing.T, emptyKernel bool, hardlinkGroup uint64, short string, clean ...bool) (source.Inputs, []byte, func()) {
	return preservationFixtureExtraFiles(t, emptyKernel, hardlinkGroup, short, 0, clean...)
}

func preservationFixtureExtraFiles(t *testing.T, emptyKernel bool, hardlinkGroup uint64, short string, extra int, clean ...bool) (source.Inputs, []byte, func()) {
	t.Helper()
	ctx := context.Background()
	le := binary.LittleEndian
	data, ads, reparse := []byte("shared original"), []byte("named bytes"), []byte("opaque reparse bytes")
	h1, h2, h3 := sha1.Sum(data), sha1.Sum(ads), sha1.Sum(reparse)
	kernel := h1[:]
	if emptyKernel {
		kernel = nil
	}
	nodes := testNode{attrs: 16, children: []testNode{{name: "Windows", attrs: 16, children: []testNode{{name: "System32", attrs: 16, children: []testNode{{name: "ntoskrnl.exe", attrs: 32, hash: kernel, link: hardlinkGroup}, {name: "kernel.link", attrs: 32, hash: kernel, link: hardlinkGroup}, {name: "config", attrs: 16, children: []testNode{{name: "SOFTWARE", attrs: 32, hash: h1[:]}, {name: "SYSTEM", attrs: 32, hash: h1[:]}}}, {name: "named", attrs: 32, hash: h1[:], ads: h2[:], tag: true}, {name: "empty", attrs: 32}, {name: "reparse", attrs: 0x420, hash: h3[:]}}}}}}}
	for j := 0; j < extra; j++ {
		nodes.children[0].children[0].children = append(nodes.children[0].children[0].children, testNode{name: fmt.Sprintf("extra-%04d", j), attrs: 32, hash: h1[:]})
	}
	if len(clean) > 0 && clean[0] {
		nodes.children[0].children[0].children[3].tag = false
	}
	if len(clean) > 1 && clean[1] {
		v := &nodes.children[0].children[0].children[3]
		v.tag = true
		v.tagCode = 2
		v.tagData = []byte{3, 0, 1, 0x80, 'X', 0, 9, 8, 7}
	}
	// One literal self-relative descriptor with a bounded callback ACE. Its
	// application data is opaque to the oracle and must remain byte-identical.
	meta := make([]byte, 80)
	le.PutUint32(meta, 80)
	le.PutUint32(meta[4:], 1)
	le.PutUint64(meta[8:], 64)
	meta[16] = 1
	le.PutUint16(meta[18:], 0x8004)
	le.PutUint32(meta[32:], 32)
	meta[48] = 2
	le.PutUint16(meta[50:], 32)
	le.PutUint16(meta[52:], 1)
	meta[56] = 9
	le.PutUint16(meta[58:], 24)
	le.PutUint32(meta[60:], 0x120089)
	meta[64] = 1
	meta[65] = 1
	meta[71] = 5
	le.PutUint32(meta[72:], 32)
	copy(meta[76:], []byte{0xde, 0xad, 0xca, 0xfe})
	if len(clean) > 2 && clean[2] {
		le.PutUint64(meta[8:], 0)
		clear(meta[16:])
	}
	var list func([]testNode) uint64
	list = func(nodes []testNode) uint64 {
		start := uint64(len(meta))
		var positions []int
		for _, n := range nodes {
			positions = append(positions, len(meta))
			u := utf16.Encode([]rune(n.name))
			var su []uint16
			if n.name == "ntoskrnl.exe" {
				su = utf16.Encode([]rune(short))
			}
			length := 104
			if len(u) > 0 {
				length = (102 + len(u)*2 + 2 + 7) &^ 7
			}
			if len(su) > 0 {
				length = (102 + len(u)*2 + 2 + len(su)*2 + 2 + 7) &^ 7
			}
			extra := 0
			if n.tag {
				extra = 16
				if n.tagCode != 0 {
					extra = 8 + ((len(n.tagData) + 7) &^ 7)
				}
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
			le.PutUint16(b[98:], uint16(len(su)*2))
			for j, v := range u {
				le.PutUint16(b[102+j*2:], v)
			}
			for j, v := range su {
				le.PutUint16(b[104+len(u)*2+j*2:], v)
			}
			if n.tag {
				code, data := n.tagCode, n.tagData
				if code == 0 {
					code = 0xffff
					data = []byte{9, 8, 7}
				}
				le.PutUint32(b[length:], code)
				le.PutUint32(b[length+4:], uint32(len(data)))
				copy(b[length+8:], data)
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
	xml := fixtureXML(`<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>0</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>19041</BUILD><SPBUILD>1</SPBUILD></VERSION></WINDOWS><OPAQUE>carry</OPAQUE></IMAGE></WIM>`)
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
	return source.Inputs{Manifest: m, Files: files, Index: idx, Metadata: as[0], Oracle: o, References: view}, meta, close
}
func fixtureXML(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2+len(u)*2)
	b[0] = 255
	b[1] = 254
	for n, v := range u {
		binary.LittleEndian.PutUint16(b[2+n*2:], v)
	}
	return b
}
