package engine

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
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

type setupNode struct {
	name      string
	attrs     uint32
	link      uint64
	body, ads []byte
	tag       bool
	emptyList bool
	children  []setupNode
}

// Reopen the generated fixture as a distinct output-inspection input. Its new
// manifest is never substituted for the frozen original source authority.
func inspectSetupFixtureOutput(t *testing.T, a *SetupBootArtifact) wimmeta.Snapshot {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "output.wim")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	if _, e = io.Copy(io.MultiWriter(f, h), io.NewSectionReader(a, 0, int64(a.Receipt().Archive.Size))); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(h.Sum(nil))}, Size: int64(a.Receipt().Archive.Size), Provenance: model.PackageProvenance{Source: "fixture-output-inspection", Name: "output.wim"}}
	m, e := model.NewPayloadManifest(model.SourceIdentity{UpdateID: "output-inspection", BuildLabel: "fixture", Architecture: "x86", Language: "en-us"}, []model.Payload{{Identity: id, Destination: "output.wim"}})
	if e != nil {
		t.Fatal(e)
	}
	fs := []metadata.LocalResource{{Identity: id, Path: path}}
	idx, e := wimindex.Open(ctx, m, fs, wimindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	c, _ := idx.ContentContainerAt(0)
	if c.Header.BootIndex != 1 || c.Header.Boot.Offset != 208 || c.Header.Boot.Flags != 2 || len(c.Header.GUID) != 32 {
		t.Fatal("independent output header", c.Header)
	}
	as, e := wimindex.DecodeMetadata(ctx, m, fs, idx, wimindex.DecodeLimits{})
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
	if len(as) != 1 {
		t.Fatal("output image count", len(as))
	}
	o, e := wimmeta.Parse(ctx, as[0], idx, wimmeta.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	return o.Snapshot()
}

type setupFixtureOptions struct {
	launch, machine                                               string
	collision, missing, sharedLaunch, unexplained, foreignLibrary bool
	wrongReservation                                              bool
	explicitEmptyList                                             bool
	wrongSummary                                                  bool
}

// A two-image raw WIM exercises the real producers. Its setup executables are
// minimal PE headers used only as data. Security bytes, EA-like opaque tags,
// ADS, hard links and a reparse stream have independent literal expectations.
func setupFixture(t *testing.T, options setupFixtureOptions) (source.Inputs, *source.BoundMediaTree, []byte, func()) {
	t.Helper()
	launch := []byte("[LaunchApp]\r\nAppPath=X:\\sources\\recovery\\recenv.exe\r\n")
	if options.launch != "" {
		launch = []byte(options.launch)
	}
	exe := make([]byte, 128)
	copy(exe, "MZ")
	binary.LittleEndian.PutUint32(exe[60:], 64)
	copy(exe[64:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(exe[68:], 0x14c)
	binary.LittleEndian.PutUint16(exe[86:], 0x102)
	if options.machine == "amd64" {
		binary.LittleEndian.PutUint16(exe[68:], 0x8664)
	}
	Mui := append([]byte(nil), exe...)
	binary.LittleEndian.PutUint16(Mui[86:], 0x2102)
	if options.foreignLibrary {
		binary.LittleEndian.PutUint16(Mui[68:], 0x8664)
	}
	media := setupNode{attrs: 16, children: []setupNode{{name: "setup.exe", attrs: 32, body: exe}, {name: "sources", attrs: 16, children: []setupNode{{name: "setup.exe", attrs: 32, body: exe}, {name: "lang.ini", attrs: 32, body: []byte("[Available UI Languages]\r\nen-US = 3\r\n")}, {name: "en-us", attrs: 16, children: []setupNode{{name: "setup.exe.mui", attrs: 32, body: Mui}}}}}}}
	if options.missing {
		media.children[1].children = media.children[1].children[1:]
	}
	ini := setupNode{name: "winpeshl.ini", attrs: 32, body: launch}
	if options.sharedLaunch {
		ini.link = 77
	}
	pe := setupNode{attrs: 16, children: []setupNode{{name: "Windows", attrs: 16, children: []setupNode{{name: "System32", attrs: 16, children: []setupNode{ini, {name: "a", attrs: 32, link: 7, body: []byte("preserved data"), ads: []byte("preserved ADS"), tag: true}, {name: "b", attrs: 32, link: 7, body: []byte("preserved data"), ads: []byte("preserved ADS"), tag: true}, {name: "junction", attrs: 0x420, body: []byte("opaque reparse bytes")}}}}}, {name: "sources", attrs: 16, children: []setupNode{{name: "recovery", attrs: 16, children: []setupNode{{name: "recenv.exe", attrs: 32, body: []byte("original recovery bytes")}}}}}}}
	if options.sharedLaunch {
		pe.children[0].children[0].children = append(pe.children[0].children[0].children, setupNode{name: "launch.alias", attrs: 32, link: 77, body: launch})
	}
	if options.collision {
		pe.children[1].children = append(pe.children[1].children, setupNode{name: "setup.exe", attrs: 32, body: exe})
	}
	if options.explicitEmptyList {
		pe.children = append(pe.children, setupNode{name: "EmptyDirectory", attrs: 16, emptyList: true})
	}
	blobs := [][]byte{}
	seen := map[string]bool{}
	add := func(b []byte) []byte {
		if len(b) == 0 {
			return nil
		}
		h := sha1.Sum(b)
		key := hex.EncodeToString(h[:])
		if !seen[key] {
			blobs = append(blobs, b)
			seen[key] = true
		}
		return h[:]
	}
	metadataBytes := func(root setupNode, securityControl uint16) []byte {
		le := binary.LittleEndian
		meta := make([]byte, 40)
		le.PutUint32(meta, 40)
		le.PutUint32(meta[4:], 1)
		le.PutUint64(meta[8:], 20)
		meta[16] = 1
		le.PutUint16(meta[18:], securityControl)
		var list func([]setupNode) uint64
		list = func(ns []setupNode) uint64 {
			start := uint64(len(meta))
			positions := make([]int, len(ns))
			for i, n := range ns {
				positions[i] = len(meta)
				u := utf16.Encode([]rune(n.name))
				length := (102 + len(u)*2 + 2 + 7) &^ 7
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
				copy(b[64:], add(n.body))
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
					copy(s[16:], add(n.ads))
					le.PutUint16(s[36:], 6)
					le.PutUint16(s[38:], 'a')
					le.PutUint16(s[40:], 'd')
					le.PutUint16(s[42:], 's')
					meta = append(meta, s...)
				}
			}
			meta = append(meta, make([]byte, 8)...)
			for i, n := range ns {
				if len(n.children) > 0 || n.emptyList {
					off := list(n.children)
					le.PutUint64(meta[positions[i]+16:], off)
				}
			}
			return start
		}
		list([]setupNode{root})
		return meta
	}
	mm, pm := metadataBytes(media, 0x8000), metadataBytes(pe, 0x8004)
	if options.unexplained {
		pm = append(pm, make([]byte, 8)...)
	}
	all := append([][]byte{mm, pm}, blobs...)
	dirs, files, total, hard := 4, 5, 150+len(launch)-53, 27
	if options.explicitEmptyList {
		dirs++
	}
	if options.collision {
		files++
		total += 128
	}
	if options.sharedLaunch {
		files++
		total += len(launch)
		hard += len(launch)
	}
	if options.wrongSummary {
		total++
	}
	xmlText := fmt.Sprintf(`<WIM><IMAGE INDEX="1"><NAME>plain source files</NAME></IMAGE><IMAGE INDEX="2"><DIRCOUNT>%d</DIRCOUNT><FILECOUNT>%d</FILECOUNT><TOTALBYTES>%d</TOTALBYTES><HARDLINKBYTES>%d</HARDLINKBYTES><NAME>observed recovery description retained</NAME><WINDOWS><ARCH>0</ARCH><EDITIONID>WindowsPE</EDITIONID><INSTALLATIONTYPE>WindowsPE</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>19041</BUILD><SPBUILD>1</SPBUILD></VERSION></WINDOWS><OPAQUE>carry</OPAQUE></IMAGE></WIM>`, dirs, files, total, hard)
	xml := []byte{0xff, 0xfe}
	for _, u := range utf16.Encode([]rune(xmlText)) {
		xml = binary.LittleEndian.AppendUint16(xml, u)
	}
	table := 208
	for _, b := range all {
		table += len(b)
	}
	wim := make([]byte, table+len(all)*50+len(xml))
	copy(wim, "MSWIM\x00\x00\x00")
	le := binary.LittleEndian
	le.PutUint32(wim[8:], 208)
	le.PutUint32(wim[12:], 0x10d00)
	le.PutUint16(wim[40:], 1)
	le.PutUint16(wim[42:], 1)
	le.PutUint32(wim[44:], 2)
	desc := func(b []byte, size, off int, flag byte) {
		le.PutUint64(b, uint64(size))
		b[7] = flag
		le.PutUint64(b[8:], uint64(off))
		le.PutUint64(b[16:], uint64(size))
	}
	desc(wim[48:], len(all)*50, table, 2)
	desc(wim[72:], len(xml), table+len(all)*50, 2)
	copy(wim[table+len(all)*50:], xml)
	off := 208
	for i, b := range all {
		copy(wim[off:], b)
		r := wim[table+i*50:]
		flag := byte(0)
		if i < 2 {
			flag = 2
		}
		desc(r, len(b), off, flag)
		le.PutUint16(r[24:], 1)
		le.PutUint32(r[26:], 1)
		h := sha1.Sum(b)
		copy(r[30:], h[:])
		off += len(b)
	}
	h := sha256.Sum256(wim)
	id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(h[:])}, Size: int64(len(wim)), Provenance: model.PackageProvenance{Source: "setup-fixture", Name: "source.esd"}}
	m, e := model.NewPayloadManifest(model.SourceIdentity{UpdateID: "setup-fixture", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}, []model.Payload{{Identity: id, Destination: "source.esd"}})
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "source.bin")
	if e = os.WriteFile(path, wim, 0600); e != nil {
		t.Fatal(e)
	}
	fs := []metadata.LocalResource{{Identity: id, Path: path}}
	ctx := context.Background()
	idx, e := wimindex.Open(ctx, m, fs, wimindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	as, e := wimindex.DecodeMetadata(ctx, m, fs, idx, wimindex.DecodeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	content, e := wimcontent.Decode(ctx, m, fs, idx, wimcontent.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	ins := make([]source.Inputs, 2)
	views := []*wimcontent.ReferenceView{}
	cabs := []*cabindex.Result{}
	for i, a := range as {
		o, e := wimmeta.Parse(ctx, a, idx, wimmeta.Limits{})
		if e != nil {
			t.Fatal(e)
		}
		c, e := cabindex.Build(ctx, m, nil, o, cabindex.Limits{})
		if e != nil {
			t.Fatal(e)
		}
		v, e := wimcontent.BindReferences(ctx, content, o, c, wimcontent.Limits{})
		if e != nil {
			t.Fatal(e)
		}
		views = append(views, v)
		cabs = append(cabs, c)
		ins[i] = source.Inputs{Manifest: m, Files: fs, Index: idx, Metadata: a, Oracle: o, References: v}
	}
	close := func() {
		for _, v := range views {
			v.Close()
		}
		for _, c := range cabs {
			if e := c.Close(); e != nil {
				t.Error(e)
			}
		}
		if e := content.Close(); e != nil {
			t.Error(e)
		}
		for _, a := range as {
			if e := a.Close(); e != nil {
				t.Error(e)
			}
		}
	}
	t.Cleanup(close)
	reserved := []string{"sources/boot.wim", "sources/install.wim"}
	if options.wrongReservation {
		reserved = []string{"unused-image.wim"}
	}
	bound, e := source.BindMediaTree(ctx, ins[0], reserved, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	return ins[1], bound, pm, close
}
