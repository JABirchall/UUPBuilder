package engine

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

// These are data fixtures, never target executables. Every authority comes from
// the actual index, metadata, content and reference producers.
func mediaFixture(t *testing.T, alter func(*testNode)) (source.Inputs, []byte, func()) {
	t.Helper()
	data := []byte("source setup fixture bytes")
	h := sha1.Sum(data)
	nodes := testNode{attrs: 16, children: []testNode{{name: "setup.exe", attrs: 32, hash: h[:]}, {name: "sources", attrs: 16, children: []testNode{{name: "setup.exe", attrs: 32, hash: h[:]}, {name: "lang.ini", attrs: 32, hash: h[:]}}}, {name: "empty", attrs: 32}, {name: "emptydir", attrs: 16}}}
	if alter != nil {
		alter(&nodes)
	}
	le := binary.LittleEndian
	meta := make([]byte, 40)
	le.PutUint32(meta, 40)
	le.PutUint32(meta[4:], 1)
	le.PutUint64(meta[8:], 20)
	meta[16] = 1
	le.PutUint16(meta[18:], 0x8000)
	var list func([]testNode) uint64
	list = func(ns []testNode) uint64 {
		start := uint64(len(meta))
		positions := make([]int, len(ns))
		for i, n := range ns {
			positions[i] = len(meta)
			u := utf16.Encode([]rune(n.name))
			length := (102 + len(u)*2 + 2 + 7) &^ 7
			b := make([]byte, length)
			le.PutUint64(b, uint64(length))
			le.PutUint32(b[8:], n.attrs)
			le.PutUint64(b[40:], 123)
			le.PutUint64(b[48:], 456)
			le.PutUint64(b[56:], 789)
			copy(b[64:], n.hash)
			le.PutUint64(b[88:], n.link)
			le.PutUint16(b[100:], uint16(len(u)*2))
			for j, v := range u {
				le.PutUint16(b[102+j*2:], v)
			}
			meta = append(meta, b...)
		}
		meta = append(meta, make([]byte, 8)...)
		for i, n := range ns {
			if len(n.children) > 0 {
				off := list(n.children)
				le.PutUint64(meta[positions[i]+16:], off)
			}
		}
		return start
	}
	list([]testNode{nodes})
	text := `<WIM><IMAGE INDEX="1"><NAME>Misleading OS Recovery</NAME><OPAQUE>preserve</OPAQUE></IMAGE></WIM>`
	units := utf16.Encode([]rune(text))
	xml := []byte{0xff, 0xfe}
	for _, v := range units {
		xml = le.AppendUint16(xml, v)
	}
	table := 208 + len(meta) + len(data)
	wim := make([]byte, table+100+len(xml))
	copy(wim, "MSWIM\x00\x00\x00")
	le.PutUint32(wim[8:], 208)
	le.PutUint32(wim[12:], 0x10d00)
	le.PutUint16(wim[40:], 1)
	le.PutUint16(wim[42:], 1)
	le.PutUint32(wim[44:], 1)
	desc := func(b []byte, size, off int, flags byte) {
		le.PutUint64(b, uint64(size))
		b[7] = flags
		le.PutUint64(b[8:], uint64(off))
		le.PutUint64(b[16:], uint64(size))
	}
	desc(wim[48:], 100, table, 2)
	desc(wim[72:], len(xml), table+100, 2)
	copy(wim[table+100:], xml)
	off := 208
	for i, b := range [][]byte{meta, data} {
		copy(wim[off:], b)
		r := wim[table+i*50:]
		flag := byte(0)
		if i == 0 {
			flag = 2
		}
		desc(r, len(b), off, flag)
		le.PutUint16(r[24:], 1)
		le.PutUint32(r[26:], 1)
		sum := sha1.Sum(b)
		copy(r[30:], sum[:])
		off += len(b)
	}
	sum := sha256.Sum256(wim)
	id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, Size: int64(len(wim)), Provenance: model.PackageProvenance{Source: "media-fixture", Name: "opaque.esd"}}
	m, e := model.NewPayloadManifest(model.SourceIdentity{UpdateID: "media-fixture", BuildLabel: "fixture", Architecture: "x86", Language: "en-us"}, []model.Payload{{Identity: id, Destination: "opaque.esd"}})
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
	o, e := wimmeta.Parse(ctx, as[0], idx, wimmeta.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	c, e := wimcontent.Decode(ctx, m, fs, idx, wimcontent.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	cab, e := cabindex.Build(ctx, m, nil, o, cabindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	view, e := wimcontent.BindReferences(ctx, c, o, cab, wimcontent.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	close := func() {
		for _, e := range []error{view.Close(), cab.Close(), c.Close(), as[0].Close()} {
			if e != nil {
				t.Error(e)
			}
		}
	}
	t.Cleanup(close)
	return source.Inputs{Manifest: m, Files: fs, Index: idx, Metadata: as[0], Oracle: o, References: view}, meta, close
}

func TestMediaTreeMaterializesVerifiedSourceFilesAndKeepsMissingImages(t *testing.T) {
	ctx := context.Background()
	in, meta, closeParents := mediaFixture(t, nil)
	r, e := source.BindMediaTree(ctx, in, []string{"sources/boot.wim", "sources/install.wim"}, source.Limits{})
	if e != nil {
		t.Fatal("source media binding", e)
	}
	a, e := MaterializeMediaTree(ctx, r, MediaTreeLimits{})
	if e != nil {
		t.Fatal("materialization", e)
	}
	t.Cleanup(func() {
		if e := a.Close(); e != nil {
			t.Error(e)
		}
	})
	d := a.Receipt()
	if !d.SourceFilesVerified || d.Complete || d.NativeFilesystemPreservation || len(d.MissingImages) != 2 || d.Files != 4 || d.Directories != 2 || d.Resources != 2 {
		t.Fatal("false readiness or lost files", d)
	}
	if d.Source.Source != in.Manifest.Source || d.Source.Metadata != in.Metadata.Receipt() || d.Source.Oracle != in.Oracle.Claim() {
		t.Fatal("original source binding lost", d.Source)
	}
	closeParents()
	for _, tc := range []struct{ path, body string }{{"setup.exe", "source setup fixture bytes"}, {"sources/setup.exe", "source setup fixture bytes"}, {"sources/lang.ini", "source setup fixture bytes"}, {"empty", ""}} {
		f, e := a.Open(tc.path)
		if e != nil {
			t.Fatal(tc.path, e)
		}
		got, e := io.ReadAll(f)
		if e != nil || string(got) != tc.body {
			t.Fatal(tc.path, string(got), e)
		}
	}
	original, e := a.OriginalMetadata()
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(original)
	if e != nil || !bytes.Equal(b, meta) {
		t.Fatal("raw security/record evidence changed", e)
	}
	if _, e = a.Open("sources/boot.wim"); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("missing generated image appeared", e)
	}
	d.MissingImages[0] = "caller mutation"
	if a.Receipt().MissingImages[0] == "caller mutation" {
		t.Fatal("mutable receipt")
	}
	f, e := a.Open("setup.exe")
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = f.Read(make([]byte, 1)); !errors.Is(e, os.ErrClosed) {
		t.Fatal("borrower survived Close", e)
	}
}

func TestMediaTreeRejectsForeignSourceRevocationAndBounds(t *testing.T) {
	ctx := context.Background()
	in, _, closeParents := mediaFixture(t, nil)
	wrong := in
	wrong.Manifest.Source.UpdateID = "foreign"
	if r, e := source.BindMediaTree(ctx, wrong, []string{"sources/boot.wim"}, source.Limits{}); r != nil || e == nil {
		t.Fatal("foreign manifest accepted", e)
	}
	foreign, _, _ := mediaFixture(t, func(n *testNode) { n.children[0].name = "other.exe" })
	wrong = in
	wrong.References = foreign.References
	if r, e := source.BindMediaTree(ctx, wrong, []string{"sources/boot.wim"}, source.Limits{}); r != nil || e == nil {
		t.Fatal("foreign predecessor accepted", e)
	}
	r, e := source.BindMediaTree(ctx, in, []string{"sources/boot.wim"}, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	for _, l := range []MediaTreeLimits{{MaxEntries: 1}, {MaxResources: 1}, {MaxOutputBytes: 1}, {MaxReadBytes: 1}, {MaxResultBytes: 1}, {MaxBufferBytes: 1}} {
		if a, e := MaterializeMediaTree(ctx, r, l); a != nil || !errors.Is(e, ErrLimit) {
			t.Fatal("bound bypass", l, e)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if a, e := MaterializeMediaTree(canceled, r, MediaTreeLimits{}); a != nil || !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation", e)
	}
	closeParents()
	if a, e := MaterializeMediaTree(ctx, r, MediaTreeLimits{}); a != nil || !errors.Is(e, os.ErrClosed) {
		t.Fatal("revoked source consumed", e)
	}
}

func TestMediaTreeRejectsGraftAndWindowsPathCollisions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		alter    func(*testNode)
		reserved []string
	}{
		{"same", func(n *testNode) {
			n.children[1].children = append(n.children[1].children, testNode{name: "BOOT.WIM", attrs: 32})
		}, []string{"sources/boot.wim"}},
		{"ancestor", func(n *testNode) { n.children[1].attrs = 32; n.children[1].children = nil }, []string{"sources/boot.wim"}},
		{"descendant", nil, []string{"sources"}},
		{"duplicate-target", nil, []string{"sources/boot.wim", "SOURCES/BOOT.WIM"}},
		{"traversal", nil, []string{"../boot.wim"}},
		{"file-alias", func(n *testNode) { n.children = append(n.children, testNode{name: "SETUP.EXE", attrs: 32}) }, []string{"sources/boot.wim"}},
		{"unicode-file-alias", func(n *testNode) {
			n.children = append(n.children, testNode{name: "K.txt", attrs: 32}, testNode{name: "\u212a.txt", attrs: 32})
		}, []string{"sources/boot.wim"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, _, _ := mediaFixture(t, tc.alter)
			if r, e := source.BindMediaTree(context.Background(), in, tc.reserved, source.Limits{}); r != nil || e == nil {
				t.Fatal("collision accepted", e)
			}
		})
	}
}

func TestMediaTreeRefusesFlatteningWindowsImageMetadata(t *testing.T) {
	in, _, _ := preservationFixture(t, false)
	if r, e := source.BindMediaTree(context.Background(), in, []string{"sources/boot.wim"}, source.Limits{}); r != nil || e == nil {
		t.Fatal("OS/ADS/hardlinks/reparse tree flattened", e)
	}
}

func TestMediaTreeRejectsChangedOriginalContainer(t *testing.T) {
	in, _, _ := mediaFixture(t, nil)
	f, e := os.OpenFile(in.Files[0].Path, os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, writeErr := f.WriteAt([]byte{0x7f}, 208)
	if e = errors.Join(writeErr, f.Close()); e != nil {
		t.Fatal(e)
	}
	if r, e := source.BindMediaTree(context.Background(), in, []string{"sources/boot.wim"}, source.Limits{}); r != nil || !errors.Is(e, source.ErrIntegrity) {
		t.Fatal("corrupt original accepted despite historical verified reference bytes", e)
	}
}

func TestMediaTreeCloseRevokesEmptyReadersAndPreservesUnknownEntries(t *testing.T) {
	t.Setenv("TEMP", t.TempDir())
	t.Setenv("TMP", os.Getenv("TEMP"))
	in, _, _ := mediaFixture(t, nil)
	r, e := source.BindMediaTree(context.Background(), in, []string{"sources/boot.wim"}, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	a, e := MaterializeMediaTree(context.Background(), r, MediaTreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	empty, e := a.Open("empty")
	if e != nil {
		t.Fatal(e)
	}
	root := a.store.Path()
	foreign := filepath.Join(root, "unknown.data")
	if e = os.WriteFile(foreign, []byte("preserve unknown"), 0600); e != nil {
		t.Fatal(e)
	}
	first := a.Close()
	if first == nil || a.Close() != first {
		t.Fatal("cleanup failure not retained", first)
	}
	if b, e := os.ReadFile(foreign); e != nil || string(b) != "preserve unknown" {
		t.Fatal("unknown file removed", e)
	}
	if _, e = empty.Read(make([]byte, 1)); !errors.Is(e, os.ErrClosed) {
		t.Fatal("empty borrower hid revocation", e)
	}
}
