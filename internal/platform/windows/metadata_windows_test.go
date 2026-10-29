package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestMetadataRejectsMalformedStreamAndEARecordsBeforeCopy(t *testing.T) {
	if f := fieldError(windows.STATUS_ACCESS_DENIED); f.Status != "access-denied" || f.NativeCode != 0xc0000022 {
		t.Fatal("native denial lost", f)
	}
	le := binary.LittleEndian
	stream := make([]byte, 48)
	le.PutUint32(stream[4:], 14)
	for n, u := range utf16.Encode([]rune(":a:$DATA")) {
		le.PutUint16(stream[24+n*2:], u)
	}
	for _, mutate := range []func([]byte){func(b []byte) { le.PutUint32(b, 1) }, func(b []byte) { le.PutUint32(b[4:], 0xfffffffe) }, func(b []byte) { le.PutUint32(b[4:], 3) }} {
		b := append([]byte(nil), stream...)
		mutate(b)
		if _, e := parseStreams(b, 256); e == nil {
			t.Fatal("malformed streams accepted")
		}
	}
	if _, e := parseStreams(stream, 0); !errors.Is(e, ErrTreeLimit) {
		t.Fatal("stream budget ignored", e)
	}
	for _, name := range []string{":../x:$DATA", ":a:b:$DATA", ":a/b:$DATA", ":a\\b:$DATA"} {
		if _, e := safeStreamName(name); e == nil {
			t.Fatal("unsafe ADS", name)
		}
	}
	ea := []byte{0, 0, 0, 0, 0, 1, 2, 0, 'A', 0, 1, 2}
	if out, e := parseEAs(ea, 1); e != nil || len(out) != 1 || string(out[0].Name) != "A" {
		t.Fatal(out, e)
	}
	for _, b := range [][]byte{ea[:9], {1, 0, 0, 0, 0, 1, 2, 0, 'A', 0, 1, 2}, {0, 0, 0, 0, 0, 255, 255, 255}} {
		if _, e := parseEAs(b, 256); e == nil {
			t.Fatal("malformed EA accepted")
		}
	}
}

func TestMetadataObservesOwnedHardlinkADSAndReparseWithoutFollowing(t *testing.T) {
	ctx := context.Background()
	w, e := CreateWorkspace(t.TempDir(), "metadata-fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	tree, e := w.CreateOwnedTree("fresh", "inspect", "fixture", TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer tree.Close()
	if e = tree.CreateFile(ctx, "original", []byte("same bytes")); e != nil {
		t.Fatal(e)
	}
	if e = tree.CreateFile(ctx, "independent", []byte("same bytes")); e != nil {
		t.Fatal(e)
	}
	if e = tree.CreateHardlink(ctx, "original", "alias"); e != nil {
		t.Fatal(e)
	}
	if e = tree.CreateNamedStream(ctx, "original", "witness", []byte("named bytes")); e == nil {
		t.Fatal("mutated shared hardlink file stream")
	}
	if e = tree.CreateNamedStream(ctx, "independent", "witness", []byte("named bytes")); e != nil {
		t.Fatal(e)
	}
	a, e := tree.Observe(ctx, "original", MetadataLimits{})
	if e != nil {
		t.Fatal(e)
	}
	b, e := tree.Observe(ctx, "alias", MetadataLimits{})
	if e != nil || a.Identity != b.Identity || a.LinkCount != 2 {
		t.Fatal(a, b, e)
	}
	c, e := tree.Observe(ctx, "independent", MetadataLimits{})
	if e != nil || c.Identity == a.Identity {
		t.Fatal(c, e)
	}
	found := false
	for _, s := range c.NamedStreams {
		if string(utf16.Decode(s.Name)) == ":witness:$DATA" && s.Size == 11 {
			found = true
		}
	}
	if !found || c.Streams.Status != "complete" {
		t.Fatal("actual ADS absent", c)
	}
	if e = tree.CreateDirectory(ctx, "reparse"); e != nil {
		t.Fatal(e)
	}
	raw := setFixtureJunction(t, tree.entries["reparse"].file, filepath.Join(w.Path(), "fresh"))
	o, e := tree.Observe(ctx, "reparse", MetadataLimits{})
	if e != nil || o.Reparse.Status != "complete" || o.ReparseTag != 0xa0000003 || !slices.Equal(o.Reparse.Raw, raw) {
		t.Fatal(o, e)
	}
	if e = tree.Cleanup(ctx); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("reparse followed or deleted", e)
	}
	deleteFixtureJunction(t, tree.entries["reparse"].file)
	if e = tree.Cleanup(ctx); e != nil {
		t.Fatal(e)
	}
	if e = tree.RemoveEmpty(ctx); e != nil {
		t.Fatal(e)
	}
	t.Log("ordinary synthetic NTFS: hardlink IDs equal with 2 links; identical bytes independent ID; named ADS size=11; mountpoint raw bytes read without target traversal")
}

func setFixtureJunction(t *testing.T, f *os.File, target string) []byte {
	t.Helper()
	u := utf16.Encode([]rune(`\??\` + strings.TrimPrefix(target, `\\?\`)))
	b := make([]byte, 16+(len(u)+2)*2)
	binary.LittleEndian.PutUint32(b, 0xa0000003)
	binary.LittleEndian.PutUint16(b[4:], uint16(len(b)-8))
	binary.LittleEndian.PutUint16(b[10:], uint16(len(u)*2))
	binary.LittleEndian.PutUint16(b[12:], uint16((len(u)+1)*2))
	for n, v := range u {
		binary.LittleEndian.PutUint16(b[16+n*2:], v)
	}
	var n uint32
	if e := windows.DeviceIoControl(windows.Handle(f.Fd()), windows.FSCTL_SET_REPARSE_POINT, &b[0], uint32(len(b)), nil, 0, &n, nil); e != nil {
		t.Fatalf("actual self-created junction refused (not pass): %v", e)
	}
	return b
}
func deleteFixtureJunction(t *testing.T, f *os.File) {
	t.Helper()
	b := []byte{3, 0, 0, 160, 0, 0, 0, 0}
	var n uint32
	if e := windows.DeviceIoControl(windows.Handle(f.Fd()), windows.FSCTL_DELETE_REPARSE_POINT, &b[0], uint32(len(b)), nil, 0, &n, nil); e != nil {
		t.Fatal(e)
	}
}

func TestMetadataObservesActualOwnedNTFSFieldsAndDenials(t *testing.T) {
	ctx := context.Background()
	w, e := CreateWorkspace(t.TempDir(), "metadata-fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	tree, e := w.CreateOwnedTree("fresh", "inspect", "fixture", TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer tree.Close()
	if e = tree.CreateFile(ctx, "file", []byte("ordinary bytes")); e != nil {
		t.Fatal(e)
	}
	if e = tree.CreateDirectory(ctx, "directory"); e != nil {
		t.Fatal(e)
	}
	// EAs are set on the exact self-created file handle, never on a host path.
	ea := []byte{0, 0, 0, 0, 0, 7, 3, 0, 'F', 'I', 'X', 'T', 'U', 'R', 'E', 0, 9, 8, 7}
	f := tree.entries["file"].file
	if e = windows.NtSetEaFile(windows.Handle(f.Fd()), &windows.IO_STATUS_BLOCK{}, &ea[0], uint32(len(ea))); e != nil {
		t.Fatalf("actual EA fixture refused (not a pass): %v", e)
	}
	for _, name := range []string{"file", "directory"} {
		o, e := tree.Observe(ctx, name, MetadataLimits{})
		if e != nil {
			t.Fatal(e)
		}
		if o.Basic.Status != "complete" || o.FileID.Status != "complete" || o.Security.Status != "complete" || o.CreationTime == 0 || o.Identity.FileIndex == 0 {
			t.Fatal(o)
		}
		if name == "file" && (o.EAs.Status != "complete" || len(o.ExtendedAttributes) != 1 || string(o.ExtendedAttributes[0].Name) != "FIXTURE") {
			t.Fatal(o)
		}
		t.Logf("ordinary NTFS fixture %s: attrs=%#x links=%d security=%s SACL=%s(%d) ADS=%s EA=%s reparse=%s complete=%t", name, o.Attributes, o.LinkCount, o.Security.Status, o.SACL.Status, o.SACL.NativeCode, o.Streams.Status, o.EAs.Status, o.Reparse.Status, o.Complete)
	}
	if _, e = tree.Observe(ctx, "file", MetadataLimits{MaxResultBytes: 1}); !errors.Is(e, ErrTreeLimit) {
		t.Fatal("exhausted observation result budget", e)
	}
	if e = tree.Cleanup(ctx); e != nil {
		t.Fatal(e)
	}
	if e = tree.RemoveEmpty(ctx); e != nil {
		t.Fatal(e)
	}
}
