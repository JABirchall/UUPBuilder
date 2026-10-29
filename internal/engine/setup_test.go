package engine

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"testing"
	"unicode/utf16"
	"uupbuilder/internal/engine/source"
)

func TestSetupBootTransformsLaunchAndPreservesAllOriginalRecords(t *testing.T) {
	in, media, original, closeParents := setupFixture(t, setupFixtureOptions{})
	r, e := source.BindSetupBoot(context.Background(), in, media, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	d := r.Descriptor()
	if d.GraftFiles != 4 || d.GraftDirectories != 1 || d.OriginalRecords != 10 || d.Source != in.Manifest.Source || d.ManifestDigest != in.Manifest.Digest {
		t.Fatal("wrong fixed-rule lineage", d.GraftFiles, d.GraftDirectories, d.OriginalRecords)
	}
	id, raw, e := r.Resource(0)
	if e != nil {
		t.Fatal(e)
	}
	transformed := make([]byte, id.Size)
	if _, e = raw.ReadAt(transformed, 0); e != nil {
		t.Fatal(e)
	}
	// Original PE security descriptor and its numeric ID survive. The media's
	// distinct security descriptor is appended, never an inherited generic ACL.
	if binary.LittleEndian.Uint32(transformed[4:]) != 2 || !bytes.Equal(transformed[24:44], original[16:36]) || binary.LittleEndian.Uint16(transformed[46:]) != 0x8000 {
		t.Fatal("source security descriptor changed")
	}
	if e = r.InspectMetadata(context.Background(), bytes.NewReader(transformed), uint64(len(transformed))); e != nil {
		t.Fatal("independent record inspection", e)
	}
	// The root's new sibling list uses ASCII uppercase collation, as used by
	// the Windows-style name index, even when the original fixture is unsorted.
	root := uint64(binary.LittleEndian.Uint32(transformed))
	child := binary.LittleEndian.Uint64(transformed[root+16:])
	length := int(binary.LittleEndian.Uint16(transformed[child+100:]))
	name := transformed[child+102 : child+102+uint64(length)]
	if !bytes.Equal(name, []byte{'s', 0, 'e', 0, 't', 0, 'u', 0, 'p', 0, '.', 0, 'e', 0, 'x', 0, 'e', 0}) {
		t.Fatal("grafted sibling framing is not collated")
	}
	for _, off := range []int{26, 100, len(transformed) - 16} {
		changed := bytes.Clone(transformed)
		changed[off] ^= 1
		if e = r.InspectMetadata(context.Background(), bytes.NewReader(changed), uint64(len(changed))); e == nil {
			t.Fatal("undeclared metadata mutation accepted", off)
		}
	}
	a, e := BuildSetupBoot(context.Background(), r, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := a.Close(); e != nil {
			t.Error(e)
		}
	})
	receipt := a.Receipt()
	receipt.Source.Media.ReservedPaths[0] = "caller mutation"
	if a.Receipt().Source.Media.ReservedPaths[0] != "sources/boot.wim" {
		t.Fatal("caller changed archive lineage")
	}
	if !receipt.RecordsVerified || !receipt.Archive.BytesVerified || receipt.Archive.WindowsCompatible || receipt.NativeFilesystemPreservation || receipt.Complete {
		t.Fatal("false operational readiness", receipt)
	}
	snapshot := inspectSetupFixtureOutput(t, a)
	if snapshot.Complete || snapshot.Summary.Entries != 15 || snapshot.Summary.Security != 2 || snapshot.Summary.HardlinkGroups != 1 || snapshot.Summary.Reparse != 1 || snapshot.Summary.Gaps != 2 {
		t.Fatal("Windows records lost in output parse", snapshot.Summary)
	}
	paths := map[string]bool{}
	for _, en := range snapshot.Entries {
		paths[en.Path] = true
		switch en.Path {
		case "/Windows/System32/a", "/Windows/System32/b":
			if en.SecurityID != 0 || en.HardlinkID != 7 || en.CreationTime != 123 || en.AccessTime != 456 || en.WriteTime != 789 || len(en.Tags) != 1 || !bytes.Equal(en.Tags[0].Data, []byte{9, 8, 7}) || len(en.Streams) != 2 {
				t.Fatal("preserved inode changed", en)
			}
			h := sha1.Sum([]byte("preserved ADS"))
			if en.Streams[1].SHA1 != hex.EncodeToString(h[:]) {
				t.Fatal("ADS reference lost")
			}
		case "/setup.exe", "/sources/setup.exe":
			if en.SecurityID != 1 {
				t.Fatal("grafted security not remapped")
			}
		case "/Windows/System32/junction":
			if en.ReparseTag != 0xa0000003 || en.Streams[0].Kind != "reparse" {
				t.Fatal("reparse changed")
			}
		}
	}
	for _, path := range []string{"/sources/recovery/recenv.exe", "/sources/lang.ini", "/sources/en-us/setup.exe.mui"} {
		if !paths[path] {
			t.Fatal("required or original path lost", path)
		}
	}
	closeParents()
	var header [208]byte
	if _, e = a.ReadAt(header[:], 0); e != nil {
		t.Fatal(e)
	}
	if binary.LittleEndian.Uint32(header[120:]) != 1 || binary.LittleEndian.Uint64(header[104:]) != 208 {
		t.Fatal("boot metadata descriptor/index missing")
	}
	launchFound := false
	for _, v := range receipt.Archive.Resources {
		b := make([]byte, v.Size)
		if _, e = a.ReadAt(b, int64(v.Offset)); e != nil {
			t.Fatal(e)
		}
		if string(b) == "[LaunchApp]\r\nAppPath=X:\\sources\\setup.exe\r\n" {
			launchFound = true
		}
		if string(b) == "[LaunchApp]\r\nAppPath=X:\\sources\\recovery\\recenv.exe\r\n" {
			t.Fatal("unused original launch retained as content")
		}
	}
	if !launchFound {
		t.Fatal("declared launch bytes missing")
	}
	a.Close()
	if _, e = a.ReadAt(nil, 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed output", e)
	}
}

func TestSetupBootRejectsUnmatchedShapesAndMissingSetup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options setupFixtureOptions
	}{{"wrong-launch", setupFixtureOptions{launch: "[LaunchApp]\r\nAppPath=cmd.exe\r\n"}}, {"wrong-architecture", setupFixtureOptions{machine: "amd64"}}, {"foreign-library", setupFixtureOptions{foreignLibrary: true}}, {"wrong-generated-image-reservations", setupFixtureOptions{wrongReservation: true}}, {"existing-file", setupFixtureOptions{collision: true}}, {"missing-setup", setupFixtureOptions{missing: true}}, {"launch-hardlink", setupFixtureOptions{sharedLaunch: true}}, {"unexplained-metadata", setupFixtureOptions{unexplained: true}}} {
		t.Run(tc.name, func(t *testing.T) {
			in, media, _, _ := setupFixture(t, tc.options)
			if r, e := source.BindSetupBoot(context.Background(), in, media, source.Limits{}); r != nil || e == nil {
				t.Fatal("unsupported transformation accepted", e)
			}
		})
	}
}
func TestSetupBootRejectsForeignRevokedCorruptAndBoundedInputs(t *testing.T) {
	in, media, _, closeParents := setupFixture(t, setupFixtureOptions{})
	foreign, _, _, _ := setupFixture(t, setupFixtureOptions{launch: "foreign"})
	if r, e := source.BindSetupBoot(context.Background(), foreign, media, source.Limits{}); r != nil || e == nil {
		t.Fatal("foreign media accepted", e)
	}
	for _, l := range []source.Limits{{MaxEntries: 1}, {MaxReferences: 1}, {MaxWitnesses: 1}, {MaxXMLBytes: 1}, {MaxResultBytes: 1}, {MaxReadBytes: 1}} {
		if r, e := source.BindSetupBoot(context.Background(), in, media, l); r != nil || !errors.Is(e, source.ErrLimit) {
			t.Fatal("source bound bypass", l, e)
		}
	}
	r, e := source.BindSetupBoot(context.Background(), in, media, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	for _, l := range []Limits{{MaxResources: 1}, {MaxOutputBytes: 1}, {MaxReadBytes: 1}, {MaxResultBytes: 1}} {
		if a, e := BuildSetupBoot(context.Background(), r, l); a != nil || !errors.Is(e, ErrLimit) {
			t.Fatal("archive bound bypass", l, e)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if a, e := BuildSetupBoot(canceled, r, Limits{}); a != nil || e != context.Canceled {
		t.Fatal("canceled output", e)
	}
	closeParents()
	if a, e := BuildSetupBoot(context.Background(), r, Limits{}); a != nil || !errors.Is(e, os.ErrClosed) {
		t.Fatal("revoked source", e)
	}
	in, media, _, _ = setupFixture(t, setupFixtureOptions{})
	f, e := os.OpenFile(in.Files[0].Path, os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteAt([]byte{1}, 24); e != nil {
		t.Fatal(e)
	}
	f.Close()
	if r, e := source.BindSetupBoot(context.Background(), in, media, source.Limits{}); r != nil || !errors.Is(e, source.ErrIntegrity) {
		t.Fatal("changed original accepted", e)
	}
}

var _ io.ReaderAt = (*SetupBootArtifact)(nil)

func TestSetupBootPreservesExplicitEmptyDirectoryLists(t *testing.T) {
	in, media, _, _ := setupFixture(t, setupFixtureOptions{explicitEmptyList: true})
	r, e := source.BindSetupBoot(context.Background(), in, media, source.Limits{})
	if e != nil {
		t.Fatal("explicit empty sibling list refused", e)
	}
	a, e := BuildSetupBoot(context.Background(), r, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Close() })
	s := inspectSetupFixtureOutput(t, a)
	found := false
	for _, en := range s.Entries {
		if en.Path == "/EmptyDirectory" {
			found = true
			if en.ChildOffset == 0 {
				t.Fatal("original empty child-list pointer lost")
			}
		}
	}
	if !found {
		t.Fatal("original empty directory lost")
	}
}

func TestSetupBootXMLCountsLogicalStreamsAndExtraHardlinkNames(t *testing.T) {
	in, media, _, _ := setupFixture(t, setupFixtureOptions{})
	r, e := source.BindSetupBoot(context.Background(), in, media, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	raw := r.XML()
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	text := []byte(string(utf16.Decode(u[1:])))
	var x struct {
		Images []struct {
			Index  int    `xml:"INDEX,attr"`
			Dirs   uint64 `xml:"DIRCOUNT"`
			Files  uint64 `xml:"FILECOUNT"`
			Total  uint64 `xml:"TOTALBYTES"`
			Hard   uint64 `xml:"HARDLINKBYTES"`
			Name   string `xml:"NAME"`
			Opaque string `xml:"OPAQUE"`
		} `xml:"IMAGE"`
	}
	if e = xml.Unmarshal(text, &x); e != nil {
		t.Fatal(e)
	}
	if len(x.Images) != 1 {
		t.Fatal("image count")
	}
	im := x.Images[0]
	if im.Index != 1 || im.Dirs != 5 || im.Files != 9 || im.Total != 561 || im.Hard != 27 {
		t.Fatal("wrong logical-name/ADS/hardlink XML accounting", im)
	}
	if im.Name != "observed recovery description retained" || im.Opaque != "carry" {
		t.Fatal("undeclared XML field changed")
	}
	in, media, _, _ = setupFixture(t, setupFixtureOptions{wrongSummary: true})
	if r, e := source.BindSetupBoot(context.Background(), in, media, source.Limits{}); r != nil || e == nil {
		t.Fatal("unmatched original summary accepted", e)
	}
}
