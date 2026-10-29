package wimindex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

var le = binary.LittleEndian

// Hand-built format fixtures: the table at 4096 holds 50-byte records; data
// lives at independent literal offsets. Expected mappings never use the parser.
func resource(b []byte, size, offset, original uint64, flags byte) {
	le.PutUint64(b, size)
	b[7] = flags
	le.PutUint64(b[8:], offset)
	le.PutUint64(b[16:], original)
}
func record(size, offset, original uint64, flags byte, hash byte) []byte {
	b := make([]byte, 50)
	resource(b, size, offset, original, flags)
	le.PutUint16(b[24:], 1)
	le.PutUint32(b[26:], 1)
	for i := 30; i < 50; i++ {
		b[i] = hash
	}
	return b
}
func fixture(records ...[]byte) []byte {
	b := make([]byte, 8192)
	copy(b, "MSWIM\x00\x00\x00")
	le.PutUint32(b[8:], 208)
	le.PutUint32(b[12:], 0xe00)
	le.PutUint32(b[16:], 0x80002)
	le.PutUint32(b[20:], 32768)
	le.PutUint16(b[40:], 1)
	le.PutUint16(b[42:], 1)
	images := uint32(0)
	for _, r := range records {
		if r[7]&2 != 0 && le.Uint32(r[26:]) != 0 {
			images++
		}
	}
	le.PutUint32(b[44:], images)
	resource(b[48:], uint64(len(records)*50), 4096, uint64(len(records)*50), 2)
	for i, r := range records {
		copy(b[4096+i*50:], r)
	}
	x := "<WIM>"
	for i := uint32(1); i <= images; i++ {
		x += `<IMAGE INDEX="` + string(rune('0'+i)) + `"><WINDOWS><ARCH>0</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE>`
	}
	x += "</WIM>"
	u := utf16.Encode([]rune(x))
	xml := make([]byte, len(u)*2)
	for i, v := range u {
		le.PutUint16(xml[i*2:], v)
	}
	copy(b[6000:], xml)
	resource(b[72:], uint64(len(xml)), 6000, uint64(len(xml)), 2)
	return b
}
func inputs(t *testing.T, bodies ...[]byte) (model.PayloadManifest, []metadata.LocalResource) {
	t.Helper()
	var ps []model.Payload
	var fs []metadata.LocalResource
	for i, b := range bodies {
		sum := sha256.Sum256(b)
		name := string(rune('a'+i)) + ".esd"
		id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, Size: int64(len(b)), Provenance: model.PackageProvenance{Source: "uupdump:get.php:fixture", Name: name}}
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		ps = append(ps, model.Payload{Identity: id, Destination: name})
		fs = append(fs, metadata.LocalResource{Identity: id, Path: p})
	}
	m, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: "fixture", BuildLabel: "1", Architecture: "x86", Language: "en-us"}, ps)
	if err != nil {
		t.Fatal(err)
	}
	return m, fs
}
func TestIndexKeepsWitnessesImmutableAndDeterministic(t *testing.T) {
	b := fixture(record(8, 256, 8, 2, 1), record(4, 320, 4, 0, 2))
	m, fs := inputs(t, b, b)
	idx, err := Open(context.Background(), m, fs, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("02", 20)
	witnesses := idx.Lookup(hash)
	if len(witnesses) != 2 || witnesses[0].Payload.Provenance.Name != "a.esd" || witnesses[1].Payload.Provenance.Name != "b.esd" {
		t.Fatalf("lost provenance witnesses: %+v", witnesses)
	}
	original, _ := idx.MarshalJSON()
	digest := idx.Digest()
	witnesses[0].Payload.Provenance.Name = "changed"
	snap := idx.Snapshot()
	snap.Containers[0].Entries[0].SHA1 = "changed"
	snap.Containers[0].Images[0].Edition = "changed"
	m.Payloads[0].Destination = "changed"
	fs[0].Identity.Size = 1
	again, _ := idx.MarshalJSON()
	if !bytes.Equal(original, again) || idx.Digest() != digest || bytes.Contains(again, []byte(fs[0].Path)) {
		t.Fatal("public state aliases caller/accessor memory or includes runtime path")
	}
	var decoded any
	if json.Unmarshal(original, &decoded) != nil {
		t.Fatal("invalid serialized index")
	}
	m, fs = inputs(t, b, b)
	fs[0], fs[1] = fs[1], fs[0]
	idx2, err := Open(context.Background(), m, fs, Limits{})
	if err != nil || idx2.Digest() != digest {
		t.Fatalf("nondeterministic index: %v", err)
	}
}
func TestImageMappingUsesTableOrderAndBootAlias(t *testing.T) {
	b := fixture(record(8, 350, 8, 2, 1), record(8, 300, 8, 2, 2), record(8, 256, 8, 2, 3))
	le.PutUint32(b[120:], 2)
	copy(b[96:120], b[4096+50:4096+74])
	m, fs := inputs(t, b)
	idx, err := Open(context.Background(), m, fs, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	c := idx.Snapshot().Containers[0]
	if !c.MappingComplete || c.Header.BootIndex != 2 || c.Images[2].Index != 3 || c.Images[2].MetadataEntry != 3 || c.Entries[2].Location.PhysicalOffset != 256 {
		t.Fatalf("mapped by physical order/boot index: %+v", c)
	}
}
func TestIndexRejectsUnboundOrChangedSources(t *testing.T) {
	for _, kind := range []string{"missing", "wrong-provenance", "corrupt", "wrong-size", "mutated-manifest", "omitted"} {
		t.Run(kind, func(t *testing.T) {
			m, fs := inputs(t, fixture(record(8, 256, 8, 2, 1)))
			switch kind {
			case "missing":
				os.Remove(fs[0].Path)
			case "wrong-provenance":
				fs[0].Identity.Provenance.Name = "wrong"
			case "corrupt":
				// Alter unused padding so structural parsing still succeeds. Only
				// full source verification can detect this corruption.
				body, err := os.ReadFile(fs[0].Path)
				if err != nil {
					t.Fatal(err)
				}
				body[7000] ^= 255
				if err := os.WriteFile(fs[0].Path, body, 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-size":
				os.Truncate(fs[0].Path, 200)
			case "mutated-manifest":
				m.Payloads[0].Identity.Provenance.Name = "wrong"
			case "omitted":
				fs = nil
			}
			if idx, err := Open(context.Background(), m, fs, Limits{}); err == nil || idx != nil {
				t.Fatalf("accepted %s source", kind)
			}
		})
	}
}
func TestIndexRejectsMalformedRangesAndConflicts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"truncated-table", func(b []byte) { resource(b[48:], 51, 4096, 51, 2) }},
		{"table-outside-file", func(b []byte) { resource(b[48:], 100, 8190, 100, 2) }},
		{"offset-overflow", func(b []byte) { le.PutUint64(b[4096+8:], math.MaxUint64-2) }},
		{"logical-overflow", func(b []byte) { le.PutUint64(b[4096+16:], math.MaxUint64) }},
		{"count-limit", func(b []byte) { resource(b[48:], 50*262145, 4096, 50*262145, 2) }},
		{"illegal-physical-overlap", func(b []byte) { le.PutUint64(b[4096+50+8:], 260) }},
		{"conflicting-hash-size", func(b []byte) {
			for i := 30; i < 50; i++ {
				b[4096+50+i] = 1
			}
		}},
		{"wrong-boot-alias", func(b []byte) { le.PutUint32(b[120:], 1); copy(b[96:120], b[4096:4096+24]); le.PutUint64(b[104:], 300) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := fixture(record(8, 256, 8, 2, 1), record(4, 320, 4, 0, 2))
			tc.mutate(b)
			m, fs := inputs(t, b)
			if idx, err := Open(context.Background(), m, fs, Limits{}); err == nil || idx != nil {
				t.Fatal("accepted malformed/conflicting layout")
			}
		})
	}
}
func TestUnknownFeaturesAndIncompleteMappingAreGaps(t *testing.T) {
	for _, kind := range []string{"split", "cross-part", "compressed-table", "unknown-flags", "missing-metadata", "shared-metadata"} {
		t.Run(kind, func(t *testing.T) {
			b := fixture(record(8, 256, 8, 2, 1))
			switch kind {
			case "split":
				le.PutUint16(b[42:], 2)
			case "cross-part":
				le.PutUint16(b[4096+24:], 2)
			case "compressed-table":
				b[55] = 6
			case "unknown-flags":
				b[4096+7] = 0x22
			case "missing-metadata":
				le.PutUint32(b[44:], 2)
			case "shared-metadata":
				le.PutUint32(b[4096+26:], 2)
			}
			m, fs := inputs(t, b)
			idx, err := Open(context.Background(), m, fs, Limits{})
			if err != nil || idx == nil {
				t.Fatalf("valid unsupported format rejected: %v", err)
			}
			s := idx.Snapshot()
			if len(s.Gaps) == 0 || s.Complete || s.ConversionSupported || s.ContentVerified {
				t.Fatalf("false closure: %+v", s)
			}
			for _, g := range s.Gaps {
				if g.Classification != "implementation-gap" {
					t.Fatalf("wrong gap classification: %+v", g)
				}
			}
		})
	}
}
func TestSharedAndAmbiguousDuplicateLocations(t *testing.T) {
	for _, different := range []bool{false, true} {
		b := fixture(record(8, 256, 8, 2, 1), record(4, 320, 4, 0, 2), record(4, 320, 4, 0, 2))
		if different {
			le.PutUint64(b[4096+100+8:], 340)
		}
		m, fs := inputs(t, b)
		idx, err := Open(context.Background(), m, fs, Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if len(idx.Lookup(strings.Repeat("02", 20))) != 2 {
			t.Fatal("duplicate witness lost")
		}
		if idx.Snapshot().Complete == different {
			t.Fatalf("ambiguous=%v not distinguished from shared reference", different)
		}
	}
}
func TestSolidRunsResolveLogicalOffsetsAcrossResources(t *testing.T) {
	// Two solid backing resources, two blobs; second blob offset=8+3, hence
	// physical resource 512 and logical offset 3 (never physical file offset 11).
	b := fixture(record(8, 256, 8, 2, 1), record(32, 400, 0x100000000, 16, 0), record(3, 1, 0, 16, 2), record(32, 512, 0x100000000, 16, 0), record(2, 11, 0, 16, 3))
	for _, off := range []int{400, 512} {
		le.PutUint64(b[off:], 8)
		le.PutUint32(b[off+8:], 32768)
		le.PutUint32(b[off+12:], 3)
	}
	m, fs := inputs(t, b)
	idx, err := Open(context.Background(), m, fs, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	w := idx.Lookup(strings.Repeat("03", 20))
	if len(w) != 1 || w[0].Location.PhysicalOffset != 512 || w[0].Location.LogicalOffset != 3 || w[0].LogicalSize != 2 {
		t.Fatalf("solid logical offset became physical: %+v", w)
	}
	for _, kind := range []string{"overflow", "overlap", "crosses-resource", "missing-marker"} {
		t.Run(kind, func(t *testing.T) {
			bad := bytes.Clone(b)
			switch kind {
			case "overflow":
				le.PutUint64(bad[4096+200+8:], math.MaxUint64)
			case "overlap":
				le.PutUint64(bad[4096+200+8:], 2)
			case "crosses-resource":
				le.PutUint64(bad[4096+200+8:], 7)
			case "missing-marker":
				le.PutUint64(bad[4096+50+16:], 0)
				le.PutUint64(bad[4096+150+16:], 0)
			}
			m, fs := inputs(t, bad)
			if _, err := Open(context.Background(), m, fs, Limits{}); err == nil {
				t.Fatal("invalid solid run accepted")
			}
		})
	}
}
func TestIndexCancellationAndLimits(t *testing.T) {
	m, fs := inputs(t, fixture(record(8, 256, 8, 2, 1)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Open(ctx, m, fs, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, err := Open(context.Background(), m, fs, Limits{MaxEntries: 1, MaxXMLBytes: 8}); err == nil {
		t.Fatal("ignored explicit budget")
	}
}

func TestOrdinaryLocationsUseEffectiveCompression(t *testing.T) {
	for _, tc := range []struct {
		name          string
		flags         uint32
		resourceFlags byte
		original      uint64
		compression   uint32
	}{
		{"raw-in-LZMS-container", 0x80002, 2, 8, 0},
		{"LZMS", 0x80002, 6, 16, 3},
		{"LZX", 0x40002, 6, 16, 2},
		{"XPRESS", 0x20002, 6, 16, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := fixture(record(8, 256, tc.original, tc.resourceFlags, 1))
			le.PutUint32(b[16:], tc.flags)
			m, fs := inputs(t, b)
			idx, err := Open(context.Background(), m, fs, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if got := idx.Snapshot().Containers[0].Entries[0].Location.Compression; got != tc.compression {
				t.Fatalf("effective resource compression=%d, want %d", got, tc.compression)
			}
		})
	}
}

func TestXMLDeclarationAndBigEndianRemainDistinct(t *testing.T) {
	for _, bigEndian := range []bool{false, true} {
		b := fixture(record(8, 256, 8, 2, 1))
		x := `<?xml version="1.0" encoding="utf-16"?><WIM><IMAGE INDEX="1"/></WIM>`
		u := utf16.Encode([]rune(x))
		raw := make([]byte, 2+2*len(u))
		if bigEndian {
			binary.BigEndian.PutUint16(raw, 0xfeff)
		} else {
			le.PutUint16(raw, 0xfeff)
		}
		for i, v := range u {
			if bigEndian {
				binary.BigEndian.PutUint16(raw[2+2*i:], v)
			} else {
				le.PutUint16(raw[2+2*i:], v)
			}
		}
		copy(b[6000:], raw)
		resource(b[72:], uint64(len(raw)), 6000, uint64(len(raw)), 2)
		m, fs := inputs(t, b)
		idx, err := Open(context.Background(), m, fs, Limits{})
		if err != nil {
			t.Fatalf("valid XML encoding treated as corruption: %v", err)
		}
		if bigEndian {
			if idx.Snapshot().Complete || len(idx.Snapshot().Gaps) == 0 {
				t.Fatal("big endian capability gap disappeared")
			}
		} else if !idx.Snapshot().Containers[0].MappingComplete {
			t.Fatal("standard UTF16 declaration prevented XML association")
		}
	}
}

// This reader cancels while a table batch is being read; observing cancellation
// only at function entry would incorrectly return a complete index.
type cancelDuringRead struct {
	reader *bytes.Reader
	cancel context.CancelFunc
}

func (r cancelDuringRead) ReadAt(b []byte, off int64) (int, error) {
	n, err := r.reader.ReadAt(b, off)
	if off == 4096 {
		r.cancel()
	}
	return n, err
}
func TestReaderCancellationDuringTableRead(t *testing.T) {
	b := fixture(record(8, 256, 8, 2, 1))
	m, _ := inputs(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, _ := bounded(Limits{})
	if _, _, err := readContainer(ctx, cancelDuringRead{bytes.NewReader(b), cancel}, uint64(len(b)), m.Payloads[0].Identity, l, l.MaxTotalEntries); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel during range read was ignored: %v", err)
	}
}
func TestRetainedHandleRehashRejectsChangedOrReplacedSource(t *testing.T) {
	for _, kind := range []string{"content-change", "path-replacement", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			b := fixture(record(8, 256, 8, 2, 1))
			_, fs := inputs(t, b)
			v, err := openSource(context.Background(), fs[0])
			if err != nil {
				t.Fatal(err)
			}
			defer v.file.Close()
			if _, err := v.rehash(); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "content-change":
				f, err := os.OpenFile(fs[0].Path, os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteAt([]byte{255}, 400)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "path-replacement":
				// Windows denies renaming an os.Open handle without delete
				// sharing. Exercise the path/retained-handle identity boundary
				// deterministically with another file containing identical bytes.
				v.path = fs[0].Path + ".replacement"
				if err := os.WriteFile(v.path, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.Truncate(fs[0].Path, 5000); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := v.rehash(); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("reused changed source handle: %v", err)
			}
		})
	}
}
func TestSolidCrossPartAndAbsentHashStayIncomplete(t *testing.T) {
	for _, kind := range []string{"cross-part", "zero-hash"} {
		t.Run(kind, func(t *testing.T) {
			b := fixture(record(8, 256, 8, 2, 1), record(32, 400, 0x100000000, 16, 0), record(3, 1, 0, 16, 2))
			le.PutUint64(b[400:], 8)
			le.PutUint32(b[408:], 32768)
			le.PutUint32(b[412:], 3)
			if kind == "cross-part" {
				le.PutUint16(b[4096+50+24:], 2)
			} else {
				for i := 30; i < 50; i++ {
					b[4096+100+i] = 0
				}
			}
			m, fs := inputs(t, b)
			idx, err := Open(context.Background(), m, fs, Limits{})
			if err != nil {
				t.Fatalf("valid unresolved descriptor treated as malformed: %v", err)
			}
			if idx.Snapshot().Complete || len(idx.Snapshot().Gaps) == 0 {
				t.Fatal("incomplete identity was advertised as complete index")
			}
		})
	}
}

func TestPipableHeaderPreservesUnresolvedIdentity(t *testing.T) {
	b := fixture(record(8, 256, 8, 2, 1))
	copy(b, "WLPWM\x00\x00\x00")
	for i := 24; i < 40; i++ {
		b[i] = 0x44
	}
	m, fs := inputs(t, b)
	idx, err := Open(context.Background(), m, fs, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	s := idx.Snapshot()
	h := s.Containers[0].Header
	if s.Complete || len(s.Gaps) != 1 || s.Gaps[0].Capability != "pipable-header" || h.Part != 1 || h.TotalParts != 1 || h.GUID != strings.Repeat("44", 16) {
		t.Fatalf("unresolved header identity discarded: %+v", s)
	}
}

func TestCodecChunkDeclarationsRejectImpossibleSizes(t *testing.T) {
	for _, tc := range []struct{ flags, chunk uint32 }{{0x20002, 131072}, {0x40002, 4096}, {0x80002, 16384}} {
		b := fixture(record(8, 256, 8, 2, 1))
		le.PutUint32(b[16:], tc.flags)
		le.PutUint32(b[20:], tc.chunk)
		m, fs := inputs(t, b)
		if _, err := Open(context.Background(), m, fs, Limits{}); err == nil {
			t.Errorf("accepted impossible header chunk=%d flags=%x", tc.chunk, tc.flags)
		}
	}
	for _, tc := range []struct{ compression, chunk uint32 }{{1, 131072}, {2, 4096}, {3, 16384}} {
		b := fixture(record(8, 256, 8, 2, 1), record(32, 400, 0x100000000, 16, 0), record(3, 1, 0, 16, 2))
		le.PutUint64(b[400:], 8)
		le.PutUint32(b[408:], tc.chunk)
		le.PutUint32(b[412:], tc.compression)
		m, fs := inputs(t, b)
		if _, err := Open(context.Background(), m, fs, Limits{}); err == nil {
			t.Errorf("accepted impossible solid chunk=%d compression=%d", tc.chunk, tc.compression)
		}
	}
}
