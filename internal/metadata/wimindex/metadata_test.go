package wimindex

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// Synthetic codec port: only framing, source binding and verification are tested.
// The independently known logical bytes are 32768 'A' bytes followed by "tail!".
type syntheticCodec struct {
	mode   string
	calls  int
	mutate func()
}

func (c *syntheticCodec) Identity() CodecIdentity { return CodecIdentity{Name: "synthetic-test-only"} }
func (c *syntheticCodec) Close() error            { return nil }
func (c *syntheticCodec) Decode(ctx context.Context, b []byte, n int) ([]byte, error) {
	c.calls++
	if c.mutate != nil {
		c.mutate()
	}
	if c.mode == "error" {
		return nil, errors.New("synthetic codec failure")
	}
	if c.mode == "noop" {
		return b, nil
	}
	if !bytes.Equal(b, []byte{'Z'}) || n != 32768 {
		return nil, errors.New("unexpected synthetic chunk")
	}
	v := bytes.Repeat([]byte{'A'}, 32768)
	if c.mode == "wrong" {
		v[0] = 'B'
	}
	return v, nil
}
func metadataInputs(t *testing.T, mutate func([]byte)) (model.PayloadManifest, []metadata.LocalResource, *Index, []byte) {
	t.Helper()
	want := append(bytes.Repeat([]byte{'A'}, 32768), []byte("tail!")...)
	h := sha1.Sum(want)
	r := record(10, 8192, 32773, 6, 0)
	copy(r[30:], h[:])
	b := fixture(r)
	b = append(b, 1, 0, 0, 0, 'Z', 't', 'a', 'i', 'l', '!')
	if mutate != nil {
		mutate(b)
	}
	m, fs := inputs(t, b)
	idx, err := Open(context.Background(), m, fs, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return m, fs, idx, want
}
func runSynthetic(ctx context.Context, m model.PayloadManifest, fs []metadata.LocalResource, idx *Index, l DecodeLimits, c *syntheticCodec) ([]*MetadataArtifact, error) {
	return decodeMetadata(ctx, m, fs, idx, l, func(context.Context) (metadataCodec, error) { return c, nil })
}
func TestStandardMetadataVerifiedBoundaryAndLifecycle(t *testing.T) {
	m, fs, idx, want := metadataInputs(t, nil)
	c := &syntheticCodec{}
	artifacts, err := runSynthetic(context.Background(), m, fs, idx, DecodeLimits{}, c)
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("verified metadata missing: %v", err)
	}
	a := artifacts[0]
	got, err := io.ReadAll(io.NewSectionReader(a, 0, int64(a.Receipt().Size)))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("decoded bytes differ", err)
	}
	r := a.Receipt()
	h := sha1.Sum(want)
	if r.SHA1 != hex.EncodeToString(h[:]) || r.Size != 32773 || r.IndexDigest != idx.Digest() || r.SourceSHA256 != fs[0].Identity.Digest.Value || !r.SourceRehashed || c.calls != 1 {
		t.Fatalf("incomplete verified identity: %+v", r)
	}
	r.Entry.Descriptor.Offset = 0
	r.Payload.Provenance.Name = "changed"
	fs[0].Identity.Size = 1
	m.Payloads[0].Identity.Size = 1
	if a.Receipt().Entry.Descriptor.Offset != 8192 || a.Receipt().Payload.Provenance.Name != "a.esd" {
		t.Fatal("receipt aliases caller memory")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("closed artifact remains readable")
	}
}
func TestStandardMetadataRejectsMalformedTableBeforeCodec(t *testing.T) {
	for _, v := range []uint32{0, 6, 7, 0xffffffff} {
		t.Run(hex.EncodeToString([]byte{byte(v)}), func(t *testing.T) {
			m, fs, idx, _ := metadataInputs(t, func(b []byte) { le.PutUint32(b[8192:], v) })
			c := &syntheticCodec{}
			a, err := runSynthetic(context.Background(), m, fs, idx, DecodeLimits{}, c)
			if err == nil || a != nil || c.calls != 0 {
				t.Fatalf("malformed offset authorized decode: %v calls=%d", err, c.calls)
			}
		})
	}
}
func TestCodecSuccessCannotPublishWrongHashOrSize(t *testing.T) {
	for _, mode := range []string{"wrong", "noop", "error"} {
		t.Run(mode, func(t *testing.T) {
			m, fs, idx, _ := metadataInputs(t, nil)
			a, err := runSynthetic(context.Background(), m, fs, idx, DecodeLimits{}, &syntheticCodec{mode: mode})
			if err == nil || a != nil {
				t.Fatal("unverified codec bytes published")
			}
		})
	}
}
func TestMetadataRejectsChangedAuthorityAndSource(t *testing.T) {
	for _, kind := range []string{"manifest", "payload", "source", "during-decode", "index", "entry", "missing"} {
		t.Run(kind, func(t *testing.T) {
			m, fs, idx, _ := metadataInputs(t, nil)
			c := &syntheticCodec{}
			switch kind {
			case "manifest":
				m.Source.BuildLabel = "other"
			case "payload":
				fs[0].Identity.Provenance.Name = "other"
			case "source":
				f, _ := os.OpenFile(fs[0].Path, os.O_WRONLY, 0)
				if f == nil {
					t.Fatal("open mutation")
				}
				f.WriteAt([]byte{'X'}, 7000)
				f.Close()
			case "during-decode":
				c.mutate = func() {
					f, e := os.OpenFile(fs[0].Path, os.O_WRONLY, 0)
					if e != nil {
						t.Fatal(e)
					}
					f.WriteAt([]byte{'X'}, 7000)
					f.Close()
				}
			case "index":
				idx = &Index{state: idx.Snapshot(), digest: idx.Digest()}
				idx.state.Source.BuildLabel = "other"
			case "entry":
				idx.state.Containers[0].Entries[0].Descriptor.Offset = 7000
			case "missing":
				fs = nil
			}
			a, err := runSynthetic(context.Background(), m, fs, idx, DecodeLimits{}, c)
			if err == nil || a != nil {
				t.Fatalf("accepted %s mutation", kind)
			}
		})
	}
}
func TestMetadataLimitsAndCancellationPreventCodec(t *testing.T) {
	for _, kind := range []string{"cancel", "resource", "total", "chunks", "read", "chunk", "memory", "negative"} {
		t.Run(kind, func(t *testing.T) {
			m, fs, idx, _ := metadataInputs(t, nil)
			c := &syntheticCodec{}
			l := DecodeLimits{}
			ctx := context.Background()
			switch kind {
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "resource":
				l.MaxResourceBytes = 32772
			case "total":
				l.MaxTotalBytes = 32772
			case "chunks":
				l.MaxChunks = 1
			case "read":
				l.MaxReadBytes = 9
			case "chunk":
				l.MaxChunkBytes = 32767
			case "memory":
				l.MaxBufferBytes = 32768
			case "negative":
				l.MaxResources = -1
			}
			a, err := runSynthetic(ctx, m, fs, idx, l, c)
			if err == nil || a != nil || c.calls != 0 {
				t.Fatalf("limit/cancel did not gate codec: %v", err)
			}
			if kind == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}

// Literal geometry expectations cover the original format's 4 GiB width
// boundary, arithmetic overflow, no-table single chunks and impossible tables.
func TestStandardShapeWidthCountAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		logical, physical, chunk uint64
		want                     standardTable
		bad                      bool
	}{
		{1, 1, 32768, standardTable{1, 4, 0, 1}, false},
		{65537, 13, 32768, standardTable{3, 4, 8, 5}, false},
		{0xffffffff, 32765, 1 << 20, standardTable{4096, 4, 16380, 16385}, false},
		{0x100000000, 32761, 1 << 20, standardTable{4096, 8, 32760, 1}, false},
		{math.MaxUint64, math.MaxUint64, 1, standardTable{}, true},
		{65537, 8, 32768, standardTable{}, true},
		{0, 1, 32768, standardTable{}, true},
		{4, 4, 3, standardTable{}, true},
	} {
		got, err := standardShape(tc.logical, tc.physical, tc.chunk)
		if (err != nil) != tc.bad || (!tc.bad && got != tc.want) {
			t.Fatalf("logical=%d physical=%d got=%+v err=%v", tc.logical, tc.physical, got, err)
		}
	}
	// A 64-bit offset must not be truncated to a plausible 32-bit range.
	p := standardTable{count: 2, width: 8, bytes: 8, data: 0x100000002}
	b := []byte{1, 0, 0, 0, 1, 0, 0, 0}
	off, err := p.offset(context.Background(), bytes.NewReader(b), 8, 0, 1)
	if err != nil || off != 0x100000001 {
		t.Fatalf("64-bit offset truncated: %x %v", off, err)
	}
}
func TestMetadataStoredChunksAndRawResource(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw-resource", true: "stored-standard-chunks"}[compressed], func(t *testing.T) {
			want := append(bytes.Repeat([]byte{'R'}, 32768), []byte("last")...)
			h := sha1.Sum(want)
			flags := byte(2)
			data := want
			if compressed {
				flags = 6
				data = append([]byte{0, 128, 0, 0}, want...)
			}
			r := record(uint64(len(data)), 8192, uint64(len(want)), flags, 0)
			copy(r[30:], h[:])
			m, fs := inputs(t, append(fixture(r), data...))
			idx, err := Open(context.Background(), m, fs, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			c := &syntheticCodec{mode: "error"}
			a, err := runSynthetic(context.Background(), m, fs, idx, DecodeLimits{}, c)
			if err != nil || len(a) != 1 {
				t.Fatal("stored data rejected", err)
			}
			defer a[0].Close()
			got, err := io.ReadAll(io.NewSectionReader(a[0], 0, int64(len(want))))
			if err != nil || !bytes.Equal(got, want) || c.calls != 0 {
				t.Fatal("stored chunks incorrectly entered codec", err)
			}
		})
	}
}
func TestWrongOriginalHashAndSizeCannotPublish(t *testing.T) {
	for _, kind := range []string{"hash", "size", "cancel-during-codec"} {
		t.Run(kind, func(t *testing.T) {
			m, fs, idx, _ := metadataInputs(t, func(b []byte) {
				if kind == "hash" {
					b[4096+30] ^= 0xff
				}
				if kind == "size" {
					le.PutUint64(b[4096+16:], 32774)
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := &syntheticCodec{}
			if kind == "cancel-during-codec" {
				c.mutate = cancel
			}
			a, err := runSynthetic(ctx, m, fs, idx, DecodeLimits{}, c)
			if err == nil || a != nil {
				t.Fatal("wrong original identity/cancel published")
			}
			if kind == "cancel-during-codec" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}
func TestCallerMutationDuringDecodeCannotChangeFrozenIdentity(t *testing.T) {
	m, fs, idx, _ := metadataInputs(t, nil)
	c := &syntheticCodec{mutate: func() {
		m.Payloads[0].Identity.Size = 1
		fs[0].Identity.Size = 1
		s := idx.Snapshot()
		s.Containers[0].Entries[0].Descriptor.Offset = 7000
	}}
	a, err := runSynthetic(context.Background(), m, fs, idx, DecodeLimits{}, c)
	if err != nil || len(a) != 1 {
		t.Fatal(err)
	}
	defer a[0].Close()
	if a[0].Receipt().Entry.Descriptor.Offset != 8192 || a[0].Receipt().Payload.Size != 8202 {
		t.Fatal("caller mutation escaped freeze")
	}
}

func TestDecodedTemporaryBytesAreReverifiedBeforeReceipt(t *testing.T) {
	for _, kind := range []string{"corrupt", "short", "extra", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "unverified-")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.Write([]byte("abc")); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "corrupt":
				f.WriteAt([]byte{'X'}, 1)
			case "short":
				f.Truncate(2)
			case "extra":
				f.WriteAt([]byte{'x'}, 3)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel" {
				cancel()
			}
			sha, err := verifyDecoded(ctx, f, 3, "a9993e364706816aba3e25717850c26c9cd0d89d")
			if err == nil || sha != "" {
				t.Fatal("unverified temporary bytes accepted")
			}
		})
	}
}

func TestMetadataFailureRemovesEarlierAndCurrentPrivateOutputs(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMP", root)
	t.Setenv("TEMP", root)
	want := append(bytes.Repeat([]byte{'A'}, 32768), []byte("tail!")...)
	h := sha1.Sum(want)
	r1 := record(10, 8192, 32773, 6, 0)
	copy(r1[30:], h[:])
	// A second raw metadata resource is structurally valid but has the wrong
	// original content hash. The first pending artifact must also be removed.
	r2 := record(1, 8202, 1, 2, 1)
	b := append(fixture(r1, r2), 1, 0, 0, 0, 'Z', 't', 'a', 'i', 'l', '!', 'x')
	m, fs := inputs(t, b)
	idx, err := Open(context.Background(), m, fs, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := runSynthetic(context.Background(), m, fs, idx, DecodeLimits{}, &syntheticCodec{})
	if err == nil || a != nil {
		t.Fatal("partial verified batch published")
	}
	leaks, err := filepath.Glob(filepath.Join(root, "uup-metadata-unverified-*"))
	if err != nil || len(leaks) != 0 {
		t.Fatal("failed decode leaked private output", leaks, err)
	}
}

func TestUnsupportedCodecAndOversizedStandardChunkRemainGaps(t *testing.T) {
	for _, kind := range []string{"xpress", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			m, fs, idx, _ := metadataInputs(t, func(b []byte) {
				if kind == "xpress" {
					le.PutUint32(b[16:], 0x20002)
				} else {
					le.PutUint32(b[20:], 2<<20)
				}
			})
			c := &syntheticCodec{}
			a, err := runSynthetic(context.Background(), m, fs, idx, DecodeLimits{}, c)
			if err == nil || a != nil || c.calls != 0 {
				t.Fatal("unsupported format reached codec")
			}
			if kind == "xpress" && !errors.Is(err, ErrUnsupported) {
				t.Fatal("codec implementation gap misclassified", err)
			}
			if kind == "oversized" && !errors.Is(err, ErrLimit) {
				t.Fatal("chunk ceiling not retained", err)
			}
		})
	}
}

type tableReads struct {
	io.ReaderAt
	calls int
}

func (r *tableReads) ReadAt(b []byte, off int64) (int, error) {
	r.calls++
	return r.ReaderAt.ReadAt(b, off)
}
func TestStandardPreflightRejectsDecreasingOffsetsAndCountsBeforeRead(t *testing.T) {
	l, err := decodeBounds(DecodeLimits{})
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{LogicalSize: 65537, Descriptor: Descriptor{Offset: 0, Size: 13}, Location: Location{ChunkSize: 32768}}
	for _, offsets := range [][]byte{{3, 0, 0, 0, 2, 0, 0, 0}, {2, 0, 0, 0, 2, 0, 0, 0}, {2, 0, 0, 0, 6, 0, 0, 0}} {
		r := &tableReads{ReaderAt: bytes.NewReader(offsets)}
		if _, err := validateStandard(context.Background(), r, 13, e, l); !errors.Is(err, ErrLayout) {
			t.Fatal("bad offsets accepted", err)
		}
	}
	l.MaxChunks = 2
	r := &tableReads{ReaderAt: bytes.NewReader(nil)}
	if _, err := validateStandard(context.Background(), r, 13, e, l); !errors.Is(err, ErrLimit) || r.calls != 0 {
		t.Fatal("chunk count consumed table before limit", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l.MaxChunks = 3
	if _, err := validateStandard(ctx, r, 13, e, l); !errors.Is(err, context.Canceled) || r.calls != 0 {
		t.Fatal("cancel consumed table", err)
	}
}
