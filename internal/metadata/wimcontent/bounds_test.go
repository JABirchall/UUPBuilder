package wimcontent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"uupbuilder/internal/metadata/wimindex"
)

func TestLowerBudgetsAndRawInputStringsRefuseBeforeProviderOrLargeCopy(t *testing.T) {
	for _, l := range []Limits{{MaxEntries: 1}, {MaxResources: 1}, {MaxChunks: 1}, {MaxTotalChunks: 1}, {MaxSourceBytes: 1}, {MaxTotalSourceBytes: 1}, {MaxOutputBytes: 32780}, {MaxReadBytes: 1}, {MaxResultBytes: 1}, {MaxChunkBytes: 65536, MaxBufferBytes: 32768}} {
		m, fs, idx, _ := fixture(t, nil)
		called := false
		r, e := decode(context.Background(), m, fs, idx, l, func(context.Context, Limits) (codec, error) { called = true; return &syntheticCodec{}, nil })
		if r != nil {
			r.Close()
		}
		if e == nil || called || r != nil {
			t.Fatalf("budget reached native or published %+v %v", l, e)
		}
	}
	m, fs, idx, _ := fixture(t, nil)
	fs[0].Identity.Provenance.Name = strings.Repeat("UNBOUND", 1<<20)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	r, e := Decode(context.Background(), m, fs, idx, Limits{})
	runtime.ReadMemStats(&after)
	if r != nil || !errors.Is(e, ErrLimit) || after.TotalAlloc-before.TotalAlloc > 1<<20 {
		t.Fatal("unbounded input normalized before refusal", e, after.TotalAlloc-before.TotalAlloc)
	}
}
func TestSourceBindingCancellationAndChangedSourceDiscardOwnedBatch(t *testing.T) {
	m, fs, idx, _ := fixture(t, nil)
	if r, e := Decode(context.Background(), m, fs, &wimindex.Index{}, Limits{}); e == nil || r != nil {
		t.Fatal("forged index")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, e := Decode(ctx, m, fs, idx, Limits{}); r != nil || !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	for _, mode := range []string{"cancel-native", "change-source", "caller-slices"} {
		t.Run(mode, func(t *testing.T) {
			m, fs, idx, _ := fixture(t, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := fs[0].Identity
			c := &syntheticCodec{}
			c.mutate = func() {
				switch mode {
				case "cancel-native":
					cancel()
				case "change-source":
					b, _ := os.ReadFile(fs[0].Path)
					b[len(b)-1] ^= 1
					if e := os.WriteFile(fs[0].Path, b, 0600); e != nil {
						t.Fatal(e)
					}
				case "caller-slices":
					m.Payloads[0].Identity.Size = 1
					fs[0].Identity.Size = 1
				}
			}
			r, e := decode(ctx, m, fs, idx, Limits{}, func(context.Context, Limits) (codec, error) { return c, nil })
			if mode == "caller-slices" {
				if e != nil {
					t.Fatal(e)
				}
				defer r.Close()
				if r.catalog.state.Sources[0].Payload != original {
					t.Fatal("caller alias")
				}
			} else {
				if r != nil {
					r.Close()
				}
				if e == nil || r != nil {
					t.Fatal("changed/canceled source published")
				}
			}
		})
	}
}
func TestEveryOriginalDigestAndContradictoryFingerprintGatePublication(t *testing.T) {
	m, fs, idx, _ := fixture(t, func(b []byte) { b[4096+50+30] ^= 1 })
	r, e := decode(context.Background(), m, fs, idx, Limits{}, func(context.Context, Limits) (codec, error) { return &syntheticCodec{}, nil })
	if r != nil {
		r.Close()
	}
	if !errors.Is(e, ErrIntegrity) || r != nil {
		t.Fatal("wrong original blob SHA1 published", e)
	}
	for _, f := range []fingerprint{{size: 2, sha256: "different"}, {size: 1, sha256: "same"}} {
		seen := map[string]fingerprint{"original": {size: 2, sha256: "same"}}
		if e := recordFingerprint(seen, "original", f); !errors.Is(e, ErrConflict) {
			t.Fatal("SHA1 collision contradiction chose provenance", e)
		}
	}
	m, fs, idx, _ = fixture(t, func(b []byte) { copy(b[8216:], []byte("Ytail!")) })
	r, e = decode(context.Background(), m, fs, idx, Limits{}, func(context.Context, Limits) (codec, error) { return &syntheticCodec{}, nil })
	if r != nil {
		r.Close()
	}
	if e == nil {
		t.Fatal("corrupt compressed block published")
	}
}
func TestRawSolidPartialChunksAndTruncatedDeclarations(t *testing.T) {
	data := append(bytes.Repeat([]byte("A"), 32768), []byte("tail!")...)
	b := make([]byte, 24)
	le.PutUint64(b, 32773)
	le.PutUint32(b[8:], 32768)
	le.PutUint32(b[12:], 0)
	le.PutUint32(b[16:], 32768)
	le.PutUint32(b[20:], 5)
	b = append(b, data...)
	e := wimindex.Entry{Kind: "solid-resource", LogicalSize: 32773, Descriptor: wimindex.Descriptor{Size: uint64(len(b)), Flags: 16}, Location: wimindex.Location{ResourceLogicalSize: 32773, PhysicalSize: uint64(len(b)), ChunkSize: 32768}}
	l, _ := bounds(Limits{})
	if p, er := inspect(context.Background(), bytes.NewReader(b), uint64(len(b)), e, l); er != nil || p.chunks[1].size != 5 {
		t.Fatal(p, er)
	}
	if _, er := inspect(context.Background(), bytes.NewReader(b[:20]), 20, e, l); er == nil {
		t.Fatal("truncated alternate data")
	}
}
