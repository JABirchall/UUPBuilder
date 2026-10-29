package wimcontent

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"uupbuilder/internal/metadata/wimindex"
)

func TestBoundFingerprintMismatchReturnsIntegrityError(t *testing.T) {
	r, _, _, o, c := referenceFixture(t)
	r.catalog.state.Witnesses[1].SHA256 = "contradictory test-only stored fingerprint"
	if v, e := BindReferences(context.Background(), r, o, c, Limits{}); v != nil || e == nil {
		t.Fatal("mismatched witness returned no integrity error", e)
	}
}
func TestCombinedChunkPairIsBoundDuringFraming(t *testing.T) {
	b := make([]byte, 28+32768+1+1)
	le.PutUint64(b, 65537)
	le.PutUint32(b[8:], 32768)
	le.PutUint32(b[12:], 3)
	le.PutUint32(b[16:], 32768)
	le.PutUint32(b[20:], 1)
	le.PutUint32(b[24:], 1)
	e := wimindex.Entry{Kind: "solid-resource", LogicalSize: 65537, Descriptor: wimindex.Descriptor{Size: uint64(len(b)), Flags: 16}, Location: wimindex.Location{ResourceLogicalSize: 65537, ChunkSize: 32768, Compression: 3}}
	l, _ := bounds(Limits{MaxBufferBytes: 32769})
	if _, er := inspect(context.Background(), bytes.NewReader(b), uint64(len(b)), e, l); er == nil {
		t.Fatal("separately valid chunks hid an oversized reusable pair")
	}
}
func TestTotalChunkBudgetIncludesRawOrdinaryResources(t *testing.T) {
	m, fs, idx, _ := fixture(t, nil)
	called := false
	r, e := decode(context.Background(), m, fs, idx, Limits{MaxTotalChunks: 2}, func(context.Context, Limits) (codec, error) { called = true; return &syntheticCodec{}, nil })
	if r != nil {
		r.Close()
	}
	if !errors.Is(e, ErrLimit) || called {
		t.Fatal("two solid chunks plus one raw resource bypassed aggregate chunk budget", e, called)
	}
}
func TestExhaustedPrivateFramingAndReadBudgetsNeverSelectDefaults(t *testing.T) {
	l, _ := bounds(Limits{})
	l.MaxResultBytes = 0
	b := make([]byte, 21)
	le.PutUint64(b, 1)
	le.PutUint32(b[8:], 32768)
	le.PutUint32(b[12:], 3)
	le.PutUint32(b[16:], 1)
	e := wimindex.Entry{Kind: "solid-resource", LogicalSize: 1, Descriptor: wimindex.Descriptor{Size: 21, Flags: 16}, Location: wimindex.Location{ResourceLogicalSize: 1, ChunkSize: 32768, Compression: 3}}
	if _, er := inspect(context.Background(), bytes.NewReader(b), 21, e, l); !errors.Is(er, ErrLimit) {
		t.Fatal("zero framing allowance became default", er)
	}
	budget := &readBudget{limit: 1, used: 1}
	if _, _, er := hashInterval(context.Background(), bytes.NewReader([]byte("x")), 0, 1, budget); !errors.Is(er, ErrLimit) {
		t.Fatal("zero read remainder became default", er)
	}
}
