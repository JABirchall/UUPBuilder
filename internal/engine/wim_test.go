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
	"testing"
)

func inputFixture() writeInput {
	meta := []byte("raw metadata: security EA callback unknown tags names times streams hardlinks reparse\x00")
	data := []byte("original stream")
	resource := func(b []byte, metadata bool) inputResource {
		a, c := sha1.Sum(b), sha256.Sum256(b)
		return inputResource{SHA1: hex.EncodeToString(a[:]), SHA256: hex.EncodeToString(c[:]), Size: uint64(len(b)), References: 1, Metadata: metadata, Reader: bytes.NewReader(b)}
	}
	return writeInput{XML: []byte{0xff, 0xfe, '<', 0, 'W', 0, 'I', 0, 'M', 0, '/', 0, '>', 0}, Resources: []inputResource{resource(meta, true), resource(data, false)}, CheckLive: func() error { return nil }}
}

func TestStandardWIMPreservesRawMetadataAndStreams(t *testing.T) {
	in := inputFixture()
	a, e := writeStandard(context.Background(), in, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	s := a.Receipt()
	if !s.BytesVerified || s.WindowsCompatible || s.NativeFilesystemPreservation || s.Size == 0 {
		t.Fatal(s)
	}
	var header [208]byte
	if _, e = a.ReadAt(header[:], 0); e != nil {
		t.Fatal(e)
	}
	if string(header[:8]) != "MSWIM\x00\x00\x00" || binary.LittleEndian.Uint32(header[12:]) != 0x10d00 || binary.LittleEndian.Uint32(header[44:]) != 1 || binary.LittleEndian.Uint32(header[120:]) != 0 {
		t.Fatal("wrong standard single-install framing")
	}
	for n, r := range s.Resources {
		b := make([]byte, r.Size)
		if _, e = a.ReadAt(b, int64(r.Offset)); e != nil {
			t.Fatal(e)
		}
		want := make([]byte, r.Size)
		in.Resources[n].Reader.ReadAt(want, 0)
		if !bytes.Equal(b, want) {
			t.Fatal("raw source changed")
		}
	}
	a.Close()
	if _, e = a.ReadAt(nil, 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed empty reader usable", e)
	}
}

func TestStandardWIMRejectsBoundsCorruptionAndRevocation(t *testing.T) {
	for _, l := range []Limits{{MaxResources: 1}, {MaxOutputBytes: 1}, {MaxReadBytes: 1}, {MaxResultBytes: 1}, {MaxXMLBytes: 1}, {MaxBufferBytes: 1}} {
		if a, e := writeStandard(context.Background(), inputFixture(), l); e == nil || a != nil {
			t.Fatal("budget bypass", l, e)
		}
	}
	in := inputFixture()
	in.Resources[1].SHA256 = string(bytes.Repeat([]byte{'0'}, 64))
	if a, e := writeStandard(context.Background(), in, Limits{}); !errors.Is(e, ErrIntegrity) || a != nil {
		t.Fatal("wrong source hash", e)
	}
	in = inputFixture()
	in.Resources[0], in.Resources[1] = in.Resources[1], in.Resources[0]
	if a, e := writeStandard(context.Background(), in, Limits{}); e == nil || a != nil {
		t.Fatal("metadata order guessed")
	}
	in = inputFixture()
	in.CheckLive = func() error { return os.ErrClosed }
	if a, e := writeStandard(context.Background(), in, Limits{}); !errors.Is(e, os.ErrClosed) || a != nil {
		t.Fatal("closed parent", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a, e := writeStandard(ctx, inputFixture(), Limits{}); e != context.Canceled || a != nil {
		t.Fatal("cancellation", e)
	}
}

// The independent verifier must reject a changed table, payload, or header,
// even if the writer's own bookkeeping still describes the expected image.
func TestIndependentWIMVerificationRejectsChangedOutput(t *testing.T) {
	in := inputFixture()
	a, e := writeStandard(context.Background(), in, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	s := a.Receipt()
	b := make([]byte, s.Size)
	if _, e = a.ReadAt(b, 0); e != nil {
		t.Fatal(e)
	}
	for _, off := range []int{12, 208, int(s.LookupOffset) + 26, int(s.XMLOffset)} {
		changed := bytes.Clone(b)
		changed[off] ^= 1
		if _, e = verifyStandard(context.Background(), bytes.NewReader(changed), s.Size, in, Limits{}); e == nil {
			t.Fatal("changed output accepted", off)
		}
	}
}

func TestIndependentWIMBootVerificationRejectsDescriptorAndIndexChanges(t *testing.T) {
	in := inputFixture()
	in.Boot = true
	a, e := writeStandard(context.Background(), in, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	s := a.Receipt()
	raw := make([]byte, s.Size)
	if _, e = a.ReadAt(raw, 0); e != nil {
		t.Fatal(e)
	}
	for _, off := range []int{96, 103, 104, 112, 120, 124} {
		changed := bytes.Clone(raw)
		changed[off] ^= 1
		if _, e = verifyStandard(context.Background(), bytes.NewReader(changed), s.Size, in, Limits{}); e == nil {
			t.Fatal("changed boot descriptor/index accepted", off)
		}
	}
}

var _ io.ReaderAt = (*Artifact)(nil)

func TestZeroArtifactIsNotReadableAndCanClose(t *testing.T) {
	a := &Artifact{}
	if _, e := a.ReadAt(nil, 0); !errors.Is(e, ErrInput) {
		t.Fatal("zero artifact readable", e)
	}
	if e := a.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestStandardWIMReadBudgetExactAndExhaustedRemainder(t *testing.T) {
	in := inputFixture()
	for n, data := range [][]byte{[]byte("m"), []byte("dd")} {
		a, b := sha1.Sum(data), sha256.Sum256(data)
		in.Resources[n].Reader = bytes.NewReader(data)
		in.Resources[n].Size = uint64(len(data))
		in.Resources[n].SHA1 = hex.EncodeToString(a[:])
		in.Resources[n].SHA256 = hex.EncodeToString(b[:])
	}
	// 208 header + 3 content + 100 table + 14 XML = 325 output bytes.
	// Two original reads and three complete output reads total 981 bytes.
	a, e := writeStandard(context.Background(), in, Limits{MaxReadBytes: 981})
	if e != nil {
		t.Fatal(e)
	}
	if a.Receipt().Size != 325 || a.Receipt().ReadBytes != 981 {
		t.Fatal(a.Receipt())
	}
	a.Close()
	if a, e = writeStandard(context.Background(), in, Limits{MaxReadBytes: 980}); a != nil || !errors.Is(e, ErrLimit) {
		t.Fatal("exhausted read remainder selected defaults", e)
	}
	b := &readBudget{limit: 1}
	if e = b.charge(1); e != nil {
		t.Fatal(e)
	}
	if e = b.charge(1); !errors.Is(e, ErrLimit) {
		t.Fatal("exhausted internal remainder", e)
	}
}

type changingReader struct {
	data   []byte
	calls  int
	cancel context.CancelFunc
}

func (r *changingReader) ReadAt(b []byte, off int64) (int, error) {
	r.calls++
	data := bytes.Clone(r.data)
	if r.calls > 1 {
		data[0] ^= 1
	}
	if r.cancel != nil {
		r.cancel()
	}
	return bytes.NewReader(data).ReadAt(b, off)
}
func TestStandardWIMRefusesSourceChangeAndCancellationAfterMutationStarts(t *testing.T) {
	in := inputFixture()
	in.Resources[1].Reader = &changingReader{data: []byte("original stream")}
	if a, e := writeStandard(context.Background(), in, Limits{}); a != nil || !errors.Is(e, ErrIntegrity) {
		t.Fatal("changed source published", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in = inputFixture()
	in.Resources[1].Reader = &changingReader{data: []byte("original stream"), cancel: cancel}
	if a, e := writeStandard(ctx, in, Limits{}); a != nil || !errors.Is(e, context.Canceled) {
		t.Fatal("canceled partial output published", e)
	}
}
