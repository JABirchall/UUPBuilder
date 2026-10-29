package cabformat

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func fixture(name string, data []byte) []byte {
	block := 61 + len(name)
	b := make([]byte, block+8+len(data))
	copy(b, "MSCF")
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[16:], 44)
	b[24] = 3
	b[25] = 1
	binary.LittleEndian.PutUint16(b[26:], 1)
	binary.LittleEndian.PutUint16(b[28:], 1)
	binary.LittleEndian.PutUint32(b[36:], uint32(block))
	binary.LittleEndian.PutUint16(b[40:], 1)
	binary.LittleEndian.PutUint32(b[44:], uint32(len(data)))
	copy(b[60:], name)
	binary.LittleEndian.PutUint16(b[block+4:], uint16(len(data)))
	binary.LittleEndian.PutUint16(b[block+6:], uint16(len(data)))
	copy(b[block+8:], data)
	return b
}
func TestDirectoryValidatesBeforeOutputAndHonorsReadBudget(t *testing.T) {
	b := fixture(`component\member.dll`, []byte("exact"))
	v, e := Inspect(context.Background(), bytes.NewReader(b), uint64(len(b)), Limits{})
	if e != nil || len(v.Members) != 1 || v.Members[0].Name != `component\member.dll` || v.Members[0].Size != 5 || v.DecodedBytes != 5 {
		t.Fatalf("valid bounded directory rejected: %+v %v", v, e)
	}
	for _, l := range []Limits{{MaxSourceBytes: 1}, {MaxMemberBytes: 4}, {MaxDecodedBytes: 4}, {MaxMetadataBytes: 1}, {MaxNameBytes: 2}} {
		if _, e := Inspect(context.Background(), bytes.NewReader(b), uint64(len(b)), l); !errors.Is(e, ErrLimit) {
			t.Fatalf("lower bound bypassed: %+v %v", l, e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Inspect(ctx, panicReader{}, uint64(len(b)), Limits{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

type panicReader struct{}

func (panicReader) ReadAt([]byte, int64) (int, error) { panic("read before limit/cancellation") }
func TestDirectoryRejectsUnsafeAndMalformedTables(t *testing.T) {
	for _, name := range []string{`..\x`, `C:x`, `/x`, `x\NUL.txt`, `x.`, `x\..\z`, `x?`, `x\CONIN$`} {
		b := fixture(name, []byte("x"))
		if _, e := Inspect(context.Background(), bytes.NewReader(b), uint64(len(b)), Limits{}); e == nil {
			t.Fatalf("unsafe name %q", name)
		}
	}
	for _, change := range []func([]byte){func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 0xffffffff) }, func(b []byte) { binary.LittleEndian.PutUint32(b[36:], 10) }, func(b []byte) { binary.LittleEndian.PutUint16(b[52:], 0xffff) }, func(b []byte) { binary.LittleEndian.PutUint32(b[48:], 99) }, func(b []byte) { binary.LittleEndian.PutUint16(b[28:], 0xffff) }, func(b []byte) { b[30] = 2 }, func(b []byte) { b[24] = 2 }} {
		b := fixture("a", []byte("x"))
		change(b)
		if _, e := Inspect(context.Background(), bytes.NewReader(b), uint64(len(b)), Limits{}); e == nil {
			t.Fatal("malformed directory accepted")
		}
	}
	if _, e := Inspect(context.Background(), panicReader{}, 1<<31, Limits{}); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
}

func TestDirectoryReservesCallerMemoryBeforeDirectoryAllocation(t *testing.T) {
	b := fixture("a", []byte("x"))
	r := &countReader{Reader: bytes.NewReader(b)}
	if _, e := Inspect(context.Background(), r, uint64(len(b)), Limits{MaxDirectoryBytes: 1}); !errors.Is(e, ErrLimit) {
		t.Fatal("directory allocation lower limit bypassed", e)
	}
	if r.calls != 1 {
		t.Fatal("directory accessed before its allocation reservation", r.calls)
	}
}

type countReader struct {
	*bytes.Reader
	calls int
}

func (r *countReader) ReadAt(b []byte, o int64) (int, error) { r.calls++; return r.Reader.ReadAt(b, o) }

func TestReferenceNameCeilingRemainsAnExplicitLimit(t *testing.T) {
	b := fixture(strings.Repeat("a", 256), []byte("x"))
	if _, e := Inspect(context.Background(), bytes.NewReader(b), uint64(len(b)), Limits{}); !errors.Is(e, ErrLimit) {
		t.Fatalf("valid-format name beyond supported bound was called malformed: %v", e)
	}
}
