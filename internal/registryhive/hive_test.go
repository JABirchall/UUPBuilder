package registryhive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// Synthetic REGF with a root, one compressed-name child, one inline DWORD and
// one external REG_SZ. These bytes do not represent a serviced Windows image.
func sampleHive() []byte {
	b := make([]byte, 8192)
	copy(b, "regf")
	put := func(at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	put(4, 1)
	put(8, 1)
	put(20, 1)
	put(24, 5)
	put(32, 1)
	put(36, 32)
	put(40, 4096)
	put(44, 1)
	copy(b[4096:], "hbin")
	put(4104, 4096)
	cell := func(off, size int) []byte { put(4096+off, uint32(int32(-size))); return b[4100+off : 4096+off+size] }
	root := cell(32, 88)
	copy(root, "nk")
	root[2] = 0x24
	binary.LittleEndian.PutUint32(root[20:], 1)
	binary.LittleEndian.PutUint32(root[28:], 120)
	list := cell(120, 16)
	copy(list, "li")
	list[2] = 1
	binary.LittleEndian.PutUint32(list[4:], 136)
	key := cell(136, 88)
	copy(key, "nk")
	key[2] = 0x20
	key[72] = 4
	copy(key[76:], "Test")
	binary.LittleEndian.PutUint32(key[36:], 2)
	binary.LittleEndian.PutUint32(key[40:], 224)
	values := cell(224, 16)
	binary.LittleEndian.PutUint32(values, 240)
	binary.LittleEndian.PutUint32(values[4:], 272)
	v := cell(240, 32)
	copy(v, "vk")
	v[2] = 1
	binary.LittleEndian.PutUint32(v[4:], 0x80000004)
	v[8] = 42
	v[12] = 4
	v[16] = 1
	v[20] = 'D'
	v = cell(272, 32)
	copy(v, "vk")
	v[2] = 1
	v[4] = 6
	binary.LittleEndian.PutUint32(v[8:], 304)
	v[12] = 1
	v[16] = 1
	v[20] = 'S'
	d := cell(304, 16)
	copy(d, []byte{'h', 0, 'i', 0, 0, 0})
	put(4096+320, 4096-320)
	fixChecksum(b)
	return b
}

func fixChecksum(b []byte) {
	var c uint32
	for i := 0; i < 508; i += 4 {
		c ^= binary.LittleEndian.Uint32(b[i:])
	}
	if c == 0 {
		c = 1
	}
	if c == 0xffffffff {
		c = 0xfffffffe
	}
	binary.LittleEndian.PutUint32(b[508:], c)
}

func TestHiveReadsSelectedTypedValues(t *testing.T) {
	b := sampleHive()
	h, err := Open(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	v, err := h.Value("test", "s")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v.String(); err != nil || got != "hi" {
		t.Fatalf("string %q: %v", got, err)
	}
	v, err = h.Value("Test", "D")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v.DWORD(); err != nil || got != 42 {
		t.Fatalf("DWORD %d: %v", got, err)
	}
	if _, err := v.String(); err == nil {
		t.Fatal("DWORD accepted as string")
	}
	if _, err := h.Value("Missing", "D"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing key: %v", err)
	}
}

func TestHiveRejectsDirtyCorruptAndUnsupportedInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"dirty", func(b []byte) { b[8] = 2; fixChecksum(b) }},
		{"checksum", func(b []byte) { b[508] ^= 1 }},
		{"format", func(b []byte) { b[24] = 9; fixChecksum(b) }},
		{"bin-offset", func(b []byte) { b[4100] = 1 }},
		{"cell-zero", func(b []byte) { clear(b[4128:4132]) }},
		{"cell-overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[4128:], 0x80000000) }},
		{"root-outside", func(b []byte) { binary.LittleEndian.PutUint32(b[36:], 4090); fixChecksum(b) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := sampleHive()
			tc.mutate(b)
			if _, err := Open(bytes.NewReader(b), int64(len(b))); err == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
	if _, err := Open(bytes.NewReader(nil), 129<<20); err == nil {
		t.Fatal("oversized input accepted")
	}
}

func TestHiveRejectsCyclesAmbiguityAndMalformedValues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"list-cycle", func(b []byte) { copy(b[4220:], "ri"); binary.LittleEndian.PutUint32(b[4224:], 120) }},
		{"key-cycle", func(b []byte) { b[4204] = 4; copy(b[4208:], "Test"); binary.LittleEndian.PutUint32(b[4224:], 32) }},
		{"key-count", func(b []byte) { binary.LittleEndian.PutUint32(b[4152:], 2) }},
		{"duplicate-value", func(b []byte) { b[4392] = 'D' }},
		{"bad-string", func(b []byte) { b[4408] = 'x' }},
		{"bad-inline", func(b []byte) { binary.LittleEndian.PutUint32(b[4344:], 0x80000008) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := sampleHive()
			tc.mutate(b)
			h, err := Open(bytes.NewReader(b), int64(len(b)))
			if err != nil {
				return
			}
			if _, err = h.Values("Test"); err == nil {
				t.Fatal("malformed query accepted")
			}
		})
	}
}
