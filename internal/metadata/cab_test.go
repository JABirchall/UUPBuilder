package metadata

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

// Hand-built uncompressed CAB with one folder, one file and one CFDATA block.
func testCAB(name string, data []byte) []byte {
	table := 44
	block := table + 16 + len(name) + 1
	size := block + 8 + len(data)
	b := make([]byte, size)
	copy(b, "MSCF")
	binary.LittleEndian.PutUint32(b[8:], uint32(size))
	binary.LittleEndian.PutUint32(b[16:], uint32(table))
	b[24] = 3
	b[25] = 1
	binary.LittleEndian.PutUint16(b[26:], 1)
	binary.LittleEndian.PutUint16(b[28:], 1)
	binary.LittleEndian.PutUint32(b[36:], uint32(block))
	binary.LittleEndian.PutUint16(b[40:], 1)
	binary.LittleEndian.PutUint32(b[table:], uint32(len(data)))
	copy(b[table+16:], name)
	binary.LittleEndian.PutUint16(b[block+4:], uint16(len(data)))
	binary.LittleEndian.PutUint16(b[block+6:], uint16(len(data)))
	copy(b[block+8:], data)
	return b
}

func TestCABValidatesAllMembersBeforeSelectedRead(t *testing.T) {
	b := testCAB("metadata.xml", []byte("<safe/>"))
	inv, err := InspectCAB(context.Background(), append(b, 1, 2, 3))
	if err != nil {
		t.Fatal(err)
	}
	if inv.CabinetBytes != len(b) || inv.TrailingBytes != 3 || len(inv.Members) != 1 || inv.Members[0].Size != 7 {
		t.Fatalf("wrong table: %+v", inv)
	}
	for _, name := range []string{"../metadata.xml", "C:metadata.xml", "/metadata.xml", "a\\b.xml", "CON.xml", "bad?.xml"} {
		if _, err := InspectCAB(context.Background(), testCAB(name, []byte("x"))); err == nil {
			t.Fatalf("unsafe name accepted: %q", name)
		}
	}
	for _, mutate := range []func([]byte){func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 0xffffffff) }, func(b []byte) { binary.LittleEndian.PutUint32(b[44:], (16<<20)+1) }, func(b []byte) { binary.LittleEndian.PutUint32(b[48:], 999) }, func(b []byte) { binary.LittleEndian.PutUint16(b[52:], 0xfffd) }, func(b []byte) { binary.LittleEndian.PutUint32(b[36:], 10) }} {
		bad := append([]byte(nil), b...)
		mutate(bad)
		if _, err := InspectCAB(context.Background(), bad); err == nil {
			t.Fatal("corrupt cabinet accepted")
		}
	}
}

func TestCABRejectsCaseCollisionAndAcquisitionMemberBounds(t *testing.T) {
	first := "metadata.xml"
	second := "Metadata.xml"
	b := testCAB(first, []byte("x"))
	oldBlock := int(binary.LittleEndian.Uint32(b[36:]))
	extra := 17 + len(second)
	collision := make([]byte, len(b)+extra)
	copy(collision, b[:oldBlock])
	copy(collision[oldBlock+extra:], b[oldBlock:])
	copy(collision[oldBlock+16:], second)
	binary.LittleEndian.PutUint32(collision[8:], uint32(len(collision)))
	binary.LittleEndian.PutUint16(collision[28:], 2)
	binary.LittleEndian.PutUint32(collision[36:], uint32(oldBlock+extra))
	if _, err := InspectCAB(context.Background(), collision); err == nil {
		t.Fatal("case-colliding CAB members accepted")
	}
	if _, err := InspectCAB(context.Background(), make([]byte, (32<<20)+1)); !errors.Is(err, ErrLimit) {
		t.Fatalf("unbounded compressed metadata: %v", err)
	}
	binary.LittleEndian.PutUint16(b[28:], 1025)
	if _, err := InspectCAB(context.Background(), b); !errors.Is(err, ErrLimit) {
		t.Fatalf("unbounded member directory: %v", err)
	}
}
