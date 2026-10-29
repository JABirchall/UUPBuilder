package cabindex

import (
	"context"
	"errors"
	"os"
	"testing"
	"unsafe"

	"uupbuilder/internal/metadata/cabformat"
)

func TestFDIBorrowsBoundedNativeStackBuffers(t *testing.T) {
	l, _ := bounds(Limits{})
	s := fdiSession{budget: &runBudget{limits: l}, allocations: map[uintptr]uint64{}}
	b := [5]byte{'s', 't', 'a', 'c', 'k'}
	got, ok := s.buffer(unsafe.Pointer(&b[0]), 5)
	if !ok || string(got) != "stack" {
		t.Fatal("documented borrowed native callback buffer rejected")
	}
	if _, ok := s.buffer(unsafe.Pointer(&b[0]), uintptr(l.MaxBufferBytes+1)); ok {
		t.Fatal("callback count exceeded buffer cap")
	}
}

func TestFDIClosedLifetimeRefusesNativeCalls(t *testing.T) {
	p, e := openFDI(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e := p.Close(); e != nil {
		t.Fatal(e)
	}
	if e := p.Extract(context.Background(), nil, 0, cabformat.Inventory{}, nil, nil); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed native context remained callable", e)
	}
}

func TestNativeRejectsCorruptDataChecksumWithoutAWitness(t *testing.T) {
	b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	block := int(le.Uint32(b[36:]))
	le.PutUint32(b[block:], 0x11223344)
	m, fs, o := input(t, [][]byte{b}, [][]byte{[]byte("xx")})
	if r, e := Build(context.Background(), m, fs, o, Limits{}); e == nil || r != nil {
		if r != nil {
			r.Close()
		}
		t.Fatal("native checksum failure produced verified content")
	}
}
