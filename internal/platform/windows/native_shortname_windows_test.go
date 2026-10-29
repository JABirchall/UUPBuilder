package windows

import (
	"encoding/binary"
	"errors"
	"slices"
	"testing"
)

// Catches truncating the signed byte length, guessing a missing name, and
// normalizing raw UTF-16. No host 8.3 setting or native object is changed.
func TestNativeDirectoryShortNameLosslessAndBounded(t *testing.T) {
	b := make([]byte, 106)
	b[68] = 6
	for j, u := range []uint16{'A', 0xd800, '~'} {
		binary.LittleEndian.PutUint16(b[70+j*2:], u)
	}
	u, e := directoryShortName(b)
	if e != nil || !slices.Equal(u, []uint16{'A', 0xd800, '~'}) {
		t.Fatalf("lossless counted name: %x %v", u, e)
	}
	for _, length := range []byte{1, 25, 0xff} {
		b[68] = length
		if _, e := directoryShortName(b); !errors.Is(e, ErrTreePreserved) {
			t.Fatalf("malformed length %d: %v", length, e)
		}
	}
	b[68] = 0
	if u, e = directoryShortName(b); e != nil || len(u) != 0 {
		t.Fatal("invented missing name", u, e)
	}
	if _, e = directoryShortName(b[:93]); e == nil {
		t.Fatal("short fixed header accepted")
	}
}
