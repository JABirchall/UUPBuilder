package wimmeta

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestPreservationEAsRetainFlagsNamesValuesAndRejectBrokenFraming(t *testing.T) {
	// tag-2 format: uint16 value length, byte name length, byte flags,
	// NUL-terminated name, then value; successive records have no padding.
	raw := []byte{3, 0, 1, 0x80, 'A', 0, 9, 8, 7, 0, 0, 1, 0, 'B', 0}
	eas, _, err := DecodeSourceEAs(context.Background(), raw, 2, 4096)
	if err != nil || len(eas) != 2 || string(eas[0].Name) != "A" || eas[0].Flags != 0x80 || !bytes.Equal(eas[0].Value, []byte{9, 8, 7}) || string(eas[1].Name) != "B" {
		t.Fatal(eas, err)
	}
	eas[0].Value[0] = 1
	if raw[6] != 9 {
		t.Fatal("EA aliases input")
	}
	for _, broken := range [][]byte{raw[:8], {0, 0, 0, 0, 0}, {0, 0, 1, 0, 'A', 1}, {0, 0, 1, 0, 'A', 0, 0}} {
		if _, _, err = DecodeSourceEAs(context.Background(), broken, 2, 4096); !errors.Is(err, ErrLayout) {
			t.Fatal("malformed accepted", broken, err)
		}
	}
	if _, _, err = DecodeSourceEAs(context.Background(), raw, 1, 4096); !errors.Is(err, ErrLimit) {
		t.Fatal("EA count bypass", err)
	}
	if _, _, err = DecodeSourceEAs(context.Background(), raw, 2, 0); !errors.Is(err, ErrLimit) {
		t.Fatal("EA exhausted budget", err)
	}
}

func TestPreservationSecurityInspectionKeepsOpaqueACEAndOriginalGaps(t *testing.T) {
	raw := securityFixture(9)[16:76]
	s, gaps, _, err := InspectSecurity(context.Background(), raw, 1<<20)
	if err != nil || len(gaps) != 1 || gaps[0].Kind != "ace-semantics" || s.DACL.ACEs[0].Type != 9 || !bytes.Equal(s.Raw, raw) {
		t.Fatal(s, gaps, err)
	}
	s.Raw[40] = 0
	if raw[40] != 9 {
		t.Fatal("security aliases caller")
	}
	if _, _, _, err = InspectSecurity(context.Background(), raw, 0); !errors.Is(err, ErrLimit) {
		t.Fatal("security exhausted", err)
	}
	broken := bytes.Clone(raw)
	broken[42] = 0xff
	if _, _, _, err = InspectSecurity(context.Background(), broken, 1<<20); !errors.Is(err, ErrLayout) {
		t.Fatal("malformed security", err)
	}
}
