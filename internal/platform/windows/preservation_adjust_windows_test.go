package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// A successful BOOL with ERROR_NOT_ALL_ASSIGNED must still cause rollback.
// This tests the fixed adapter's buffer boundary; it never adjusts a token.
func TestFixedPrivilegeAdjustmentChecksNativePreviousState(t *testing.T) {
	for _, kind := range []string{"partial", "foreign", "length", "duplicate", "good"} {
		t.Run(kind, func(t *testing.T) {
			before := privilegeFixture()
			next := append([]PrivilegeState(nil), before...)
			for j := range next {
				next[j].Attributes = windows.SE_PRIVILEGE_ENABLED
			}
			got, err := fixedPrivilegeAdjustment(next, before, func(in, out []byte) (uint32, error) {
				if len(in) != 40 || binary.LittleEndian.Uint32(in) != 3 || binary.LittleEndian.Uint32(in[12:]) != 2 {
					t.Fatal("wrong fixed native state", in)
				}
				copy(out, in)
				for j := 0; j < 3; j++ {
					binary.LittleEndian.PutUint32(out[12+j*12:], 0)
				}
				switch kind {
				case "partial":
					binary.LittleEndian.PutUint32(out, 1)
					return 16, windows.ERROR_NOT_ALL_ASSIGNED
				case "foreign":
					binary.LittleEndian.PutUint32(out[4:], 99)
				case "length":
					return 39, nil
				case "duplicate":
					copy(out[16:28], out[4:16])
				}
				return 40, nil
			})
			if kind == "good" {
				if err != nil || len(got) != 3 || got[2] != before[2] {
					t.Fatal(got, err)
				}
				return
			}
			if kind == "partial" {
				if !errors.Is(err, windows.ERROR_NOT_ALL_ASSIGNED) || len(got) != 1 {
					t.Fatal(got, err)
				}
				return
			}
			if err == nil {
				t.Fatal("unchecked native PreviousState", kind, got)
			}
		})
	}
}

func TestFixedPrivilegeRestoreAlwaysQueriesAndChecksFullOriginal(t *testing.T) {
	state := privilegeFixture()
	state[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	queries, adjustments := 0, 0
	restoreErr := errors.New("native restore error")
	p := privilegePorts{query: func() ([]PrivilegeState, error) { queries++; return append([]PrivilegeState(nil), state...), nil }, close: func() error { return nil }}
	p.adjust = func(next []PrivilegeState) ([]PrivilegeState, error) {
		adjustments++
		if adjustments == 1 {
			old := append([]PrivilegeState(nil), state[1:]...)
			state[1].Attributes = 2
			state[2].Attributes = 2
			return old, nil
		}
		state[0].Attributes = 0 // Previously enabled privilege drift must be visible too.
		return nil, restoreErr
	}
	l, e := acquirePreservationPrivileges(context.Background(), p, true)
	if e != nil {
		t.Fatal(e)
	}
	before := queries
	e = l.Close()
	if !errors.Is(e, restoreErr) || !errors.Is(e, ErrPrivilegeRequirement) || queries != before+1 {
		t.Fatal("restore query or exact baseline omitted", e, queries, before)
	}
}

func TestFixedPrivilegeAdjustmentRejectsNonProfileAndUnrequestedPrevious(t *testing.T) {
	for _, kind := range []string{"duplicate-known-luid", "removed", "foreign-request", "unrequested-previous", "wrong-previous-attributes"} {
		t.Run(kind, func(t *testing.T) {
			known := privilegeFixture()
			next := append([]PrivilegeState(nil), known[:1]...)
			next[0].Attributes = 2
			switch kind {
			case "duplicate-known-luid":
				known[2].LUID = known[0].LUID
			case "removed":
				next[0].Attributes = windows.SE_PRIVILEGE_REMOVED
			case "foreign-request":
				next[0].Name = "SeDebugPrivilege"
			}
			_, e := fixedPrivilegeAdjustment(next, known, func(in, out []byte) (uint32, error) {
				copy(out, in)
				binary.LittleEndian.PutUint32(out[12:], 0)
				if kind == "unrequested-previous" {
					binary.LittleEndian.PutUint32(out[4:], 2)
				}
				if kind == "wrong-previous-attributes" {
					binary.LittleEndian.PutUint32(out[12:], 2)
				}
				return 16, nil
			})
			if e == nil {
				t.Fatal("unchecked fixed profile/PreviousState", kind)
			}
		})
	}
}
