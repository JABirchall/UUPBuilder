package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var preservationAdjustmentMu sync.Mutex

// AcquireImagePreservationPrivileges is the fixed Backup/Restore/Security
// adapter. CODE ONLY in U07B2B2: no ordinary test or production entry calls it.
// Its process-token lease serializes adjustment until exact restoration/close.
// Presence is mandatory; this cannot add privileges or obtain elevation.
func AcquireImagePreservationPrivileges(ctx context.Context) (*ImagePrivilegeLease, error) {
	preservationAdjustmentMu.Lock()
	p, e := openPreservationToken(true)
	if e != nil {
		preservationAdjustmentMu.Unlock()
		return nil, e
	}
	closeToken := p.close
	p.close = func() error { e := closeToken(); preservationAdjustmentMu.Unlock(); return e }
	return acquirePreservationPrivileges(ctx, p, true)
}

// fixedPrivilegeAdjustment never accepts a caller privilege profile. Only the
// three queried LUIDs may appear, each once, and no removal is permitted.
// Returned bytes are copied/validated even when BOOL succeeded but LastError
// reports partial assignment. The acquisition kernel authenticates old state
// against its pre-query and rolls back on every malformed/partial response.
func fixedPrivilegeAdjustment(next, known []PrivilegeState, call func([]byte, []byte) (uint32, error)) ([]PrivilegeState, error) {
	if len(next) == 0 || len(next) > 3 || call == nil || validatePrivilegeStates(known, false) != nil {
		return nil, ErrPrivilegeRequirement
	}
	var in, out [40]byte // DWORD count; at most three LUID_AND_ATTRIBUTES.
	binary.LittleEndian.PutUint32(in[:], uint32(len(next)))
	seen := [3]bool{}
	for j, s := range next {
		found := -1
		for k, v := range known {
			if v.Name == s.Name && v.LUID == s.LUID && s.Present {
				found = k
			}
		}
		if found < 0 || seen[found] || s.Attributes & ^uint32(windows.SE_PRIVILEGE_ENABLED|windows.SE_PRIVILEGE_ENABLED_BY_DEFAULT|windows.SE_PRIVILEGE_USED_FOR_ACCESS) != 0 {
			return nil, ErrPrivilegeRequirement
		}
		seen[found] = true
		v := in[4+j*12:]
		binary.LittleEndian.PutUint32(v, s.LUID.LowPart)
		binary.LittleEndian.PutUint32(v[4:], uint32(s.LUID.HighPart))
		binary.LittleEndian.PutUint32(v[8:], s.Attributes)
	}
	n, e := call(in[:], out[:])
	if n < 4 || n > 40 {
		return nil, errors.Join(e, ErrPrivilegeRequirement)
	}
	count := binary.LittleEndian.Uint32(out[:])
	if count > uint32(len(next)) || n != 4+count*12 {
		return nil, errors.Join(e, ErrPrivilegeRequirement)
	}
	previous := make([]PrivilegeState, 0, count)
	requested := seen
	seen = [3]bool{}
	for j := uint32(0); j < count; j++ {
		v := out[4+j*12:]
		id := windows.LUID{LowPart: binary.LittleEndian.Uint32(v), HighPart: int32(binary.LittleEndian.Uint32(v[4:]))}
		found := -1
		for k, s := range known {
			if s.LUID == id {
				found = k
			}
		}
		if found < 0 || seen[found] || !requested[found] {
			return nil, errors.Join(e, ErrPrivilegeRequirement)
		}
		seen[found] = true
		s := known[found]
		s.Attributes = binary.LittleEndian.Uint32(v[8:])
		if s.Attributes != known[found].Attributes {
			return nil, errors.Join(e, ErrPrivilegeRequirement)
		}
		previous = append(previous, s)
	}
	return previous, e
}

func preservationAdjustCall(t windows.Token, in, out []byte) (uint32, error) {
	// x/sys's wrapper checks BOOL only; this API additionally requires its
	// immediate LastError even on success (ERROR_NOT_ALL_ASSIGNED).
	p := windows.NewLazySystemDLL("advapi32.dll").NewProc("AdjustTokenPrivileges")
	if e := p.Find(); e != nil {
		return 0, e
	}
	var n uint32
	ok, _, errno := syscall.SyscallN(p.Addr(), uintptr(t), 0, uintptr(unsafe.Pointer(&in[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&n)))
	if ok == 0 || errno != 0 {
		return n, errors.Join(errno, ErrPrivilegeRequirement)
	}
	return n, nil
}
