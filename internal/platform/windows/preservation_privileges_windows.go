package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"sync"

	"golang.org/x/sys/windows"
)

// This fixed profile covers backup reads, restoration of owner/DACL and full
// SACL inspection. Microsoft does not specify a complete WIMApplyImage privilege
// profile; these prerequisites do not assert provider sufficiency.
const ImagePreservationPrivilegeProfile = "image-restore-full-security-inspection-v1"

var ErrPrivilegeRequirement = errors.New("image preservation privilege requirement unmet")

type PrivilegeState struct {
	Name       string
	LUID       windows.LUID
	Present    bool
	Attributes uint32
}
type PrivilegeObservation struct {
	Profile, TokenKind        string
	Required                  []PrivilegeState
	ProviderSufficiencyProved bool
}

// Native adjustment remains behind the fixed, separately invoked adapter.
type privilegePorts struct {
	query  func() ([]PrivilegeState, error)
	adjust func([]PrivilegeState) ([]PrivilegeState, error)
	close  func() error
}
type ImagePrivilegeLease struct {
	mu             sync.Mutex
	ports          privilegePorts
	original       []PrivilegeState
	baseline       []PrivilegeState
	active, closed bool
	closeErr       error
}

func acquirePreservationPrivileges(ctx context.Context, p privilegePorts, enable bool) (*ImagePrivilegeLease, error) {
	l := &ImagePrivilegeLease{ports: p}
	fail := func(e error) (*ImagePrivilegeLease, error) { return l, errors.Join(e, l.Close()) }
	if ctx == nil || p.query == nil || p.close == nil {
		return fail(ErrPrivilegeRequirement)
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	state, e := p.query()
	if e != nil {
		return fail(e)
	}
	if e = validatePrivilegeStates(state, false); e != nil {
		return fail(e)
	}
	l.baseline = slices.Clone(state)
	var next []PrivilegeState
	for _, s := range state {
		if s.Attributes&windows.SE_PRIVILEGE_ENABLED == 0 {
			if !enable || p.adjust == nil {
				return fail(fmt.Errorf("%w: %s disabled", ErrPrivilegeRequirement, s.Name))
			}
			s.Attributes = windows.SE_PRIVILEGE_ENABLED
			next = append(next, s)
		}
	}
	if len(next) > 0 {
		before := slices.Clone(state)
		// PreviousState includes only changed privileges. Preserve it even on
		// ERROR_NOT_ALL_ASSIGNED, then roll back before closing on every failure.
		previous, adjustErr := p.adjust(next)
		// Roll back only authenticated original states. On malformed native
		// PreviousState, restore the bounded pre-query states for our requested
		// privileges, never arbitrary returned names/LUIDs/attributes.
		for _, wanted := range next {
			for _, b := range before {
				if wanted.Name == b.Name {
					l.original = append(l.original, b)
				}
			}
		}
		if e = validPrevious(previous, next, before, adjustErr != nil); e != nil {
			return fail(errors.Join(adjustErr, e))
		}
		l.original = slices.Clone(previous)
		if adjustErr != nil {
			return fail(adjustErr)
		}
	}
	state, e = p.query()
	if e == nil {
		e = validatePrivilegeStates(state, true)
	}
	if e != nil {
		return fail(e)
	}
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	l.active = true
	return l, nil
}
func validatePrivilegeStates(s []PrivilegeState, enabled bool) error {
	names := []string{"SeBackupPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege"}
	if len(s) != len(names) {
		return ErrPrivilegeRequirement
	}
	for n, name := range names {
		if s[n].Name != name || !s[n].Present || s[n].LUID == (windows.LUID{}) || s[n].Attributes&windows.SE_PRIVILEGE_REMOVED != 0 || enabled && s[n].Attributes&windows.SE_PRIVILEGE_ENABLED == 0 {
			return fmt.Errorf("%w: %s", ErrPrivilegeRequirement, name)
		}
		for j := 0; j < n; j++ {
			if s[j].LUID == s[n].LUID {
				return ErrPrivilegeRequirement
			}
		}
	}
	return nil
}
func validPrevious(old, next, before []PrivilegeState, partial bool) error {
	if len(old) > len(next) || !partial && len(old) != len(next) {
		return ErrPrivilegeRequirement
	}
	seen := map[string]bool{}
	for _, s := range old {
		if seen[s.Name] {
			return ErrPrivilegeRequirement
		}
		seen[s.Name] = true
		requested := false
		for _, n := range next {
			if s.Name == n.Name && s.LUID == n.LUID {
				requested = true
			}
		}
		if !requested {
			return ErrPrivilegeRequirement
		}
		found := false
		for _, b := range before {
			if s == b {
				found = true
			}
		}
		if !found {
			return ErrPrivilegeRequirement
		}
	}
	return nil
}
func (l *ImagePrivilegeLease) CheckActive() error {
	if l == nil {
		return ErrPrivilegeRequirement
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return os.ErrClosed
	}
	if !l.active {
		return ErrPrivilegeRequirement
	}
	s, e := l.ports.query()
	if e != nil {
		return e
	}
	return validatePrivilegeStates(s, true)
}
func (l *ImagePrivilegeLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		l.active = false
		if len(l.original) > 0 {
			if l.ports.adjust == nil {
				l.closeErr = ErrPrivilegeRequirement
			} else {
				_, l.closeErr = l.ports.adjust(slices.Clone(l.original))
			}
		}
		// Query even after native restore failure. Check every original required
		// privilege, including those already enabled before acquisition.
		if len(l.baseline) != 0 && l.ports.query != nil {
			actual, e := l.ports.query()
			l.closeErr = errors.Join(l.closeErr, e)
			if e == nil && !slices.Equal(actual, l.baseline) {
				l.closeErr = errors.Join(l.closeErr, fmt.Errorf("%w: exact original privilege state not observed", ErrPrivilegeRequirement))
			}
		}
		if l.ports.close != nil {
			l.closeErr = errors.Join(l.closeErr, l.ports.close())
		}
	}
	return l.closeErr
}

// ObserveImagePreservationPrivileges queries the process token only, refusing
// thread impersonation. It never enables a privilege or launches elevation.
func ObserveImagePreservationPrivileges(ctx context.Context) (PrivilegeObservation, error) {
	o := PrivilegeObservation{Profile: ImagePreservationPrivilegeProfile, TokenKind: "process (no impersonation)"}
	if ctx == nil {
		return o, ErrPrivilegeRequirement
	}
	if e := ctx.Err(); e != nil {
		return o, e
	}
	p, e := openPreservationQuery()
	if e != nil {
		return o, e
	}
	o.Required, e = p.query()
	e = errors.Join(e, p.close(), ctx.Err())
	return o, e
}

// GuardImagePreservationPrivileges borrows already enabled requirements.
// Close releases the held query handle and latches cleanup failures.
func GuardImagePreservationPrivileges(ctx context.Context) (*ImagePrivilegeLease, error) {
	p, e := openPreservationQuery()
	if e != nil {
		return nil, e
	}
	return acquirePreservationPrivileges(ctx, p, false)
}
func noImpersonation() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var t windows.Token
	e := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, false, &t)
	if errors.Is(e, windows.ERROR_NO_TOKEN) {
		return nil
	}
	if e != nil {
		return e
	}
	return errors.Join(errors.New("impersonation token refused"), t.Close())
}
func tokenData(t windows.Token, class uint32) ([]byte, error) {
	var n uint32
	e := windows.GetTokenInformation(t, class, nil, 0, &n)
	if !errors.Is(e, windows.ERROR_INSUFFICIENT_BUFFER) || n < 4 || n > 65536 {
		return nil, fmt.Errorf("token information length %d: %w", n, errors.Join(e, ErrPrivilegeRequirement))
	}
	b := make([]byte, n)
	if e = windows.GetTokenInformation(t, class, &b[0], n, &n); e != nil {
		return nil, e
	}
	if n < 4 || n > uint32(len(b)) {
		return nil, ErrPrivilegeRequirement
	}
	return b[:n], nil
}
func openPreservationQuery() (privilegePorts, error) {
	return openPreservationToken(false)
}
func openPreservationToken(adjust bool) (privilegePorts, error) {
	if e := noImpersonation(); e != nil {
		return privilegePorts{}, e
	}
	var t windows.Token
	access := uint32(windows.TOKEN_QUERY)
	if adjust {
		access |= windows.TOKEN_ADJUST_PRIVILEGES
	}
	if e := windows.OpenProcessToken(windows.CurrentProcess(), access, &t); e != nil {
		return privilegePorts{}, e
	}
	stats, e := tokenData(t, windows.TokenStatistics)
	if e != nil || len(stats) < 8 {
		return privilegePorts{}, errors.Join(e, t.Close(), ErrPrivilegeRequirement)
	}
	id := binary.LittleEndian.Uint64(stats)
	p := privilegePorts{close: t.Close}
	p.query = func() ([]PrivilegeState, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if e := noImpersonation(); e != nil {
			return nil, e
		}
		var current windows.Token
		if e := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &current); e != nil {
			return nil, e
		}
		got, e := tokenData(current, windows.TokenStatistics)
		e = errors.Join(e, current.Close())
		if e != nil {
			return nil, e
		}
		if len(got) < 8 || binary.LittleEndian.Uint64(got) != id {
			return nil, errors.New("process token identity changed")
		}
		b, e := tokenData(t, windows.TokenPrivileges)
		if e != nil {
			return nil, e
		}
		count := binary.LittleEndian.Uint32(b)
		if count > 1024 || uint64(count)*12+4 != uint64(len(b)) {
			return nil, ErrPrivilegeRequirement
		}
		out := make([]PrivilegeState, 3)
		for n, name := range []string{"SeBackupPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege"} {
			out[n].Name = name
			u, _ := windows.UTF16PtrFromString(name)
			if e := windows.LookupPrivilegeValue(nil, u, &out[n].LUID); e != nil {
				return out, e
			}
			for j := uint32(0); j < count; j++ {
				v := b[4+j*12:]
				if binary.LittleEndian.Uint32(v) == out[n].LUID.LowPart && int32(binary.LittleEndian.Uint32(v[4:])) == out[n].LUID.HighPart {
					out[n].Present = true
					out[n].Attributes = binary.LittleEndian.Uint32(v[8:])
				}
			}
		}
		return out, nil
	}
	if adjust {
		p.adjust = func(next []PrivilegeState) ([]PrivilegeState, error) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			known, e := p.query() // Rechecks identity and impersonation before every change.
			if e != nil {
				return nil, e
			}
			return fixedPrivilegeAdjustment(next, known, func(in, out []byte) (uint32, error) { return preservationAdjustCall(t, in, out) })
		}
	}
	return p, nil
}
