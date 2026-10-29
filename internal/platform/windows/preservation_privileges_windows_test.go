package windows

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func privilegeFixture() []PrivilegeState {
	return []PrivilegeState{{Name: "SeBackupPrivilege", Present: true, LUID: windows.LUID{LowPart: 1}}, {Name: "SeRestorePrivilege", Present: true, LUID: windows.LUID{LowPart: 2}}, {Name: "SeSecurityPrivilege", Present: true, LUID: windows.LUID{LowPart: 3}}}
}

func TestPreservationPrivilegeLeaseRollsBackPartialAndLatchesClose(t *testing.T) {
	restoreErr, closeErr := errors.New("restore failed"), errors.New("close failed")
	states := privilegeFixture()
	closed, restored := 0, 0
	p := privilegePorts{query: func() ([]PrivilegeState, error) { return states, nil }, close: func() error { closed++; return closeErr }}
	p.adjust = func(next []PrivilegeState) ([]PrivilegeState, error) {
		if next[0].Attributes == windows.SE_PRIVILEGE_ENABLED {
			return states[:1], windows.ERROR_NOT_ALL_ASSIGNED
		}
		restored++
		if len(next) != 1 || next[0].Name != "SeBackupPrivilege" || next[0].Attributes != 0 {
			t.Fatal("wrong rollback", next)
		}
		return nil, restoreErr
	}
	l, e := acquirePreservationPrivileges(context.Background(), p, true)
	if l == nil || !errors.Is(e, windows.ERROR_NOT_ALL_ASSIGNED) || !errors.Is(e, restoreErr) || !errors.Is(e, closeErr) || closed != 1 || restored != 1 {
		t.Fatal(l, e, closed, restored)
	}
	if e = l.Close(); !errors.Is(e, restoreErr) || !errors.Is(e, closeErr) || closed != 1 {
		t.Fatal("close not latched", e, closed)
	}
	if e = l.CheckActive(); e == nil {
		t.Fatal("failed acquisition usable")
	}
}

func TestPreservationPrivilegeLeaseRestoresExactOriginalAndGuardsMissing(t *testing.T) {
	for _, missing := range []bool{false, true} {
		states := privilegeFixture()
		states[0].Attributes = windows.SE_PRIVILEGE_ENABLED | windows.SE_PRIVILEGE_ENABLED_BY_DEFAULT
		if missing {
			states[2].Present = false
		}
		adjusted, restored, closed := 0, 0, 0
		p := privilegePorts{query: func() ([]PrivilegeState, error) { return states, nil }, close: func() error { closed++; return nil }}
		p.adjust = func(next []PrivilegeState) ([]PrivilegeState, error) {
			if adjusted == 0 {
				adjusted++
				if len(next) != 2 {
					t.Fatal(next)
				}
				states[1].Attributes = windows.SE_PRIVILEGE_ENABLED
				states[2].Attributes = windows.SE_PRIVILEGE_ENABLED
				return privilegeFixture()[1:], nil
			}
			restored++
			if len(next) != 2 || next[0].Attributes != 0 || next[1].Attributes != 0 {
				t.Fatal(next)
			}
			states[1].Attributes = 0
			states[2].Attributes = 0
			return nil, nil
		}
		l, e := acquirePreservationPrivileges(context.Background(), p, true)
		if missing {
			if e == nil || adjusted != 0 || closed != 1 {
				t.Fatal("missing privilege adjusted", e)
			}
			continue
		}
		if e != nil || l.CheckActive() != nil {
			t.Fatal(e)
		}
		if e = l.Close(); e != nil || restored != 1 || closed != 1 {
			t.Fatal(e, restored, closed)
		}
	}
}

func TestPreservationPrivilegeLeaseRejectsMalformedPreviousAndUnrestoredState(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		state := privilegeFixture()
		calls := 0
		p := privilegePorts{query: func() ([]PrivilegeState, error) { return state, nil }, close: func() error { return nil }}
		p.adjust = func(next []PrivilegeState) ([]PrivilegeState, error) {
			calls++
			if calls == 1 {
				for n := range state {
					state[n].Attributes = windows.SE_PRIVILEGE_ENABLED
				}
				previous := privilegeFixture()
				if malformed {
					previous[0].LUID.LowPart = 99
				}
				return previous, nil
			}
			return nil, nil
		}
		l, e := acquirePreservationPrivileges(context.Background(), p, true)
		if malformed {
			if l == nil || e == nil {
				t.Fatal("unchecked previous state", e)
			}
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = l.Close(); e == nil {
			t.Fatal("restore success accepted without restored observation")
		}
	}
}

func TestPreservationPrivilegeGuardNeverAdjustsAndReportsActualToken(t *testing.T) {
	p := privilegePorts{query: func() ([]PrivilegeState, error) { return privilegeFixture(), nil }, adjust: func([]PrivilegeState) ([]PrivilegeState, error) {
		t.Fatal("query guard adjusted token")
		return nil, nil
	}, close: func() error { return nil }}
	if l, e := acquirePreservationPrivileges(context.Background(), p, false); e == nil || l == nil {
		t.Fatal("disabled guard accepted", e)
	}
	o, e := ObserveImagePreservationPrivileges(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if len(o.Required) != 3 || o.TokenKind == "" {
		t.Fatal(o)
	}
	t.Logf("QUERY ONLY: token=%s requirements=%+v; WIMGAPI sufficiency=%t", o.TokenKind, o.Required, o.ProviderSufficiencyProved)
}
