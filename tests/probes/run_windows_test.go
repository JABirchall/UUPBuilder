//go:build windows

package probes

import (
	"context"
	"errors"
	"runtime"
	"syscall"
	"testing"

	"uupbuilder/internal/model"
)

// These API-result fixtures test classification only. They are not matching-host
// execution evidence or proof that any image provider works on these systems.
func TestWindowsObservationNativeAndEmulatedMachines(t *testing.T) {
	for _, test := range []struct {
		name          string
		process       model.Architecture
		build         uint32
		nativeMachine uint16
		wantNative    model.Architecture
	}{
		{"native x86", "x86", 19045, 0x014c, "x86"},
		{"native amd64", "amd64", 19045, 0x8664, "amd64"},
		{"native arm64", "arm64", 19045, 0xaa64, "arm64"},
		{"x86 emulated on arm64", "x86", 19045, 0xaa64, "arm64"},
		{"amd64 emulated on arm64", "amd64", 26100, 0xaa64, "arm64"},
		{"WOW64 on amd64", "x86", 19045, 0x8664, "amd64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			host, err := observeWindowsHost(test.process, func() (uint32, uint16, error) {
				return test.build, test.nativeMachine, nil
			})
			if err != nil || host.OS != "windows" || host.Host.WindowsBuild != test.build || host.Host.NativeArchitecture != test.wantNative || host.Host.ProcessArchitecture != test.process {
				t.Fatalf("injected API observation: host=%+v, err=%v; want native/process=%s/%s", host, err, test.wantNative, test.process)
			}
		})
	}
}

func TestWindowsObservationFailsClosedWithoutNativeIdentity(t *testing.T) {
	for _, test := range []struct {
		name     string
		build    uint32
		machine  uint16
		queryErr error
	}{
		{"early Windows 10 missing API", 10240, 0, syscall.ERROR_PROC_NOT_FOUND},
		{"API failure with output bytes", 19045, 0x8664, syscall.ERROR_ACCESS_DENIED},
		{"unknown machine is not native x86", 19045, 0, nil},
		{"legacy processor enum is not a machine identity", 19045, 9, nil},
		{"future unknown machine", 19045, 0xffff, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			host, err := observeWindowsHost("amd64", func() (uint32, uint16, error) {
				return test.build, test.machine, test.queryErr
			})
			if err == nil || host.Host.NativeArchitecture != "" || host.Host.ProcessArchitecture != "amd64" || host.Host.WindowsBuild != test.build {
				t.Fatalf("uncertain native identity must preserve build/process and return error, got %+v / %v", host, err)
			}
			if test.queryErr != nil && !errors.Is(err, test.queryErr) {
				t.Fatalf("native-query error identity lost: %v", err)
			}
		})
	}
}

func TestWindowsObservationEmulationCannotMatchNativeRunCase(t *testing.T) {
	for _, process := range []model.Architecture{"x86", "amd64"} {
		t.Run(string(process), func(t *testing.T) {
			c, _ := unitRecord()
			c.Host.NativeArchitecture, c.Host.ProcessArchitecture = process, process
			for i := range c.Components {
				c.Components[i].NativeArchitecture = process
			}
			e, err := runCase(context.Background(), c, nil, func() (ObservedHost, error) {
				build := uint32(19045)
				if process == "amd64" {
					build = 26100
				}
				return observeWindowsHost(process, func() (uint32, uint16, error) { return build, 0xaa64, nil })
			})
			mismatch := false
			for _, b := range e.Blockers {
				mismatch = mismatch || b.Code == "host-requirement-mismatch"
			}
			if err == nil || e.Status != Unverified || len(e.Invocations) != 0 || !mismatch || e.Host.Host.NativeArchitecture != "arm64" || e.Host.Host.ProcessArchitecture != process {
				t.Fatalf("emulated process matched native case: %+v / %v", e, err)
			}
		})
	}
}

func TestWindowsObservationActualReadOnlyHost(t *testing.T) {
	host, err := observeHost()
	if host.OS != "windows" || host.Host.WindowsBuild < 10240 || host.Host.ProcessArchitecture != model.ArchitectureFromGo(runtime.GOARCH) {
		t.Fatalf("OS/process observation missing: %+v / %v", host, err)
	}
	if err != nil && host.Host.NativeArchitecture != "" {
		t.Fatalf("failed observation asserted native identity: %+v / %v", host, err)
	}
	if err == nil && !oneOf(string(host.Host.NativeArchitecture), "x86", "amd64", "arm64") {
		t.Fatalf("successful observation lacks native identity: %+v", host)
	}
	t.Logf("actual read-only OS build=%d, native/process=%s/%s, observation error=%v; no provider execution", host.Host.WindowsBuild, host.Host.NativeArchitecture, host.Host.ProcessArchitecture, err)
}

func TestWindowsObservationUnavailableKeepsRunCaseUnverified(t *testing.T) {
	c, _ := unitRecord()
	e, err := runCase(context.Background(), c, nil, func() (ObservedHost, error) {
		return observeWindowsHost("amd64", func() (uint32, uint16, error) {
			return 10240, 0, syscall.ERROR_PROC_NOT_FOUND
		})
	})
	unverified := false
	for _, b := range e.Blockers {
		unverified = unverified || b.Code == "host-observation-unverified"
	}
	if err == nil || e.Status != Unverified || len(e.Invocations) != 0 || !unverified || e.Host.Host.NativeArchitecture != "" || e.Host.Host.WindowsBuild != 10240 || e.Host.Host.ProcessArchitecture != "amd64" {
		t.Fatalf("missing early-Windows API must leave native host unverified: %+v / %v", e, err)
	}
}
