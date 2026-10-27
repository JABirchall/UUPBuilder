//go:build windows

package probes

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"uupbuilder/internal/model"
)

// observeHost only reads OS-owned APIs. No downloaded provider is loaded or
// executed. No privilege, driver, filesystem, or clean-machine claim is made.
// Report is deliberately empty: this observation is not retained proof evidence.
func observeHost() (ObservedHost, error) {
	return observeWindowsHost(model.ArchitectureFromGo(runtime.GOARCH), readWindowsHost)
}

// The raw observation boundary permits tests of native and emulated hosts
// without executing another architecture's binary or changing the host.
func observeWindowsHost(process model.Architecture, read func() (uint32, uint16, error)) (ObservedHost, error) {
	host := ObservedHost{OS: "windows", Host: model.Host{ProcessArchitecture: process}}
	build, machine, err := read()
	host.Host.WindowsBuild = build
	if err != nil {
		return host, err
	}
	switch machine {
	case 0x014c: // IMAGE_FILE_MACHINE_I386
		host.Host.NativeArchitecture = "x86"
	case 0x8664: // IMAGE_FILE_MACHINE_AMD64
		host.Host.NativeArchitecture = "amd64"
	case 0xaa64: // IMAGE_FILE_MACHINE_ARM64
		host.Host.NativeArchitecture = "arm64"
	default:
		return host, fmt.Errorf("native Windows machine identity unverified: unknown IMAGE_FILE_MACHINE value %#x", machine)
	}
	return host, nil
}

func readWindowsHost() (uint32, uint16, error) {
	var version struct {
		Size, Major, Minor, Build, Platform uint32
		ServicePack                         [128]uint16
	}
	version.Size = uint32(unsafe.Sizeof(version))
	versionProc := syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion")
	if err := versionProc.Find(); err != nil {
		return 0, 0, fmt.Errorf("RtlGetVersion unavailable: %w", err)
	}
	status, _, _ := versionProc.Call(uintptr(unsafe.Pointer(&version)))
	if status != 0 {
		return 0, 0, fmt.Errorf("RtlGetVersion NTSTATUS %#x", status)
	}
	if version.Major < 10 {
		return version.Build, 0, fmt.Errorf("Windows %d.%d predates required Windows 10", version.Major, version.Minor)
	}
	// GetNativeSystemInfo and IsWow64Process can report emulated x86/x64
	// details on ARM64. IsWow64Process2's native-machine output is explicit:
	// https://learn.microsoft.com/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2
	// It is optional on early Windows 10. Missing/failed/unknown identity stays
	// unverified; neither GOARCH nor legacy processor information is a fallback
	// proof of the native host. This leaves early-host coverage pending.
	wowProc := syscall.NewLazyDLL("kernel32.dll").NewProc("IsWow64Process2")
	if err := wowProc.Find(); err != nil {
		return version.Build, 0, fmt.Errorf("IsWow64Process2 unavailable; native host architecture unverified: %w", err)
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return version.Build, 0, fmt.Errorf("GetCurrentProcess failed: %w", err)
	}
	var processMachine, nativeMachine uint16
	success, _, callErr := wowProc.Call(uintptr(current), uintptr(unsafe.Pointer(&processMachine)), uintptr(unsafe.Pointer(&nativeMachine)))
	if success == 0 {
		if callErr == nil || callErr == syscall.Errno(0) {
			return version.Build, 0, fmt.Errorf("IsWow64Process2 returned FALSE without an error code; native host architecture unverified")
		}
		return version.Build, 0, fmt.Errorf("IsWow64Process2 failed; native host architecture unverified: %w", callErr)
	}
	// processMachine can be UNKNOWN for a non-WOW64 process. The executable's
	// actual process architecture remains the separate runtime.GOARCH value.
	return version.Build, nativeMachine, nil
}
