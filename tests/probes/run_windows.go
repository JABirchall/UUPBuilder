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
	host := ObservedHost{OS: "windows", Host: model.Host{ProcessArchitecture: model.ArchitectureFromGo(runtime.GOARCH)}}
	var version struct {
		Size, Major, Minor, Build, Platform uint32
		ServicePack                         [128]uint16
	}
	version.Size = uint32(unsafe.Sizeof(version))
	status, _, _ := syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion").Call(uintptr(unsafe.Pointer(&version)))
	if status != 0 {
		return host, fmt.Errorf("RtlGetVersion NTSTATUS %#x", status)
	}
	if version.Major < 10 {
		return host, fmt.Errorf("Windows %d.%d predates required Windows 10", version.Major, version.Minor)
	}
	host.Host.WindowsBuild = version.Build
	var info struct {
		Architecture, Reserved                                   uint16
		PageSize                                                 uint32
		MinimumAddress, MaximumAddress, ActiveProcessorMask      uintptr
		NumberOfProcessors, ProcessorType, AllocationGranularity uint32
		ProcessorLevel, ProcessorRevision                        uint16
	}
	syscall.NewLazyDLL("kernel32.dll").NewProc("GetNativeSystemInfo").Call(uintptr(unsafe.Pointer(&info)))
	switch info.Architecture {
	case 0:
		host.Host.NativeArchitecture = "x86"
	case 9:
		host.Host.NativeArchitecture = "amd64"
	case 12:
		host.Host.NativeArchitecture = "arm64"
	default:
		return host, fmt.Errorf("unknown native Windows processor architecture %d", info.Architecture)
	}
	return host, nil
}
