package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
)

func DetectHost(ctx context.Context) (model.Host, error) {
	return detectHost(ctx, runtime.GOARCH, nativeHostInfo, func() (model.FileSystemCapabilities, error) {
		p, err := os.Getwd()
		if err != nil {
			return model.FileSystemCapabilities{}, err
		}
		return InspectFileSystem(p)
	})
}

func detectHost(ctx context.Context, goarch string, probe func() (uint32, uint16, uint16, error), fs func() (model.FileSystemCapabilities, error)) (model.Host, error) {
	if err := ctx.Err(); err != nil {
		return model.Host{}, err
	}
	build, _, native, err := probe()
	if err != nil {
		return model.Host{}, err
	}
	if build < 10240 {
		return model.Host{}, errors.New("Windows 10 or later required")
	}
	arch, err := machineArchitecture(native)
	if err != nil {
		return model.Host{}, err
	}
	cap, err := fs()
	if err != nil {
		return model.Host{}, err
	}
	if err := ctx.Err(); err != nil {
		return model.Host{}, err
	}
	return model.Host{WindowsBuild: build, ProcessArchitecture: model.ArchitectureFromGo(goarch), NativeArchitecture: arch, FileSystem: cap}, nil
}

func machineArchitecture(machine uint16) (model.Architecture, error) {
	switch machine {
	case 0x14c:
		return "x86", nil
	case 0x8664:
		return "amd64", nil
	case 0xaa64:
		return "arm64", nil
	case 0x1c4:
		return "arm", nil
	default:
		return "", fmt.Errorf("unrecognized native machine 0x%x", machine)
	}
}

func nativeHostInfo() (uint32, uint16, uint16, error) {
	v := windows.RtlGetVersion()
	// IsWow64Process2 was introduced in Windows 10 1709, before ARM64 Windows.
	// GetNativeSystemInfo may report an emulated architecture on ARM64, so never
	// use it when the authoritative API exists, or on a 1709+ failure.
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsWow64Process2")
	process, native, err := probeNativeMachines(v.BuildNumber, func() (uint16, uint16, error) {
		if err := proc.Find(); err != nil {
			return 0, 0, errMachineAPIUnavailable
		}
		var process, native uint16
		err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native)
		return process, native, err
	}, legacyNativeArchitecture)
	return v.BuildNumber, process, native, err
}

var errMachineAPIUnavailable = errors.New("IsWow64Process2 unavailable")

func probeNativeMachines(build uint32, modern func() (uint16, uint16, error), legacy func() (uint16, error)) (uint16, uint16, error) {
	process, native, err := modern()
	if err == nil {
		return process, native, nil
	}
	if !errors.Is(err, errMachineAPIUnavailable) {
		return 0, 0, err
	}
	if build >= 16299 {
		return 0, 0, errors.New("IsWow64Process2 unavailable on Windows 10 1709+")
	}
	architecture, err := legacy()
	if err != nil {
		return 0, 0, err
	}
	switch architecture {
	case 0:
		return 0, 0x14c, nil
	case 9:
		return 0, 0x8664, nil
	default:
		return 0, 0, errors.New("unsupported legacy native architecture")
	}
}

func legacyNativeArchitecture() (uint16, error) {
	type systemInfo struct {
		Architecture          uint16
		Reserved              uint16
		PageSize              uint32
		MinimumAddress        uintptr
		MaximumAddress        uintptr
		ActiveProcessorMask   uintptr
		NumberOfProcessors    uint32
		ProcessorType         uint32
		AllocationGranularity uint32
		ProcessorLevel        uint16
		ProcessorRevision     uint16
	}
	var info systemInfo
	windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNativeSystemInfo").Call(uintptr(unsafe.Pointer(&info)))
	return info.Architecture, nil
}
