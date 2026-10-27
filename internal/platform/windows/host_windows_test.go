package windows

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"uupbuilder/internal/model"
)

func TestDetectHostDistinguishesProcessAndNativeArchitecture(t *testing.T) {
	for _, tc := range []struct {
		process, native         uint16
		goarch                  string
		wantProcess, wantNative model.Architecture
	}{
		{0x14c, 0x8664, "386", "x86", "amd64"},
		{0x8664, 0xaa64, "amd64", "amd64", "arm64"},
		{0, 0xaa64, "arm64", "arm64", "arm64"},
	} {
		h, err := detectHost(context.Background(), tc.goarch, func() (uint32, uint16, uint16, error) { return 19045, tc.process, tc.native, nil }, func() (model.FileSystemCapabilities, error) {
			return model.FileSystemCapabilities{Name: "NTFS", Local: true}, nil
		})
		if err != nil || h.ProcessArchitecture != tc.wantProcess || h.NativeArchitecture != tc.wantNative || h.WindowsBuild != 19045 {
			t.Fatalf("host %#v, error %v", h, err)
		}
	}
}

func TestHostDetectionRejectsOldWindowsAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DetectHost(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	_, err := detectHost(context.Background(), "amd64", func() (uint32, uint16, uint16, error) { return 9600, 0, 0x8664, nil }, func() (model.FileSystemCapabilities, error) {
		t.Fatal("filesystem on unsupported OS")
		return model.FileSystemCapabilities{}, nil
	})
	if err == nil {
		t.Fatal("accepted Windows 8.1")
	}
}

func TestNativeHostDetection(t *testing.T) {
	h, err := DetectHost(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.WindowsBuild < 10240 || h.ProcessArchitecture != model.ArchitectureFromGo(runtime.GOARCH) || h.NativeArchitecture == "" || h.FileSystem.Name == "" {
		t.Fatalf("host %#v", h)
	}
	t.Logf("native host evidence: %#v", h)
}

func TestNativeArchitectureFallbackIsLimitedToPreARM64Windows(t *testing.T) {
	missing := func() (uint16, uint16, error) { return 0, 0, errMachineAPIUnavailable }
	legacy := func() (uint16, error) { return 9, nil }
	_, native, err := probeNativeMachines(10240, missing, legacy)
	if err != nil || native != 0x8664 {
		t.Fatalf("baseline fallback %x %v", native, err)
	}
	for _, build := range []uint32{16299, 19045} {
		if _, _, err := probeNativeMachines(build, missing, func() (uint16, error) {
			t.Fatal("emulation-prone fallback used on ARM64-capable Windows")
			return 0, nil
		}); err == nil {
			t.Fatal("accepted unavailable authoritative API")
		}
	}
	denied := errors.New("access denied")
	if _, _, err := probeNativeMachines(10240, func() (uint16, uint16, error) { return 0, 0, denied }, legacy); !errors.Is(err, denied) {
		t.Fatalf("lost native API error %v", err)
	}
}
