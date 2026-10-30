package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

type dismRunnerFunc func(context.Context, platform.Invocation, model.Emit) (platform.RunResult, error)

func (f dismRunnerFunc) Run(ctx context.Context, inv platform.Invocation, emit model.Emit) (platform.RunResult, error) {
	return f(ctx, inv, emit)
}

func nativeShortPathForTest(t *testing.T, path string) string {
	t.Helper()
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 32768)
	n, err := windows.GetShortPathName(wide, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || n >= uint32(len(buffer)) {
		t.Fatalf("native short path: length=%d error=%v", n, err)
	}
	return strings.TrimPrefix(windows.UTF16ToString(buffer[:n]), `\\?\`)
}

func TestDISMCommandsUseNativeShortAliasOfOwnedMount(t *testing.T) {
	w, err := platform.CreateWorkspace(t.TempDir(), "short-offline-path")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	parent := "scratch/" + strings.Repeat("a", 70)
	if err := w.MkdirAll(parent); err != nil {
		t.Fatal(err)
	}
	mount, err := w.ClaimMount(parent+"/edition-mount-1", "service-image")
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(w.Path(), filepath.FromSlash(mount.RelativePath))
	want := nativeShortPathForTest(t, original)
	if want == strings.TrimPrefix(original, `\\?\`) {
		t.Skip("this volume has no shorter native 8.3 alias")
	}
	longInfo, err := os.Stat(original)
	if err != nil {
		t.Fatal(err)
	}
	shortInfo, err := os.Stat(want)
	if err != nil || !os.SameFile(longInfo, shortInfo) {
		t.Fatalf("native alias changed directory identity: %v", err)
	}
	d, err := NewDISM(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var invocations []platform.Invocation
	d.runner = dismRunnerFunc(func(_ context.Context, inv platform.Invocation, _ model.Emit) (platform.RunResult, error) {
		invocations = append(invocations, inv)
		return platform.RunResult{}, nil
	})
	if err := d.Mount(context.Background(), filepath.Join(w.Path(), "source.wim"), mount, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.offline(context.Background(), mount, nil, "/Get-Packages"); err != nil {
		t.Fatal(err)
	}
	if err := d.Unmount(context.Background(), mount, false, nil); err != nil {
		t.Fatal(err)
	}
	for i, prefix := range []string{"/MountDir:", "/Image:", "/MountDir:"} {
		found := false
		for _, arg := range invocations[i].Arguments {
			if strings.HasPrefix(arg, prefix) {
				found = true
				if arg != prefix+want {
					t.Fatalf("native invocation used %q; want verified alias %q", arg, prefix+want)
				}
			}
		}
		if !found {
			t.Fatalf("missing %s in native arguments %v", prefix, invocations[i].Arguments)
		}
	}
	foreign := mount
	foreign.DirectoryID.FileIndex++
	if _, err := mountPath(foreign); err == nil {
		t.Fatal("short-path lookup accepted an unowned directory identity")
	}
	t.Logf("same-object native alias shortened mount from %d to %d characters", len(strings.TrimPrefix(original, `\\?\`)), len(want))
}

func TestDISMRejectsStillUnsafeActualServicingStackPathBeforeProviderLaunch(t *testing.T) {
	w, err := platform.CreateWorkspace(t.TempDir(), "unsafe-cbs-path")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	mount, err := w.ClaimMount("mount", "service-image")
	if err != nil {
		t.Fatal(err)
	}
	stack := "mount/Windows/WinSxS/amd64_microsoft-windows-servicingstack_" + strings.Repeat("a", 180)
	if err := w.MkdirAll(stack); err != nil {
		t.Fatal(err)
	}
	f, err := w.OpenFile(stack+"/CbsCore.dll", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	d, err := NewDISM(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	launched := false
	d.runner = dismRunnerFunc(func(context.Context, platform.Invocation, model.Emit) (platform.RunResult, error) {
		launched = true
		return platform.RunResult{}, nil
	})
	_, err = d.offline(context.Background(), mount, nil, "/Add-Package", "/PackagePath:unused.msu")
	if launched || err == nil || !strings.Contains(err.Error(), "shorter") || !strings.Contains(err.Error(), "CbsCore.dll") {
		t.Fatalf("unsafe CBS path reached provider or lacked remedy: launched=%t error=%v", launched, err)
	}
}
