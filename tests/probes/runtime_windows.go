//go:build windows

package probes

import (
	"context"
	"debug/pe"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

func newRuntimePorts(observe func() (ObservedHost, error)) runtimePorts {
	runner := platform.NewRunner()
	return runtimePorts{kind: "component-runtime", observe: observe,
		createWorkspace:  func(parent, id string) (proofWorkspace, error) { return platform.CreateWorkspace(parent, id) },
		fileSystem:       platform.InspectFileSystem,
		openComponent:    openNativeSystemComponent,
		decompress:       nativeLZMS,
		privateWorkspace: func(w proofWorkspace) any { return w.(*platform.Workspace).Identity() },
		run: func(ctx context.Context, w proofWorkspace, request directRequest, emit model.Emit) (processResult, error) {
			owned, ok := w.(*platform.Workspace)
			if !ok {
				return processResult{}, errors.New("real adapter requires W1 owned Workspace")
			}
			result, err := runner.Run(ctx, platform.Invocation{Executable: request.Executable, Arguments: request.Arguments, Workspace: owned, JobID: owned.Identity().JobID, OperationID: request.ID, Cancellation: platform.CancelTerminateTree}, emit)
			return processResult{result.ProcessID, result.ExitCode, result.Stdout, result.Stderr, result.Cancelled}, err
		},
	}
}

func openNativeSystemComponent(name string, arch model.Architecture) (*os.File, string, error) {
	if !oneOf(name, "expand.exe", "certutil.exe", "cabinet.dll") {
		return nil, "", errors.New("component is outside the fixed native system recipe")
	}
	directory, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(directory, name)
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, "", err
	}
	// Retain a read-only handle denying write/delete sharing throughout the
	// invocation. Hashing, PE inspection and retained copying use this object.
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(handle), path)
	image, err := pe.NewFile(file)
	if err != nil {
		file.Close()
		return nil, "", err
	}
	defer image.Close()
	want := map[model.Architecture]uint16{"x86": 0x14c, "amd64": 0x8664, "arm64": 0xaa64}[arch]
	if want == 0 || image.Machine != want {
		file.Close()
		return nil, "", fmt.Errorf("native component machine %#x does not match %s", image.Machine, arch)
	}
	return file, path, nil
}
