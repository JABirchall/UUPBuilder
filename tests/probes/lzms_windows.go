//go:build windows

package probes

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// nativeLZMS loads only the already measured/locked OS-owned cabinet.dll and
// calls documented fixed Compression API exports with bounded RAW LZMS data.
func nativeLZMS(ctx context.Context, path string, compressed []byte, size int) (output []byte, runErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(compressed) == 0 || len(compressed) > 1<<20 || size <= 0 || size > 1<<20 {
		return nil, errors.New("native LZMS input/output exceeds 1 MiB bound")
	}
	directory, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(filepath.Clean(path), filepath.Join(directory, "cabinet.dll")) {
		return nil, errors.New("native LZMS provider must be pinned System32 cabinet.dll")
	}
	library, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, err
	}
	defer func() { runErr = errors.Join(runErr, windows.FreeLibrary(library)) }()
	create, err := windows.GetProcAddress(library, "CreateDecompressor")
	if err != nil {
		return nil, err
	}
	decompress, err := windows.GetProcAddress(library, "Decompress")
	if err != nil {
		return nil, err
	}
	closeProc, err := windows.GetProcAddress(library, "CloseDecompressor")
	if err != nil {
		return nil, err
	}
	var handle uintptr
	success, _, callErr := syscall.SyscallN(create, 5|0x20000000, 0, uintptr(unsafe.Pointer(&handle)))
	if success == 0 {
		return nil, compressionError("CreateDecompressor", callErr)
	}
	defer func() {
		success, _, err := syscall.SyscallN(closeProc, handle)
		if success == 0 {
			runErr = errors.Join(runErr, compressionError("CloseDecompressor", err))
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	output = make([]byte, size)
	var actual uintptr
	success, _, callErr = syscall.SyscallN(decompress, handle, uintptr(unsafe.Pointer(&compressed[0])), uintptr(len(compressed)), uintptr(unsafe.Pointer(&output[0])), uintptr(len(output)), uintptr(unsafe.Pointer(&actual)))
	runtime.KeepAlive(compressed)
	runtime.KeepAlive(output)
	if success == 0 {
		return nil, compressionError("Decompress", callErr)
	}
	if actual != uintptr(size) {
		return nil, errors.New("native LZMS decompressed size mismatch")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return output, nil
}

func compressionError(api string, err syscall.Errno) error {
	if err == 0 {
		return fmt.Errorf("%s returned FALSE without error code", api)
	}
	return fmt.Errorf("%s: %w", api, err)
}
