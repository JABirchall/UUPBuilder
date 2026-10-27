//go:build windows

package jobstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DISM inventory covers DISM-mounted images only. Store separately rejects
// unresolved reparse/volume topology, so an empty array alone is never used as
// permission to delete a tree. No image session or mutating API is called here.
// See Microsoft's DismGetMountedImageInfo/DismMountedImageInfo documentation.
type nativeMountInspector struct{}

var dismInventoryMu sync.Mutex
var dismAPI = windows.NewLazySystemDLL("DismApi.dll") // x/sys restricts loading to System32.

// C UINT/enums are 32 bits; pointer fields use the process ABI's natural
// alignment on 386, amd64 and arm64. No W1 native rename/mount ABI is duplicated.
type dismMountedImageInfo struct {
	MountPath     *uint16
	ImageFilePath *uint16
	ImageIndex    uint32
	MountMode     uint32
	MountStatus   uint32
}

func nativeWideString(p *uint16) (string, error) {
	if p == nil {
		return "", errors.New("nil DISM mount path")
	}
	units := make([]uint16, 0, 256)
	for i := 0; i < 32768; i++ {
		unit := *(*uint16)(unsafe.Add(unsafe.Pointer(p), uintptr(i)*2))
		if unit == 0 {
			if len(units) == 0 {
				return "", errors.New("empty DISM mount path")
			}
			return windows.UTF16ToString(units), nil
		}
		units = append(units, unit)
	}
	return "", errors.New("DISM mount path exceeds Windows path bound")
}
func hresult(op string, value uintptr) error {
	return fmt.Errorf("%s HRESULT 0x%08x; actual mount state is unknown", op, uint32(value))
}

func (nativeMountInspector) Inspect(ctx context.Context, _ string) (snapshot MountSnapshot, err error) {
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	dismInventoryMu.Lock()
	defer dismInventoryMu.Unlock()
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	initialize := dismAPI.NewProc("DismInitialize")
	query := dismAPI.NewProc("DismGetMountedImageInfo")
	deleteInfo := dismAPI.NewProc("DismDelete")
	shutdown := dismAPI.NewProc("DismShutdown")
	for _, proc := range []*windows.LazyProc{initialize, query, deleteInfo, shutdown} {
		if err := proc.Find(); err != nil {
			return snapshot, fmt.Errorf("system DISM inventory unavailable: %w", err)
		}
	}
	// Initialize exactly our own API lifetime. If another component initialized
	// DISM, preserve unknown state rather than shutting down its sessions.
	hr, _, _ := initialize.Call(0, 0, 0)
	if uint32(hr) != 0 {
		return snapshot, hresult("DismInitialize", hr)
	}
	defer func() {
		hr, _, _ := shutdown.Call()
		if uint32(hr) != 0 {
			snapshot.Complete = false
			err = errors.Join(err, hresult("DismShutdown", hr))
		}
	}()
	var array *dismMountedImageInfo
	var count uint32
	hr, _, _ = query.Call(uintptr(unsafe.Pointer(&array)), uintptr(unsafe.Pointer(&count)))
	if array != nil {
		defer func() {
			hr, _, _ := deleteInfo.Call(uintptr(unsafe.Pointer(array)))
			if uint32(hr) != 0 {
				snapshot.Complete = false
				err = errors.Join(err, hresult("DismDelete", hr))
			}
		}()
	}
	if uint32(hr) != 0 {
		return snapshot, hresult("DismGetMountedImageInfo", hr)
	}
	if count > 4096 || count > 0 && array == nil {
		return snapshot, errors.New("invalid or unbounded DISM inventory")
	}
	if count > 0 {
		for _, record := range unsafe.Slice(array, int(count)) {
			if err := ctx.Err(); err != nil {
				return snapshot, err
			}
			path, err := nativeWideString(record.MountPath)
			if err != nil {
				return snapshot, err
			}
			if record.MountMode > 1 || record.MountStatus > 2 || record.ImageIndex == 0 {
				return snapshot, errors.New("unknown DISM mount metadata")
			}
			if _, err := normalizedAbsolute(path); err != nil {
				return snapshot, err
			}
			// Invalid/remount-required entries are still mounted resources to retain.
			snapshot.Mounts = append(snapshot.Mounts, MountObservation{Path: path, State: MountMounted})
		}
	}
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	snapshot.Complete = true
	return snapshot, nil
}
