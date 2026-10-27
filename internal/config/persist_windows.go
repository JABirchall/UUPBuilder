//go:build windows

package config

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var setFileInformationByHandle = syscall.NewLazyDLL("kernel32.dll").NewProc("SetFileInformationByHandle")

// replaceFile uses a single native rename metadata operation. In contrast to
// ReplaceFileW, it cannot partially move the original while merging metadata;
// there is no delete/copy fallback. The source is always a same-directory temp.
// FileRenameInfo is supported from Vista onward (before our Windows 10 floor).
func replaceFile(source, destination string, replaceExisting bool) error {
	fail := func(err error) error {
		return &os.LinkError{Op: "rename config", Old: source, New: destination, Err: err}
	}
	src, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return fail(err)
	}
	dst, err := syscall.UTF16FromString(destination)
	if err != nil {
		return fail(err)
	}
	const deleteAccess = 0x00010000
	handle, err := syscall.CreateFile(src, deleteAccess, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fail(err)
	}
	defer syscall.CloseHandle(handle)
	// Native alignment differs on 386 and 64-bit targets. Derive the filename
	// offset from the Go struct rather than assuming a fixed wire header size.
	type renameInfo struct {
		ReplaceIfExists uint32
		RootDirectory   syscall.Handle
		FileNameLength  uint32
		FileName        [1]uint16
	}
	var layout renameInfo
	offset := int(unsafe.Offsetof(layout.FileName))
	filename := dst[:len(dst)-1]
	buffer := make([]byte, offset+2*len(filename))
	info := (*renameInfo)(unsafe.Pointer(&buffer[0]))
	if replaceExisting {
		info.ReplaceIfExists = 1
	}
	info.FileNameLength = uint32(2 * len(filename))
	copy(unsafe.Slice(&info.FileName[0], len(filename)), filename)
	const fileRenameInfo = 3
	ok, _, callErr := setFileInformationByHandle.Call(uintptr(handle), fileRenameInfo, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	runtime.KeepAlive(buffer)
	if ok == 0 {
		return fail(callErr)
	}
	return nil
}
