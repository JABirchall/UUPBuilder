package windows

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"strings"
	"unsafe"
)

func nativeTreeOpen(parent windows.Handle, name string, access, disposition, options uint32, sd *windows.SECURITY_DESCRIPTOR) (*os.File, error) {
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	if disposition == windows.FILE_CREATE {
		share &^= windows.FILE_SHARE_DELETE
	}
	return nativeTreeOpenShared(parent, name, access, disposition, options, share, sd)
}

func nativeTreeOpenShared(parent windows.Handle, name string, access, disposition, options, share uint32, sd *windows.SECURITY_DESCRIPTOR) (*os.File, error) {
	u, e := windows.NewNTUnicodeString(name)
	if e != nil {
		return nil, e
	}
	a := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: u, Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: sd}
	a.Length = uint32(unsafe.Sizeof(a))
	var h windows.Handle
	e = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &a, &windows.IO_STATUS_BLOCK{}, nil, windows.FILE_ATTRIBUTE_NORMAL, share, disposition, options|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	if s, ok := e.(windows.NTStatus); ok {
		e = s.Errno()
	}
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), name), nil
}

func nativeInfo(f *os.File) (windows.ByHandleFileInformation, error) {
	var i windows.ByHandleFileInformation
	if f == nil {
		return i, os.ErrClosed
	}
	e := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &i)
	return i, e
}

func nativeIdentity(i windows.ByHandleFileInformation) FileIdentity {
	return FileIdentity{i.VolumeSerialNumber, uint64(i.FileIndexHigh)<<32 | uint64(i.FileIndexLow)}
}

func treeWorkspaceOwner(w *Workspace) (FileIdentity, error) {
	root, e := w.root.Open(".")
	if e != nil {
		return FileIdentity{}, errors.Join(ErrTreePreserved, e)
	}
	f, e := nativeTreeOpen(windows.Handle(root.Fd()), ownerFile, windows.FILE_GENERIC_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
	rootErr := root.Close()
	if e != nil {
		return FileIdentity{}, errors.Join(ErrTreePreserved, e, rootErr)
	}
	i, e := nativeInfo(f)
	if e != nil || i.NumberOfLinks != 1 || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return FileIdentity{}, errors.Join(ErrTreePreserved, e, f.Close())
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	e = errors.Join(e, rootErr, f.Close())
	var id WorkspaceIdentity
	if e != nil || len(b) > 4096 || json.Unmarshal(b, &id) != nil || id != w.Identity() {
		return FileIdentity{}, errors.Join(ErrTreePreserved, e)
	}
	return nativeIdentity(i), nil
}

func treeParent(w *Workspace, path string) (*os.File, []*os.File, error) {
	f, e := w.root.Open(".")
	if e != nil {
		return nil, nil, e
	}
	held := []*os.File{f}
	fail := func(e error) (*os.File, []*os.File, error) {
		for _, p := range held {
			e = errors.Join(e, p.Close())
		}
		return nil, nil, e
	}
	if path == "." {
		return f, held, nil
	}
	for _, part := range strings.Split(path, "/") {
		next, e := nativeTreeOpenShared(windows.Handle(f.Fd()), part, windows.FILE_GENERIC_READ, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil)
		if e != nil {
			return fail(e)
		}
		held = append(held, next)
		i, e := nativeInfo(next)
		if e != nil || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fail(errors.Join(ErrTreePreserved, e))
		}
		f = next
	}
	return f, held, nil
}

func alignedNativeBuffer(size int) []byte {
	storage := make([]byte, size+7)
	offset := int((-uintptr(unsafe.Pointer(&storage[0]))) & 7)
	return storage[offset : offset+size]
}

func deleteHeld(f *os.File) error {
	b := byte(1)
	return windows.SetFileInformationByHandle(windows.Handle(f.Fd()), windows.FileDispositionInfo, &b, 1)
}

func (t *OwnedTree) openRemoval(parent windows.Handle, leaf string, dir bool) (*os.File, error) {
	if t.reopenRemoval != nil {
		return t.reopenRemoval(parent, leaf, dir)
	}
	options := uint32(windows.FILE_NON_DIRECTORY_FILE)
	if dir {
		options = windows.FILE_DIRECTORY_FILE
	}
	return nativeTreeOpen(parent, leaf, windows.DELETE|windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, options, nil)
}
