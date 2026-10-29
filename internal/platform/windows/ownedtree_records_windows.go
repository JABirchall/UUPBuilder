package windows

import (
	"context"
	"errors"
	"io"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CreateHardlink creates a second explicitly owned name for a held synthetic
// file. Equal content bytes alone never grant link-group authority.
func (t *OwnedTree) CreateHardlink(ctx context.Context, original, name string) error {
	if t == nil || ctx == nil {
		return ErrTreePreserved
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := t.validate(); e != nil {
		return e
	}
	source, e := t.entry(original)
	if e != nil || source.directory || source.alias {
		return ErrTreePreserved
	}
	info, e := nativeInfo(source.file)
	knownLinks := uint32(0)
	for _, entry := range t.entries {
		if entry.id == source.id && !entry.directory {
			knownLinks++
		}
	}
	if e != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != knownLinks {
		return errors.Join(ErrTreePreserved, e)
	}
	n, e := treeName(name, t.limits.MaxDepth)
	if e != nil {
		return e
	}
	key := strings.ToLower(n)
	cost := uint64(1024 + len(n)*4)
	// Logical bytes count every named file, including each hardlink alias, and
	// every named stream attached to that name. This is not physical allocation.
	logical := source.size
	for _, size := range source.streams {
		if logical > t.limits.MaxLogicalBytes || size > t.limits.MaxLogicalBytes-logical {
			return ErrTreeLimit
		}
		logical += size
	}
	if t.entries[key] != nil || len(t.entries) >= t.limits.MaxEntries || t.logical > t.limits.MaxLogicalBytes || logical > t.limits.MaxLogicalBytes-t.logical || cost > t.limits.MaxResultBytes-t.resultBytes {
		return ErrTreeLimit
	}
	parent, leaf, e := t.parent(n)
	if e != nil {
		return e
	}
	u, e := windows.UTF16FromString(leaf)
	if e != nil {
		return e
	}
	u = u[:len(u)-1]
	// FILE_LINK_INFORMATION uses the same native alignment as rename framing.
	type linkInfo struct {
		Replace uint32
		Root    windows.Handle
		Length  uint32
		Name    [1]uint16
	}
	var layout linkInfo
	offset := int(unsafe.Offsetof(layout.Name))
	b := alignedNativeBuffer(max(int(unsafe.Sizeof(layout)), offset+len(u)*2))
	v := (*linkInfo)(unsafe.Pointer(&b[0]))
	v.Root = windows.Handle(parent.Fd())
	v.Length = uint32(len(u) * 2)
	copy(unsafe.Slice(&v.Name[0], len(u)), u)
	if e = windows.NtSetInformationFile(windows.Handle(source.file.Fd()), &windows.IO_STATUS_BLOCK{}, &b[0], uint32(len(b)), 11); e != nil {
		return e
	}
	// Record the created namespace before the fallible independent identity open.
	entry := &treeEntry{id: source.id, size: source.size, alias: true, streams: source.streams}
	t.entries[key] = entry
	t.resultBytes += cost
	t.logical += logical
	// This read handle must consent to the source writer's write/delete access.
	// It is an exact object reference, not an independent alias namespace pin.
	// Cleanup consequently preserves every file-containing scope.
	f, e := nativeTreeOpen(windows.Handle(parent.Fd()), leaf, windows.FILE_GENERIC_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
	if e != nil {
		return errors.Join(ErrTreePreserved, e)
	}
	entry.file = f
	i, e := nativeInfo(f)
	if e != nil || nativeIdentity(i) != entry.id {
		return errors.Join(ErrTreePreserved, e)
	}
	return ctx.Err()
}

// CreateNamedStream accepts only one validated name and a held unshared file.
// Colon syntax is assembled privately after path/stream validation.
func (t *OwnedTree) CreateNamedStream(ctx context.Context, name, stream string, data []byte) error {
	if t == nil || ctx == nil {
		return ErrTreePreserved
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := t.validate(); e != nil {
		return e
	}
	n, e := treeName(name, t.limits.MaxDepth)
	if e != nil {
		return e
	}
	v, e := t.entry(n)
	if e != nil || v.directory {
		return ErrTreePreserved
	}
	if len(stream) > 1024 {
		return ErrTreeLimit
	}
	s, e := safeStreamName(":" + stream + ":$DATA")
	if e != nil || s == "" {
		return ErrTreePreserved
	}
	info, e := nativeInfo(v.file)
	if e != nil || info.NumberOfLinks != 1 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(ErrTreePreserved, e)
	}
	cost := uint64(1024 + len(s)*4)
	if len(v.streams) >= 256 || uint64(len(data)) > t.limits.MaxLogicalBytes-t.logical || cost > t.limits.MaxResultBytes-t.resultBytes {
		return ErrTreeLimit
	}
	if _, exists := v.streams[strings.ToLower(s)]; exists {
		return ErrTreePreserved
	}
	p, leaf, e := t.parent(n)
	if e != nil {
		return e
	}
	// Sharing is per stream. Keep this recorded stream write-stable while
	// consenting to the already-held default stream's DELETE access.
	f, e := nativeTreeOpenShared(windows.Handle(p.Fd()), leaf+":"+s+":$DATA", windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE, windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil)
	if e != nil {
		return e
	}
	v.streamFiles = append(v.streamFiles, f)
	t.resultBytes += cost
	v.streams[strings.ToLower(s)] = uint64(len(data))
	t.logical += uint64(len(data))
	actual, e := nativeInfo(f)
	if e != nil || nativeIdentity(actual) != v.id {
		return errors.Join(ErrTreePreserved, e)
	}
	nw, e := f.Write(data)
	if e != nil || nw != len(data) {
		return errors.Join(ErrTreePreserved, e, io.ErrShortWrite)
	}
	if e = f.Sync(); e != nil {
		return errors.Join(ErrTreePreserved, e)
	}
	return ctx.Err()
}

func (t *OwnedTree) create(ctx context.Context, name string, data []byte, dir bool) error {
	if ctx == nil {
		return ErrTreePreserved
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := t.validate(); e != nil {
		return e
	}
	n, e := treeName(name, t.limits.MaxDepth)
	if e != nil {
		return e
	}
	cost := uint64(1024 + len(n)*4)
	if len(t.entries) >= t.limits.MaxEntries || uint64(len(data)) > t.limits.MaxLogicalBytes-t.logical || cost > t.limits.MaxResultBytes-t.resultBytes {
		return ErrTreeLimit
	}
	key := strings.ToLower(n)
	if t.entries[key] != nil {
		return ErrTreePreserved
	}
	p, leaf, e := t.parent(n)
	if e != nil {
		return e
	}
	options := uint32(windows.FILE_NON_DIRECTORY_FILE)
	if dir {
		options = windows.FILE_DIRECTORY_FILE
	}
	share := uint32(windows.FILE_SHARE_READ)
	if dir {
		share |= windows.FILE_SHARE_WRITE
	}
	access := uint32(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE)
	if !dir {
		access |= windows.DELETE
	}
	f, e := nativeTreeOpenShared(windows.Handle(p.Fd()), leaf, access, windows.FILE_CREATE, options, share, nil)
	if e != nil {
		return e
	}
	// The ordinary file handle denies compatible write/delete opens through
	// proof/refusal. Do not infer independent alias or whole-stream custody.
	v := &treeEntry{file: f, directory: dir, size: uint64(len(data)), streams: map[string]uint64{}}
	// Retain the scope and exact acquired handle before any fallible descendant IO.
	t.entries[key] = v
	t.resultBytes += cost
	t.logical += uint64(len(data))
	i, e := nativeInfo(f)
	if e != nil {
		return errors.Join(ErrTreePreserved, e)
	}
	v.id = nativeIdentity(i)
	if len(data) > 0 {
		n, e := f.Write(data)
		if e != nil || n != len(data) {
			return errors.Join(ErrTreePreserved, e, io.ErrShortWrite)
		}
	}
	if !dir {
		if e = f.Sync(); e != nil {
			return errors.Join(ErrTreePreserved, e)
		}
	}
	return ctx.Err()
}
