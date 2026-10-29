package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
)

func (t *OwnedTree) checkTopology(ctx context.Context) error {
	if ctx == nil {
		return ErrTreePreserved
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := t.validate(); e != nil {
		return e
	}
	seen := map[string]bool{}
	links := map[FileIdentity]uint32{}
	var read, result, logical uint64
	chargeLogical := func(size uint64) error {
		if logical > t.limits.MaxLogicalBytes || size > t.limits.MaxLogicalBytes-logical {
			return ErrTreeLimit
		}
		logical += size
		return nil
	}
	checkStreams := func(v *treeEntry) error {
		info, e := nativeInfo(v.file)
		if e != nil {
			return e
		}
		actual := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
		if !v.directory {
			if e = chargeLogical(actual); e != nil {
				return e
			}
			if actual != v.size {
				return fmt.Errorf("%w: recorded file length changed", ErrTreePreserved)
			}
		}
		const size = 16 << 10
		if size > t.limits.MaxReadBytes-read || size > t.limits.MaxResultBytes-result {
			return ErrTreeLimit
		}
		read += size
		b := alignedNativeBuffer(size)
		e = windows.GetFileInformationByHandleEx(windows.Handle(v.file.Fd()), windows.FileStreamInfo, &b[0], uint32(len(b)))
		if errors.Is(e, windows.ERROR_HANDLE_EOF) {
			if v.directory && len(v.streams) == 0 {
				return nil
			}
			return ErrTreePreserved
		}
		if e != nil {
			return e
		}
		streams, e := parseStreams(b, 256)
		if e != nil {
			return e
		}
		seen := map[string]bool{}
		defaultSeen := false
		for _, s := range streams {
			name, e := safeStreamName(string(utf16.Decode(s.Name)))
			if e != nil {
				return e
			}
			if name != "" {
				key := strings.ToLower(name)
				if e = chargeLogical(s.Size); e != nil {
					return e
				}
				expected, exists := v.streams[key]
				if !exists || seen[key] || s.Size != expected {
					return ErrTreePreserved
				}
				seen[key] = true
			} else {
				if defaultSeen || !v.directory && s.Size != actual {
					return ErrTreePreserved
				}
				defaultSeen = true
			}
		}
		if len(seen) != len(v.streams) || !v.directory && !defaultSeen {
			return ErrTreePreserved
		}
		return nil
	}
	if e := checkStreams(&treeEntry{file: t.root, directory: true}); e != nil {
		return errors.Join(ErrTreePreserved, e)
	}
	for _, v := range t.entries {
		if !v.directory {
			links[v.id]++
		}
	}
	var walk func(string, *os.File) error
	walk = func(prefix string, dir *os.File) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		names, e := treeNames(ctx, dir, t.limits, &read, &result)
		if e != nil {
			return e
		}
		if len(names) > t.limits.MaxEntries {
			return ErrTreeLimit
		}
		for _, leaf := range names {
			name := leaf
			if prefix != "" {
				name = prefix + "/" + leaf
			}
			n, e := treeName(name, t.limits.MaxDepth)
			if e != nil {
				return e
			}
			key := strings.ToLower(n)
			v := t.entries[key]
			if v == nil || seen[key] {
				return ErrTreePreserved
			}
			seen[key] = true
			f, e := nativeTreeOpen(windows.Handle(dir.Fd()), leaf, windows.FILE_GENERIC_READ, windows.FILE_OPEN, 0, nil)
			if e != nil {
				return e
			}
			i, e := nativeInfo(f)
			e = errors.Join(e, f.Close())
			if e != nil {
				return e
			}
			if nativeIdentity(i) != v.id || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (i.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != v.directory || !v.directory && i.NumberOfLinks != links[v.id] {
				return ErrTreePreserved
			}
			if e := checkStreams(v); e != nil {
				return e
			}
			if v.directory {
				if e := walk(n, v.file); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if e := walk("", t.root); e != nil {
		return errors.Join(ErrTreePreserved, e)
	}
	if len(seen) != len(t.entries) {
		return ErrTreePreserved
	}
	if logical != t.logical {
		return fmt.Errorf("%w: logical-byte ledger total changed", ErrTreePreserved)
	}
	return nil
}

// FILE_ID_BOTH_DIR_INFO has fixed 104-byte framing and counted UTF-16 names.
// RestartInfo restarts this exact held directory's enumeration; it needs no
// path reopen and never resolves a returned child until its name is validated.
func treeNames(ctx context.Context, f *os.File, l TreeLimits, read, result *uint64) ([]string, error) {
	var names []string
	class := uint32(windows.FileIdBothDirectoryRestartInfo)
	for {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		const size = 64 << 10
		if size > l.MaxReadBytes-*read || size > l.MaxResultBytes-*result {
			return nil, ErrTreeLimit
		}
		*read += size
		b := alignedNativeBuffer(size)
		e := windows.GetFileInformationByHandleEx(windows.Handle(f.Fd()), class, &b[0], uint32(len(b)))
		if errors.Is(e, windows.ERROR_NO_MORE_FILES) {
			return names, nil
		}
		if e != nil {
			return nil, fmt.Errorf("directory information class %d: %w", class, e)
		}
		for off := 0; ; {
			if off > len(b)-104 {
				return nil, ErrTreePreserved
			}
			v := b[off:]
			next, n := binary.LittleEndian.Uint32(v), binary.LittleEndian.Uint32(v[60:])
			if n == 0 || n%2 != 0 || n > 8192 || uint64(n) > uint64(len(v)-104) || next != 0 && (next%8 != 0 || next < 104+n || uint64(next) > uint64(len(v)-104)) {
				return nil, ErrTreePreserved
			}
			if uint64(n)*4+128 > l.MaxResultBytes-*result {
				return nil, ErrTreeLimit
			}
			*result += uint64(n)*4 + 128
			u := make([]uint16, n/2)
			for j := range u {
				u[j] = binary.LittleEndian.Uint16(v[104+j*2:])
			}
			name := string(utf16.Decode(u))
			if name != "." && name != ".." {
				if len(names) >= l.MaxEntries {
					return nil, ErrTreeLimit
				}
				if _, e := treeName(name, 1); e != nil {
					return nil, e
				}
				names = append(names, name)
			}
			if next == 0 {
				break
			}
			off += int(next)
		}
		class = windows.FileIdBothDirectoryInfo
	}
}

// Cleanup proves actual lengths, namespace and internal link equivalence.
// File-containing scopes are deliberately preserved: per-stream sharing pins
// stabilize the recorded objects, but do not establish an atomic complete stream
// namespace through deletion. Only proven directory-only trees can be removed.
func (t *OwnedTree) Cleanup(ctx context.Context) error {
	if t == nil {
		return ErrTreePreserved
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.checkTopology(ctx); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return errors.Join(ErrTreePreserved, e)
	}
	for _, v := range t.entries {
		if !v.directory {
			return fmt.Errorf("%w: %s [volume=%d file=%d]: file-containing cleanup is unimplemented; whole stream namespace cannot be stabilized", ErrTreePreserved, t.identity.RelativePath, t.identity.Root.VolumeSerial, t.identity.Root.FileIndex)
		}
	}
	names := make([]string, 0, len(t.entries))
	for n := range t.entries {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, n := range names {
		if e := ctx.Err(); e != nil {
			return errors.Join(ErrTreePreserved, e)
		}
		v := t.entries[n]
		info, e := nativeInfo(v.file)
		if e != nil || !v.directory || nativeIdentity(info) != v.id || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.Join(ErrTreePreserved, e)
		}
		parent, leaf, e := t.parent(n)
		if e != nil {
			return e
		}
		if e = v.file.Close(); e != nil {
			return errors.Join(ErrTreePreserved, e)
		}
		deletion, e := t.openRemoval(windows.Handle(parent.Fd()), leaf, true)
		if e != nil {
			return errors.Join(ErrTreePreserved, e)
		}
		got, e := nativeInfo(deletion)
		if e != nil || nativeIdentity(got) != v.id || got.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.Join(ErrTreePreserved, e, deletion.Close())
		}
		if e := deleteHeld(deletion); e != nil {
			return errors.Join(ErrTreePreserved, fmt.Errorf("delete exact held directory %s: %w", n, e), deletion.Close())
		}
		if e := deletion.Close(); e != nil {
			return errors.Join(ErrTreePreserved, e)
		}
		delete(t.entries, n)
	}
	t.logical = 0
	t.resultBytes = 4096
	return nil
}

func (t *OwnedTree) RemoveEmpty(ctx context.Context) (runErr error) {
	if t == nil {
		return ErrTreePreserved
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.removed {
		return t.closeErr
	}
	if e := t.checkTopology(ctx); e != nil {
		return e
	}
	if len(t.entries) != 0 {
		return ErrTreePreserved
	}
	// Release the no-delete-sharing directory pin only after a complete empty
	// proof; reopen one leaf beneath the retained parent and check its identity
	// before marking that exact object for deletion. A race preserves/refuses.
	if e := t.root.Close(); e != nil {
		return errors.Join(ErrTreePreserved, e)
	}
	t.closed = true
	t.root = nil
	defer func() {
		for _, p := range t.parents {
			runErr = errors.Join(runErr, p.Close())
		}
		t.parents = nil
		t.closeErr = errors.Join(t.closeErr, runErr)
	}()
	parent := t.parents[len(t.parents)-1]
	f, e := t.openRemoval(windows.Handle(parent.Fd()), filepath.Base(t.identity.RelativePath), true)
	if e != nil {
		t.closeErr = errors.Join(ErrTreePreserved, e)
		return t.closeErr
	}
	i, e := nativeInfo(f)
	if e != nil || nativeIdentity(i) != t.identity.Root || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.closeErr = errors.Join(ErrTreePreserved, e, f.Close())
		return t.closeErr
	}
	e = deleteHeld(f)
	t.closeErr = errors.Join(e, f.Close())
	if t.closeErr != nil {
		t.closeErr = errors.Join(ErrTreePreserved, t.closeErr)
		return t.closeErr
	}
	t.removed = true
	return t.closeErr
}
