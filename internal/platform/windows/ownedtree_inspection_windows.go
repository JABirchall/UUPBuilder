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
	var read, result uint64
	checkStreams := func(v *treeEntry) error {
		const size = 16 << 10
		if size > t.limits.MaxReadBytes-read || size > t.limits.MaxResultBytes-result {
			return ErrTreeLimit
		}
		read += size
		b := alignedNativeBuffer(size)
		e := windows.GetFileInformationByHandleEx(windows.Handle(v.file.Fd()), windows.FileStreamInfo, &b[0], uint32(len(b)))
		if errors.Is(e, windows.ERROR_HANDLE_EOF) {
			return nil
		}
		if e != nil {
			return e
		}
		streams, e := parseStreams(b, 256)
		if e != nil {
			return e
		}
		seen := map[string]bool{}
		for _, s := range streams {
			name, e := safeStreamName(string(utf16.Decode(s.Name)))
			if e != nil {
				return e
			}
			if name != "" {
				key := strings.ToLower(name)
				if !v.streams[key] || seen[key] {
					return ErrTreePreserved
				}
				seen[key] = true
			}
		}
		if len(seen) != len(v.streams) {
			return ErrTreePreserved
		}
		return nil
	}
	if e := checkStreams(&treeEntry{file: t.root}); e != nil {
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

// Cleanup first proves the complete namespace and internal link equivalence.
// It then deletes only exact held objects, never recursively deleting a path.
// Reparse points and any unknown, foreign, replaced or linked-outside object
// preserve the entire scope before the first deletion.
func (t *OwnedTree) Cleanup(ctx context.Context) error {
	if t == nil {
		return ErrTreePreserved
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.checkTopology(ctx); e != nil {
		return e
	}
	names := make([]string, 0, len(t.entries))
	for n := range t.entries {
		names = append(names, n)
	}
	rank := func(n string) int {
		v := t.entries[n]
		if v.directory {
			return 2
		}
		if v.alias {
			return 1
		}
		return 0
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := rank(names[i]), rank(names[j])
		if a != b {
			return a < b
		}
		return len(names[i]) > len(names[j])
	})
	for _, n := range names {
		if e := ctx.Err(); e != nil {
			return errors.Join(ErrTreePreserved, e)
		}
		v := t.entries[n]
		info, e := nativeInfo(v.file)
		links := uint32(0)
		for _, other := range t.entries {
			if other.id == v.id && !other.directory {
				links++
			}
		}
		if e != nil || nativeIdentity(info) != v.id || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || !v.directory && info.NumberOfLinks != links {
			return errors.Join(ErrTreePreserved, e)
		}
		for _, f := range v.streamFiles {
			if e := f.Close(); e != nil {
				return errors.Join(ErrTreePreserved, e)
			}
		}
		v.streamFiles = nil
		deletion := v.file
		if v.alias || v.directory {
			parent, leaf, e := t.parent(n)
			if e != nil {
				return e
			}
			if v.directory {
				if e = v.file.Close(); e != nil {
					return errors.Join(ErrTreePreserved, e)
				}
			}
			options := uint32(windows.FILE_NON_DIRECTORY_FILE)
			if v.directory {
				options = windows.FILE_DIRECTORY_FILE
			}
			deletion, e = nativeTreeOpen(windows.Handle(parent.Fd()), leaf, windows.DELETE|windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, options, nil)
			if e != nil {
				return errors.Join(ErrTreePreserved, e)
			}
			got, e := nativeInfo(deletion)
			if e != nil || nativeIdentity(got) != v.id {
				deletion.Close()
				return errors.Join(ErrTreePreserved, e)
			}
		}
		if e := deleteHeld(deletion); e != nil {
			if deletion != v.file {
				deletion.Close()
			}
			return errors.Join(ErrTreePreserved, fmt.Errorf("delete exact held entry %s: %w", n, e))
		}
		if deletion != v.file {
			if e := deletion.Close(); e != nil {
				return errors.Join(ErrTreePreserved, e)
			}
		}
		if !v.directory {
			if e := v.file.Close(); e != nil {
				return errors.Join(ErrTreePreserved, e)
			}
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
