package windows

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

type InventoryEntry struct {
	Path, Status   string
	Identity       FileIdentity
	LedgerIdentity FileIdentity
	Attributes     uint32
	NativeCode     uint32
	// Read-only sessions retain independent observed identity, never a fixture
	// creation ledger. Preserve it and the available cause on known-entry failure.
	RetainedIdentity FileIdentity
	Failure          string
}
type TreeInventory struct {
	Tree                      TreeIdentity
	Entries                   []InventoryEntry
	ReadBytes, AccountedBytes uint64
	Complete                  bool
}

// CheckObservationLive rechecks the borrowed owner/root lifetime. It does not
// assert atomic metadata or ADS namespace stability.
func (t *OwnedTree) CheckObservationLive(ctx context.Context) error {
	if t == nil || ctx == nil {
		return ErrTreePreserved
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	return t.validate()
}

// ObserveInventory enumerates actual names from held directories, then checks
// them against the created-entry ledger. Unknown names are evidence, never
// adopted/opened/traversed. This is a bounded non-atomic observation; callers
// must recheck it after content/metadata reads. No cleanup is performed.
func (t *OwnedTree) ObserveInventory(ctx context.Context, limits TreeLimits) (out TreeInventory, err error) {
	defer func() {
		if err != nil {
			out.Complete = false
		}
	}()
	if t == nil || ctx == nil {
		return out, ErrTreePreserved
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	l, e := treeBounds(limits)
	if e != nil {
		return out, e
	}
	l.MaxEntries = min(l.MaxEntries, t.limits.MaxEntries)
	l.MaxDepth = min(l.MaxDepth, t.limits.MaxDepth)
	l.MaxReadBytes = min(l.MaxReadBytes, t.limits.MaxReadBytes)
	l.MaxResultBytes = min(l.MaxResultBytes, t.limits.MaxResultBytes)
	if e = ctx.Err(); e != nil {
		return out, e
	}
	if e = t.validate(); e != nil {
		return out, e
	}
	if l.MaxResultBytes < 4096 {
		return out, ErrTreeLimit
	}
	out.Tree = t.identity
	out.AccountedBytes = 4096
	out.Complete = true
	seen := make(map[string]bool)
	add := func(name, status string, id FileIdentity, attrs uint32) error {
		cost := uint64(512 + len(name)*4)
		if len(out.Entries) >= l.MaxEntries+1 || cost > l.MaxResultBytes-out.AccountedBytes {
			return ErrTreeLimit
		}
		out.AccountedBytes += cost
		out.Entries = append(out.Entries, InventoryEntry{Path: name, Status: status, Identity: id, Attributes: attrs})
		if status != "known" {
			out.Complete = false
		}
		return nil
	}
	if e = add(".", "known", t.identity.Root, windows.FILE_ATTRIBUTE_DIRECTORY); e != nil {
		return out, e
	}
	out.Entries[0].LedgerIdentity = t.identity.Root
	var walk func(string, *os.File, int) error
	walk = func(prefix string, dir *os.File, depth int) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if depth > l.MaxDepth {
			return ErrTreeLimit
		}
		before, e := nativeInfo(dir)
		if e != nil {
			return e
		}
		names, e := treeNames(ctx, dir, l, &out.ReadBytes, &out.AccountedBytes)
		if e != nil {
			return e
		}
		for _, leaf := range names {
			if e := ctx.Err(); e != nil {
				return e
			}
			// Charge the joined path and map key before either allocation.
			cost := uint64(256 + (len(prefix)+len(leaf)+1)*8)
			if cost > l.MaxResultBytes-out.AccountedBytes {
				return ErrTreeLimit
			}
			out.AccountedBytes += cost
			name := leaf
			if prefix != "" {
				name = prefix + "/" + leaf
			}
			n, e := treeName(name, l.MaxDepth)
			if e != nil {
				return e
			}
			key := strings.ToLower(n)
			v := t.entries[key]
			if seen[key] {
				if e = add(name, "duplicate", FileIdentity{}, 0); e != nil {
					return e
				}
				continue
			}
			seen[key] = true
			if v == nil {
				if e = add(name, "unknown", FileIdentity{}, 0); e != nil {
					return e
				}
				continue
			}
			f, e := nativeTreeOpen(windows.Handle(dir.Fd()), leaf, windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, 0, nil)
			if e != nil {
				code := fieldError(e).NativeCode
				if e = add(name, "denied", FileIdentity{}, 0); e != nil {
					return e
				}
				out.Entries[len(out.Entries)-1].NativeCode = code
				out.Entries[len(out.Entries)-1].LedgerIdentity = v.id
				continue
			}
			i, e := nativeInfo(f)
			e = errors.Join(e, f.Close())
			if e != nil {
				if e = add(name, "failed", FileIdentity{}, 0); e != nil {
					return e
				}
				continue
			}
			status := "known"
			if nativeIdentity(i) != v.id || (i.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != v.directory {
				status = "changed"
			}
			if i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				status = "reparse"
			}
			if e = add(name, status, nativeIdentity(i), i.FileAttributes); e != nil {
				return e
			}
			out.Entries[len(out.Entries)-1].LedgerIdentity = v.id
			if status == "known" && v.directory {
				held, e := nativeInfo(v.file)
				if e != nil || nativeIdentity(held) != v.id {
					return errors.Join(ErrTreePreserved, e)
				}
				if e = walk(n, v.file, depth+1); e != nil {
					return e
				}
			}
		}
		after, e := nativeInfo(dir)
		if e != nil || after != before {
			return errors.Join(ErrTreePreserved, e)
		}
		return nil
	}
	if e = walk("", t.root, 1); e != nil {
		return out, e
	}
	for n, v := range t.entries {
		if !seen[n] {
			if e = add(n, "missing", v.id, 0); e != nil {
				return out, e
			}
			out.Entries[len(out.Entries)-1].LedgerIdentity = v.id
		}
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Path < out.Entries[j].Path })
	if e = ctx.Err(); e != nil {
		return out, e
	}
	if e = t.validate(); e != nil {
		return out, e
	}
	return out, nil
}

// ReadOwnedAt reads only an already-held created ordinary object or recorded
// stream. It accepts no colon path and never opens an arbitrary name or stream.
// Reads are at most 64 KiB; all borrowed workspace/identity checks bracket I/O.
func (t *OwnedTree) ReadOwnedAt(ctx context.Context, name, stream string, b []byte, off int64) (int, error) {
	if t == nil || ctx == nil {
		return 0, ErrTreePreserved
	}
	if len(b) > 64<<10 || len(name) > 4096 || len(stream) > 1024 {
		return 0, ErrTreeLimit
	}
	if off < 0 || strings.Contains(stream, ":") {
		return 0, ErrTreePreserved
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	if e := t.validate(); e != nil {
		return 0, e
	}
	v, e := t.entry(name)
	if e != nil || v.directory {
		return 0, ErrTreePreserved
	}
	f := v.file
	if stream != "" {
		f = nil
		for j, n := range v.streamNames {
			if n == stream {
				f = v.streamFiles[j]
				break
			}
		}
		if f == nil {
			return 0, ErrTreePreserved
		}
	}
	before, e := nativeInfo(f)
	if e != nil || nativeIdentity(before) != v.id || before.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return 0, errors.Join(ErrTreePreserved, e)
	}
	n, readErr := f.ReadAt(b, off)
	after, e := nativeInfo(f)
	if e != nil || after != before {
		return 0, errors.Join(ErrTreePreserved, e)
	}
	if e = t.validate(); e != nil {
		return 0, e
	}
	if e = ctx.Err(); e != nil {
		return 0, e
	}
	return n, readErr
}
