//go:build windows

package jobstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	platform "uupbuilder/internal/platform/windows"
)

const lockPath = "jobstore.lock"

func (s *Store) acquire() error {
	f, err := s.w.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		f.Close()
		return fmt.Errorf("jobstore writer already owned: %w", err)
	}
	s.lock = f
	return nil
}
func (s *Store) release() error {
	if s.lock == nil {
		return nil
	}
	err := windows.UnlockFileEx(windows.Handle(s.lock.Fd()), 0, 1, 0, &windows.Overlapped{})
	return errors.Join(err, s.lock.Close())
}

// ClaimMount records the directory intent and then the exact W1 ownership
// capability before returning it. It never mounts, unmounts or adopts a path.
func (tx *Transaction) ClaimMount(relative string) (platform.OwnedMount, error) {
	s := tx.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := tx.usable(); err != nil {
		return platform.OwnedMount{}, err
	}
	n, err := cleanRelative(relative)
	if err != nil {
		return platform.OwnedMount{}, err
	}
	for _, p := range tx.intent.OwnedPaths {
		a, b := strings.ToLower(n), strings.ToLower(p)
		if a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") {
			return platform.OwnedMount{}, errors.New("mount overlaps declared output file")
		}
	}
	full := tx.scratch + "/" + n
	idx := s.stageIndex(tx.id)
	next := clone(s.state)
	for _, prior := range next.Stages[idx].MountPaths {
		a, b := strings.ToLower(full), strings.ToLower(prior)
		if a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") {
			return platform.OwnedMount{}, errors.New("mount directory overlaps an existing claim")
		}
	}
	next.Stages[idx].MountPaths = append(next.Stages[idx].MountPaths, full)
	if err := s.writeJournal(next); err != nil {
		return platform.OwnedMount{}, err
	}
	if err := s.w.MkdirAll(filepath.ToSlash(filepath.Dir(full))); err != nil {
		return platform.OwnedMount{}, err
	}
	claim, err := s.w.ClaimMount(full, tx.intent.StageID)
	if err != nil {
		return platform.OwnedMount{}, err
	}
	next = clone(s.state)
	next.Stages[idx].Mounts = append(next.Stages[idx].Mounts, claim)
	if err := s.writeJournal(next); err != nil {
		return platform.OwnedMount{}, err
	}
	return claim, nil
}

func normalizedAbsolute(path string) (string, error) {
	if strings.HasPrefix(path, `\\?\UNC\`) {
		path = `\\` + path[8:]
	} else if strings.HasPrefix(path, `\\?\`) {
		path = path[4:]
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("mount inventory has an ambiguous relative path")
	}
	return strings.ToLower(filepath.Clean(path)), nil
}
func pathsOverlap(a, b string) bool {
	// Drive/UNC roots already end in a separator; do not append a second one.
	prefix := func(path string) string { return strings.TrimRight(path, `\/`) + string(filepath.Separator) }
	return a == b || strings.HasPrefix(a, prefix(b)) || strings.HasPrefix(b, prefix(a))
}

// topology lists entries without following reparse points. All mutation still
// goes through W1's rooted handles. Enumeration is bounded and read-only.
func topology(ctx context.Context, rootPath string) ([]string, error) {
	r, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	entries := []string{}
	queue := []string{"."}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := queue[0]
		queue = queue[1:]
		info, err := r.Lstat(name)
		if err != nil {
			return nil, err
		}
		attr, ok := info.Sys().(*syscall.Win32FileAttributeData)
		if !ok || attr.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil, fmt.Errorf("unresolved reparse topology at %s", name)
		}
		if name != "." {
			entries = append(entries, filepath.ToSlash(name))
		}
		if len(entries) > 8192 || len(queue) > 8192 || strings.Count(name, "/") > 64 {
			return nil, errors.New("workspace topology inspection limit exceeded")
		}
		f, err := r.Open(name)
		if err != nil {
			return nil, err
		}
		actual, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		if !os.SameFile(info, actual) {
			f.Close()
			return nil, errors.New("workspace topology changed during inspection")
		}
		var native windows.ByHandleFileInformation
		err = windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &native)
		if err != nil {
			f.Close()
			return nil, err
		}
		if native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || !actual.IsDir() && native.NumberOfLinks != 1 {
			f.Close()
			return nil, fmt.Errorf("unresolved linked topology at %s", name)
		}
		if actual.IsDir() {
			children, err := f.Readdirnames(8193)
			if err != nil && !errors.Is(err, io.EOF) {
				f.Close()
				return nil, err
			}
			if len(children) > 8192 {
				f.Close()
				return nil, errors.New("workspace topology inspection limit exceeded")
			}
			for _, child := range children {
				queue = append(queue, filepath.ToSlash(filepath.Join(name, child)))
			}
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

func (s *Store) knownPaths() (map[string]bool, map[string]bool) {
	files := map[string]bool{journalPath: true, lockPath: true, ".uupbuilder-owner.json": true}
	dirs := map[string]bool{}
	addDir := func(p string) {
		for p != "." && p != "" {
			dirs[p] = true
			p = filepath.ToSlash(filepath.Dir(p))
		}
	}
	for _, st := range s.state.Stages {
		addDir(st.Scratch)
		addDir(st.Promotion)
		for _, p := range st.Intent.OwnedPaths {
			full := st.Scratch + "/" + p
			files[full] = true
			addDir(filepath.ToSlash(filepath.Dir(full)))
		}
		for _, o := range st.Candidates {
			files[o.Path] = true
			addDir(filepath.ToSlash(filepath.Dir(o.Path)))
		}
		for _, p := range st.MountPaths {
			addDir(p)
		}
	}
	return files, dirs
}

// Discard keeps the private journal/owner/lease for diagnosis. It removes only
// declared files and empty owned directories, with no recursive delete. The
// caller must first stop all providers and close their mutation handles.
func (s *Store) Discard(ctx context.Context, jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, jobID); err != nil {
		return err
	}
	r, err := s.inspect(ctx)
	if err != nil {
		return err
	}
	if len(r.Preserved) > 0 {
		return errors.New("unresolved resources preserved; discard requires inspection")
	}
	next := clone(s.state)
	next.Discarded = true
	if err := s.writeJournal(next); err != nil {
		return err
	}
	if s.active != nil {
		s.active.done = true
		s.active = nil
	}
	files, dirs := s.knownPaths()
	names := []string{}
	for p := range files {
		if p != journalPath && p != lockPath && p != ".uupbuilder-owner.json" {
			names = append(names, p)
		}
	}
	sort.Strings(names)
	for _, p := range names {
		if err := s.check(ctx, jobID); err != nil {
			return err
		}
		if err := s.clearResources(ctx); err != nil {
			return err
		}
		if err := s.w.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("preserved %s: %w", p, err)
		}
	}
	names = names[:0]
	for p := range dirs {
		names = append(names, p)
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, p := range names {
		if err := s.check(ctx, jobID); err != nil {
			return err
		}
		if err := s.clearResources(ctx); err != nil {
			return err
		}
		if err := s.w.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("preserved nonempty or changed directory %s: %w", p, err)
		}
	}
	return nil
}
