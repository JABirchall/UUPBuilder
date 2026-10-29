// Package privatestore owns generated-name, private local NTFS content. Runtime
// locations never grant verified-content authority; higher layers seal receipts.
package privatestore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/metadata/localsource"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

var ErrIntegrity = errors.New("private content custody changed")
var ErrLimit = errors.New("private content storage bound exceeded")

type Profile struct {
	MaxFiles int
	MaxBytes uint64
}
type owned struct {
	initial  os.FileInfo
	size     uint64
	retained *File
}

// Store is sequential during construction. Close revokes retained files first,
// removes only checked owned entries, and latches cleanup failures. It never
// recursively deletes a scope containing unknown/replaced entries.
type Store struct {
	workspace     *platform.Workspace
	root, parent  *os.Root
	names         map[string]owned
	initial       os.FileInfo
	serial, bytes uint64
	profile       Profile
	closed        bool
	closeErr      error
}

func New(p Profile, purpose string) (*Store, error) {
	if p.MaxFiles <= 0 || p.MaxFiles > 262144 || p.MaxBytes == 0 || p.MaxBytes > 8<<30 {
		return nil, ErrLimit
	}
	w, e := platform.CreateWorkspace(os.TempDir(), purpose)
	if e != nil {
		return nil, e
	}
	s := &Store{workspace: w, names: map[string]owned{}, profile: p}
	s.parent, e = os.OpenRoot(filepath.Dir(w.Path()))
	if e == nil {
		s.root, e = os.OpenRoot(w.Path())
	}
	if e != nil {
		w.Close()
		if s.parent != nil {
			s.parent.Close()
		}
		return nil, fmt.Errorf("private scope retained at %s: %w", w.Path(), e)
	}
	if s.initial, e = s.root.Stat("."); e != nil {
		return nil, errors.Join(e, s.Close())
	}
	return s, nil
}
func (s *Store) Path() string { return s.workspace.Path() }
func (s *Store) Create(size uint64) (*os.File, string, error) {
	if s.closed {
		return nil, "", os.ErrClosed
	}
	if len(s.names) >= s.profile.MaxFiles || size > s.profile.MaxBytes-s.bytes {
		return nil, "", ErrLimit
	}
	s.serial++
	name := fmt.Sprintf("member-%08d.data", s.serial)
	f, e := s.workspace.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e == nil {
		var info os.FileInfo
		info, e = f.Stat()
		if e != nil {
			return nil, name, errors.Join(e, f.Close())
		}
		s.names[name] = owned{initial: info, size: size}
		s.bytes += size
	}
	return f, name, e
}
func (s *Store) Remove(name string) error {
	v, ok := s.names[name]
	if !ok {
		return ErrIntegrity
	}
	if v.retained != nil {
		if e := v.retained.Close(); e != nil {
			return e
		}
	}
	named, e := s.root.Stat(name)
	if os.IsNotExist(e) {
		delete(s.names, name)
		s.bytes -= v.size
		return nil
	}
	if e != nil || !os.SameFile(v.initial, named) {
		return errors.Join(ErrIntegrity, e)
	}
	e = s.workspace.Remove(name)
	if e == nil || os.IsNotExist(e) {
		delete(s.names, name)
		s.bytes -= v.size
		return nil
	}
	return e
}
func (s *Store) Retain(name string, size uint64) (*File, error) {
	if s.closed {
		return nil, os.ErrClosed
	}
	v, known := s.names[name]
	if !known || v.size != size || v.retained != nil {
		return nil, ErrIntegrity
	}
	path := filepath.Join(s.workspace.Path(), name)
	u, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(u, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(h), path)
	initial, e := f.Stat()
	var info windows.ByHandleFileInformation
	if e != nil || !os.SameFile(v.initial, initial) || !initial.Mode().IsRegular() || initial.Size() != int64(size) || windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != 1 {
		f.Close()
		return nil, ErrIntegrity
	}
	a := &File{file: f, path: path, initial: initial, size: size}
	v.retained = a
	s.names[name] = v
	return a, nil
}
func (s *Store) Verify(ctx context.Context) (runErr error) {
	if s.closed {
		return os.ErrClosed
	}
	f, e := s.root.Open(".")
	if e != nil {
		return e
	}
	defer func() { runErr = errors.Join(runErr, f.Close()) }()
	count := 0
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		entries, e := f.ReadDir(128)
		for _, entry := range entries {
			count++
			if count > len(s.names)+1 || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return ErrIntegrity
			}
			if entry.Name() == ".uupbuilder-owner.json" {
				continue
			}
			v, ok := s.names[entry.Name()]
			if !ok {
				return ErrIntegrity
			}
			named, e := s.root.Stat(entry.Name())
			if e != nil || !os.SameFile(v.initial, named) {
				return errors.Join(ErrIntegrity, e)
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
	}
	if count != len(s.names)+1 {
		return ErrIntegrity
	}
	return nil
}
func (s *Store) Close() error {
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	var e error
	for _, v := range s.names {
		if v.retained != nil {
			e = errors.Join(e, v.retained.Close())
		}
	}
	for name := range s.names {
		e = errors.Join(e, s.Remove(name))
	}
	f, readErr := s.root.Open(".")
	var entries []os.DirEntry
	if readErr == nil {
		entries, readErr = f.ReadDir(2)
		if readErr == io.EOF {
			readErr = nil
		}
		readErr = errors.Join(readErr, f.Close())
	}
	if e == nil && readErr == nil && len(entries) == 1 && entries[0].Name() == ".uupbuilder-owner.json" {
		e = s.root.Remove(".uupbuilder-owner.json")
	} else {
		e = errors.Join(e, readErr, ErrIntegrity)
	}
	e = errors.Join(e, s.root.Close(), s.workspace.Close())
	if e == nil {
		name := filepath.Base(s.workspace.Path())
		named, statErr := s.parent.Stat(name)
		if statErr != nil || s.initial == nil || !os.SameFile(s.initial, named) {
			e = errors.Join(ErrIntegrity, statErr)
		} else {
			e = s.parent.Remove(name)
		}
	}
	e = errors.Join(e, s.parent.Close())
	if e != nil {
		e = fmt.Errorf("private cleanup retained scope %s: %w", s.workspace.Path(), e)
	}
	s.closeErr = e
	return e
}

// File is a borrowed read-only object. Store.Close revokes it. Verify hashes the
// complete retained object and checks its original created-file/path identity.
type File struct {
	mu      sync.RWMutex
	file    *os.File
	path    string
	initial os.FileInfo
	size    uint64
}

func (a *File) ReadAt(b []byte, off int64) (int, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.file == nil {
		return 0, os.ErrClosed
	}
	if off < 0 {
		return 0, ErrIntegrity
	}
	if len(b) == 0 {
		return 0, nil
	}
	if uint64(off) >= a.size {
		return 0, io.EOF
	}
	if uint64(len(b)) > a.size-uint64(off) {
		n, e := a.file.ReadAt(b[:a.size-uint64(off)], off)
		if e == nil {
			e = io.EOF
		}
		return n, e
	}
	return a.file.ReadAt(b, off)
}
func (a *File) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	e := a.file.Close()
	a.file = nil
	return e
}
func (a *File) Verify(ctx context.Context, algorithm model.DigestAlgorithm, digest, sha256 string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.file == nil {
		return os.ErrClosed
	}
	id := model.PayloadIdentity{Size: int64(a.size), Digest: model.Digest{Algorithm: algorithm, Value: digest}}
	got, e := localsource.Verify(ctx, a.file, a.path, id, a.initial)
	if e != nil || got != sha256 {
		return errors.Join(ErrIntegrity, e)
	}
	return nil
}
