package cabindex

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
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

// Result owns the private data scope. Content returns borrowed read-only
// artifacts; Close revokes every reader and removes only known owned entries.
// Catalog receipts survive Close as historical evidence, not readable content.
type Result struct {
	mu        sync.Mutex
	catalog   *Catalog
	store     *privateStore
	artifacts []*ContentArtifact
	closed    bool
	closeErr  error
}

func (r *Result) Catalog() *Catalog { return r.catalog }
func (r *Result) Content(n int) (*ContentArtifact, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, os.ErrClosed
	}
	if n < 0 || n >= len(r.artifacts) {
		return nil, ErrInput
	}
	return r.artifacts[n], nil
}
func (r *Result) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	var e error
	for _, a := range r.artifacts {
		e = errors.Join(e, a.close())
	}
	if r.store != nil {
		e = errors.Join(e, r.store.close())
	}
	r.closeErr = e
	return e
}

type ContentArtifact struct {
	mu      sync.RWMutex
	receipt Witness
	binding wimmeta.Claim
	file    *os.File
	path    string
	initial os.FileInfo
}

// Binding is the exact original immutable oracle claim, including its source,
// manifest/index/metadata/oracle identities and unresolved metadata summary.
// Like Receipt, it remains historical evidence after the owner revokes reads.
func (a *ContentArtifact) Binding() wimmeta.Claim {
	if a == nil {
		return wimmeta.Claim{}
	}
	return a.binding
}
func (a *ContentArtifact) Receipt() Witness { return a.receipt }
func (a *ContentArtifact) ReadAt(b []byte, off int64) (int, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.file == nil {
		return 0, os.ErrClosed
	}
	if off < 0 {
		return 0, ErrInput
	}
	if len(b) == 0 {
		return 0, nil
	}
	if uint64(off) >= a.receipt.Size {
		return 0, io.EOF
	}
	if uint64(len(b)) > a.receipt.Size-uint64(off) {
		n, e := a.file.ReadAt(b[:a.receipt.Size-uint64(off)], off)
		if e == nil {
			e = io.EOF
		}
		return n, e
	}
	return a.file.ReadAt(b, off)
}
func (a *ContentArtifact) close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	e := a.file.Close()
	a.file = nil
	return e
}
func (a *ContentArtifact) verify(ctx context.Context, w Witness, buffer int) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.file == nil || a.receipt != w {
		return ErrIntegrity
	}
	// localsource uses its historical fixed 64 KiB hash buffer. Reject a lower
	// caller buffer limit before using it, rather than silently exceeding it.
	if buffer < 64<<10 {
		return ErrLimit
	}
	id := model.PayloadIdentity{Size: int64(w.Size), Digest: model.Digest{Algorithm: model.DigestSHA1, Value: w.SHA1}}
	sha, e := localsource.Verify(ctx, a.file, a.path, id, a.initial)
	if e != nil || sha != w.SHA256 {
		return errors.Join(ErrIntegrity, e)
	}
	return nil
}

type privateStore struct {
	workspace    *platform.Workspace
	root, parent *os.Root
	names        map[string]os.FileInfo
	initial      os.FileInfo
	serial       uint64
}

func newPrivateStore() (*privateStore, error) {
	w, e := platform.CreateWorkspace(os.TempDir(), "cab-reference-content")
	if e != nil {
		return nil, e
	}
	s := &privateStore{workspace: w, names: map[string]os.FileInfo{}}
	s.parent, e = os.OpenRoot(filepath.Dir(w.Path()))
	if e == nil {
		s.root, e = os.OpenRoot(w.Path())
	}
	if e != nil {
		w.Close()
		if s.parent != nil {
			s.parent.Close()
		}
		return nil, fmt.Errorf("private CAB scope retained at %s: %w", w.Path(), e)
	}
	if s.initial, e = s.root.Stat("."); e != nil {
		return nil, errors.Join(e, s.close())
	}
	return s, nil
}
func (s *privateStore) create() (*os.File, string, error) {
	s.serial++
	name := fmt.Sprintf("member-%08d.data", s.serial)
	f, e := s.workspace.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e == nil {
		s.names[name], e = f.Stat()
		if e != nil {
			return nil, name, errors.Join(e, f.Close())
		}
	}
	return f, name, e
}
func (s *privateStore) remove(name string) error {
	initial, ok := s.names[name]
	if !ok {
		return ErrIntegrity
	}
	named, statErr := s.root.Stat(name)
	if os.IsNotExist(statErr) {
		delete(s.names, name)
		return nil
	}
	if statErr != nil || !os.SameFile(initial, named) {
		return errors.Join(ErrIntegrity, statErr)
	}
	e := s.workspace.Remove(name)
	if e == nil || os.IsNotExist(e) {
		delete(s.names, name)
		return nil
	}
	return e
}
func (s *privateStore) retain(name string, w Witness) (*ContentArtifact, error) {
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
	created, known := s.names[name]
	if e != nil || !known || !os.SameFile(created, initial) || !initial.Mode().IsRegular() || initial.Size() != int64(w.Size) || windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != 1 {
		f.Close()
		return nil, ErrIntegrity
	}
	return &ContentArtifact{receipt: w, file: f, path: path, initial: initial}, nil
}

func (s *privateStore) verify(ctx context.Context) (runErr error) {
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
			initial, ok := s.names[entry.Name()]
			if !ok {
				return ErrIntegrity
			}
			named, e := s.root.Stat(entry.Name())
			if e != nil || !os.SameFile(initial, named) {
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
func (s *privateStore) close() error {
	var e error
	for name := range s.names {
		e = errors.Join(e, s.remove(name))
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
		return fmt.Errorf("private CAB cleanup retained scope %s: %w", s.workspace.Path(), e)
	}
	return nil
}
