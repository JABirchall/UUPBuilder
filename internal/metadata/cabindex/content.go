package cabindex

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"

	"uupbuilder/internal/metadata/privatestore"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
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
	data    *privatestore.File
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
	if a.data == nil {
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
		n, e := a.data.ReadAt(b[:a.receipt.Size-uint64(off)], off)
		if e == nil {
			e = io.EOF
		}
		return n, e
	}
	return a.data.ReadAt(b, off)
}
func (a *ContentArtifact) close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.data == nil {
		return nil
	}
	e := a.data.Close()
	a.data = nil
	return e
}
func (a *ContentArtifact) verify(ctx context.Context, w Witness, buffer int) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.data == nil || a.receipt != w {
		return ErrIntegrity
	}
	// localsource uses its historical fixed 64 KiB hash buffer. Reject a lower
	// caller buffer limit before using it, rather than silently exceeding it.
	if buffer < 64<<10 {
		return ErrLimit
	}
	e := a.data.Verify(ctx, model.DigestSHA1, w.SHA1, w.SHA256)
	if e != nil {
		return errors.Join(ErrIntegrity, e)
	}
	return nil
}

type privateStore struct{ store *privatestore.Store }

func newPrivateStore() (*privateStore, error) {
	s, e := privatestore.New(privatestore.Profile{MaxFiles: 16385, MaxBytes: 2 << 30}, "cab-reference-content")
	if e != nil {
		return nil, e
	}
	return &privateStore{s}, nil
}
func (s *privateStore) create(size uint64) (*os.File, string, error) { return s.store.Create(size) }
func (s *privateStore) remove(name string) error                     { return s.store.Remove(name) }
func (s *privateStore) retain(name string, w Witness) (*ContentArtifact, error) {
	a, e := s.store.Retain(name, w.Size)
	if e != nil {
		return nil, errors.Join(ErrIntegrity, e)
	}
	return &ContentArtifact{receipt: w, data: a}, nil
}
func (s *privateStore) verify(ctx context.Context) error {
	if e := s.store.Verify(ctx); e != nil {
		return errors.Join(ErrIntegrity, e)
	}
	return nil
}
func (s *privateStore) close() error {
	if e := s.store.Close(); e != nil {
		return errors.Join(ErrIntegrity, e)
	}
	return nil
}
