package wimcontent

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"uupbuilder/internal/metadata/privatestore"
	"uupbuilder/internal/metadata/wimindex"
)

// Result owns a bounded private backing store. Content returns interval views
// borrowing this owner, without opening handles. Close revokes all borrowers,
// then removes checked owned data; failure is latched and preserved on retry.
// Receipts remain historical after Close; they do not keep readable bytes alive.
type Result struct {
	mu       sync.RWMutex
	catalog  *Catalog
	store    *privatestore.Store
	backings []*privatestore.File
	closed   bool
	closeErr error
}

func (r *Result) Catalog() *Catalog {
	if r == nil {
		return nil
	}
	return r.catalog
}
func (r *Result) Content(n int) (*ContentArtifact, error) {
	if r == nil {
		return nil, ErrInput
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, os.ErrClosed
	}
	if r.catalog == nil || n < 0 || n >= len(r.catalog.state.Witnesses) {
		return nil, ErrInput
	}
	return &ContentArtifact{r, n}, nil
}
func (r *Result) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	if r.store != nil {
		r.closeErr = r.store.Close()
	}
	return r.closeErr
}

type ContentArtifact struct {
	owner *Result
	n     int
}

func (a *ContentArtifact) Receipt() Witness               { return a.owner.catalog.state.Witnesses[a.n] }
func (a *ContentArtifact) Binding() wimindex.ContentClaim { return a.owner.catalog.state.Index }
func (a *ContentArtifact) ReadAt(b []byte, off int64) (int, error) {
	r := a.owner
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	w := r.catalog.state.Witnesses[a.n]
	if off < 0 {
		return 0, ErrInput
	}
	if len(b) == 0 {
		return 0, nil
	}
	if uint64(off) >= w.Size {
		return 0, io.EOF
	}
	short := uint64(len(b)) > w.Size-uint64(off)
	if short {
		b = b[:w.Size-uint64(off)]
	}
	n, e := r.backings[w.Backing].ReadAt(b, int64(w.Entry.Location.LogicalOffset)+off)
	if short && e == nil {
		e = io.EOF
	}
	return n, e
}
func (r *Result) live() error {
	if r == nil {
		return ErrInput
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return os.ErrClosed
	}
	if r.catalog == nil || !r.catalog.state.NonMetadataVerified {
		return ErrInput
	}
	return nil
}
func joinIntegrity(e error) error {
	return errors.Join(ErrIntegrity, e)
}

// verifyCurrent gates composition against live retained backing bytes.
func (r *Result) verifyCurrent(ctx context.Context, b *readBudget) error {
	if e := r.live(); e != nil {
		return e
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for n, f := range r.backings {
		w := r.catalog.state.Backings[n]
		if e := b.charge(w.Size); e != nil {
			return e
		}
		if e := f.Verify(ctx, "sha256", w.SHA256, w.SHA256); e != nil {
			return joinIntegrity(e)
		}
	}
	return nil
}
