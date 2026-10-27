//go:build windows

package tools

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	native "golang.org/x/sys/windows"
	"uupbuilder/internal/download"
	"uupbuilder/internal/model"
	windows "uupbuilder/internal/platform/windows"
)

type Fetcher interface {
	FetchOne(context.Context, model.Payload, model.Locator, model.Emit) (download.CachedFile, error)
}

// Options borrows a W1 private Workspace and D4 FetchOne port. Keep the
// workspace and the fetcher's cache lifetime open until Close returns. No path
// from configuration/TUI is accepted. Close releases the exclusive kernel
// lease; it never closes or recursively deletes caller-owned storage.
type Options struct {
	Manifest  TrustedManifest
	Workspace *windows.Workspace
	Fetcher   Fetcher
}
type Manager struct {
	workspace *windows.Workspace
	manifest  TrustedManifest
	fetcher   Fetcher
	lease     *os.File
	life      context.Context
	stop      context.CancelFunc
	gate      chan struct{}
	mu        sync.Mutex
	closed    bool
	ops       sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func NewManager(opts Options) (*Manager, error) {
	if opts.Workspace == nil || opts.Fetcher == nil || !validSHA(opts.Manifest.digest) || len(opts.Manifest.providers) == 0 {
		return nil, ErrInvalidInput
	}
	f, err := opts.Workspace.OpenFile("tool-manager.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	if err := native.LockFileEx(native.Handle(f.Fd()), native.LOCKFILE_EXCLUSIVE_LOCK|native.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &native.Overlapped{}); err != nil {
		f.Close()
		return nil, ErrInUse
	}
	life, stop := context.WithCancel(context.Background())
	return &Manager{workspace: opts.Workspace, manifest: opts.Manifest, fetcher: opts.Fetcher, lease: f, life: life, stop: stop, gate: make(chan struct{}, 1)}, nil
}
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.stop()
		m.mu.Unlock()
		m.ops.Wait()
		m.closeErr = errors.Join(native.UnlockFileEx(native.Handle(m.lease.Fd()), 0, 1, 0, &native.Overlapped{}), m.lease.Close())
	})
	return m.closeErr
}
func (m *Manager) start(ctx context.Context) (context.Context, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	m.ops.Add(1)
	owned, cancel := context.WithCancel(ctx)
	after := context.AfterFunc(m.life, cancel)
	return owned, func() { after(); cancel(); m.ops.Done() }, nil
}

// Ensure is intentionally refusal-only while P1 runtime/rights/prerequisite
// acceptance remains blocked. It never fetches, extracts, calls a process
// runner, installs, elevates, or interprets structural evidence as attestation.
func (m *Manager) Ensure(ctx context.Context, req Requirement, emit model.Emit) (Toolchain, error) {
	ctx, done, err := m.start(ctx)
	if err != nil {
		return Toolchain{}, err
	}
	defer done()
	selection, err := m.manifest.Select(req)
	if err != nil {
		return Toolchain{}, err
	}
	if err := ctx.Err(); err != nil {
		return Toolchain{}, err
	}
	blocked := &BlockedError{Selection: selection}
	if emit != nil {
		emit(model.Event{JobID: m.workspace.Identity().JobID, StageID: "tools", Kind: model.EventError, Message: blocked.Error(), Timestamp: time.Now().UTC()})
	}
	return Toolchain{}, blocked
}
