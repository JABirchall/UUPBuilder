package windows

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
)

// SessionRunner retains one owned process job across sequential commands in the
// exact borrowed Workspace. It authorizes no executable or image operation.
// The caller must keep the workspace open and finish safe owned mount cleanup
// before Close. Worker loss/Close kills only this job; image recovery belongs to
// the caller. The zero value is closed. A SessionRunner must not be copied.
//
// Concurrent Run calls serialize; a queued call can cancel without launching.
// Close rejects queued/new calls immediately, waits for the active Run (including
// CancelWait natural exit), then kills retained descendants and releases handles.
// Windows may finish descendant termination asynchronously after Close returns.
// Forced tree cancellation ends the entire session permanently. CancelWait alone
// leaves it reusable. Close is concurrent-safe and idempotent. Emit callbacks
// must return promptly and must not call Run or Close on this same session.
//
// Run captures each stream through a finite snapshot of the bytes available when
// direct-parent exit is observed, retaining at most the final 64 KiB per stream.
// This includes completed parent writes and may include interleaved descendant
// output. It never waits for retained descendants to close their inherited pipes;
// later descendant output is excluded and the readers close when Run returns.
type SessionRunner struct {
	workspace *Workspace
	identity  WorkspaceIdentity
	gate      chan struct{}
	closing   chan struct{}
	mu        sync.Mutex
	job       windows.Handle
	closeErr  error
}

// NewSessionRunner borrows workspace and creates a distinct non-inheritable,
// kill-on-close job. The caller retains ownership of the workspace handle.
func NewSessionRunner(workspace *Workspace) (*SessionRunner, error) {
	if workspace == nil || workspace.root == nil || !validID(workspace.identity.JobID) || !validToken(workspace.identity.Token) || !filepath.IsAbs(workspace.identity.Path) {
		return nil, errors.New("owned open workspace required")
	}
	dir, _, err := workspace.lockDirectory("")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	job, err := newOwnedJob()
	if err != nil {
		return nil, err
	}
	s := &SessionRunner{workspace: workspace, identity: workspace.Identity(), gate: make(chan struct{}, 1), closing: make(chan struct{}), job: job}
	s.gate <- struct{}{}
	return s, nil
}

func (s *SessionRunner) Run(ctx context.Context, inv Invocation, emit model.Emit) (RunResult, error) {
	if s == nil || s.gate == nil {
		return RunResult{}, errors.New("closed process session")
	}
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	select {
	case <-ctx.Done():
		return RunResult{}, ctx.Err()
	case <-s.closing:
		return RunResult{}, errors.New("closed process session")
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	// Close can win while this call was acquiring the operation gate.
	select {
	case <-s.closing:
		return RunResult{}, errors.New("closed process session")
	default:
	}
	if inv.Workspace != s.workspace || inv.JobID != s.identity.JobID || s.workspace.Identity() != s.identity {
		return RunResult{}, errors.New("invocation does not belong to this process session")
	}
	result, err := runOwnedProcess(ctx, inv, emit, s.job)
	if result.Cancelled && inv.Cancellation == CancelTerminateTree {
		s.beginClose()
		err = errors.Join(err, s.releaseJob())
	}
	return result, err
}

func (s *SessionRunner) beginClose() {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closing:
	default:
		close(s.closing)
	}
}

// releaseJob is called only while holding the operation gate.
func (s *SessionRunner) releaseJob() error {
	if s.job != 0 {
		s.closeErr = windows.CloseHandle(s.job)
		s.job = 0
	}
	return s.closeErr
}

func (s *SessionRunner) Close() error {
	if s == nil {
		return errors.New("nil process session")
	}
	if s.gate == nil {
		return nil
	}
	s.beginClose()
	<-s.gate
	defer func() { s.gate <- struct{}{} }()
	return s.releaseJob()
}

var peekSessionPipe = windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")

// sessionPipeReader captures live output without relying on descendant EOF.
// After observing direct-parent exit it snapshots the bytes then available and
// drains exactly that finite prefix. All completed parent writes are in that
// prefix or were already read. Later descendant output is outside this command's
// capture contract. A retained inherited writer cannot extend the drain.
// captureOutput still bounds each resulting tail to 64 KiB.
type sessionPipeReader struct {
	file       *os.File
	parentDone <-chan struct{}
	draining   bool
	remaining  uint32
}

func (r *sessionPipeReader) Read(p []byte) (int, error) {
	for {
		if r.draining {
			if r.remaining == 0 {
				return 0, io.EOF
			}
			if uint32(len(p)) > r.remaining {
				p = p[:r.remaining]
			}
			n, err := r.file.Read(p)
			r.remaining -= uint32(n)
			return n, err
		}
		select {
		case <-r.parentDone:
			r.draining = true
		default:
		}
		var available uint32
		ok, _, err := peekSessionPipe.Call(r.file.Fd(), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
		if ok == 0 {
			return 0, err
		}
		if r.draining {
			r.remaining = available
			continue
		}
		if available > 0 {
			if uint32(len(p)) > available {
				p = p[:available]
			}
			return r.file.Read(p)
		}
		select {
		case <-r.parentDone:
		case <-time.After(5 * time.Millisecond):
		}
	}
}
