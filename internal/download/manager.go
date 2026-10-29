//go:build windows

// Package download materializes frozen payload identities in an owned verified
// cache. Expiring locators remain runtime only; no source package is imported.
package download

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync"
	"time"

	native "golang.org/x/sys/windows"
	"uupbuilder/internal/model"
	windows "uupbuilder/internal/platform/windows"
)

type Locator = model.Locator
type Materialized map[model.PayloadIdentity]CachedFile

// CachedFile is a verified snapshot keyed by full source package provenance.
// Retain its cache workspace and do not mutate entries. No locators or private
// workspace tokens enter this DTO. SHA256 is always computed locally.
type CachedFile struct {
	Path     string                `json:"path"`
	SHA256   string                `json:"sha256"`
	Identity model.PayloadIdentity `json:"identity"`
}

type SystemProxyResolver interface {
	Resolve(context.Context, *url.URL) (*url.URL, error)
}

// Options borrows distinct W1 workspace capabilities, not arbitrary paths. The
// caller creates them with CreateWorkspace, journals their identities privately,
// and reopens with OpenWorkspace after restart. Keep them open until Close
// returns. One manager exclusively leases each workspace, across processes.
// Close releases leases without closing caller workspaces or deleting content.
// ParallelFiles defaults to 4, RetryDelay to 250ms, RequestTimeout to 30 minutes
// per request including its body. Zero Retries means no retry. Transport is
// cloned and proxy/compression policy applied. Nil SystemProxy uses W1's native
// URL-specific resolver. Refresh is used by Fetch only: FetchOne cannot supply
// the complete frozen source manifest required for refresh. Refresh callbacks
// must honor context cancellation and Emit callbacks must return promptly.
type Options struct {
	Transport                  *http.Transport
	Cache, Job                 *windows.Workspace
	ParallelFiles, Retries     int
	RetryDelay, RequestTimeout time.Duration
	Proxy                      model.ProxySettings
	SystemProxy                SystemProxyResolver
	Refresh                    func(context.Context, model.PayloadManifest) (model.Locators, error)
	Now                        func() time.Time
}

var (
	ErrClosed         = errors.New("download manager closed")
	ErrInUse          = errors.New("download workspace already leased")
	ErrInvalidOptions = errors.New("invalid download options")
	ErrInvalidInput   = errors.New("invalid download input")
	ErrIntegrity      = errors.New("download integrity check failed")
	ErrRefresh        = errors.New("download locator refresh failed")
	ErrTransfer       = errors.New("download transfer failed")
	ErrStorage        = errors.New("download owned storage operation failed")
)

type Manager struct {
	opts           Options
	client         *http.Client
	transport      *http.Transport
	leases         []*os.File
	life           context.Context
	stop           context.CancelFunc
	sem            chan struct{}
	controls       chan struct{}
	mu             sync.Mutex
	changed        chan struct{}
	paused, closed bool
	next           uint64
	active         map[uint64]context.CancelFunc
	keys           map[model.PayloadIdentity]chan struct{}
	ops            sync.WaitGroup
	closeOnce      sync.Once
	closeErr       error
}

func NewManager(opts Options) (*Manager, error) {
	if opts.Cache == nil || opts.Job == nil || opts.Cache.Identity() == opts.Job.Identity() || opts.ParallelFiles < 0 || opts.Retries < 0 || opts.RetryDelay < 0 || opts.RequestTimeout < 0 {
		return nil, ErrInvalidOptions
	}
	if opts.ParallelFiles == 0 {
		opts.ParallelFiles = 4
	}
	if opts.RetryDelay == 0 {
		opts.RetryDelay = 250 * time.Millisecond
	}
	if opts.RequestTimeout == 0 {
		opts.RequestTimeout = 30 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	transport, err := configuredTransport(opts)
	if err != nil {
		return nil, err
	}
	life, stop := context.WithCancel(context.Background())
	m := &Manager{opts: opts, transport: transport, life: life, stop: stop, sem: make(chan struct{}, opts.ParallelFiles), controls: make(chan struct{}, 1), changed: make(chan struct{}), active: make(map[uint64]context.CancelFunc), keys: make(map[model.PayloadIdentity]chan struct{})}
	m.client = &http.Client{Transport: transport, Timeout: opts.RequestTimeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || !validURL(req.URL) {
			return ErrTransfer
		}
		return nil
	}}
	for _, root := range []*windows.Workspace{opts.Cache, opts.Job} {
		f, err := root.OpenFile("download-manager.lock", os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			m.releaseLeases()
			stop()
			return nil, ErrStorage
		}
		if err := native.LockFileEx(native.Handle(f.Fd()), native.LOCKFILE_EXCLUSIVE_LOCK|native.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &native.Overlapped{}); err != nil {
			f.Close()
			m.releaseLeases()
			stop()
			return nil, ErrInUse
		}
		m.leases = append(m.leases, f)
	}
	return m, nil
}

func (m *Manager) releaseLeases() {
	for _, f := range m.leases {
		if native.UnlockFileEx(native.Handle(f.Fd()), 0, 1, 0, &native.Overlapped{}) != nil {
			m.closeErr = ErrStorage
		}
		if f.Close() != nil {
			m.closeErr = ErrStorage
		}
	}
	m.leases = nil
}

// Close cancels/quiesces work, including paused Fetch calls, then releases OS
// leases. Closing each lease handle also releases it after process failure.
// This method is idempotent and never closes caller-owned workspaces.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.stop()
		m.signal()
		m.mu.Unlock()
		m.ops.Wait()
		m.transport.CloseIdleConnections()
		m.releaseLeases()
	})
	return m.closeErr
}

func (m *Manager) signal() { close(m.changed); m.changed = make(chan struct{}) }
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
	stop := context.AfterFunc(m.life, cancel)
	return owned, func() { stop(); cancel(); m.ops.Done() }, nil
}

// Pause cancels active IO and waits for transfer/cache operations to quiesce.
// Fetch calls retain partials and wait for Resume or caller cancellation. A
// timed-out Pause leaves the manager paused.
func (m *Manager) Pause(ctx context.Context) error {
	unlock, err := m.control(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	m.paused = true
	for _, cancel := range m.active {
		cancel()
	}
	m.signal()
	for len(m.active) != 0 {
		changed := m.changed
		m.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
		m.mu.Lock()
	}
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return ErrClosed
	}
	return nil
}
func (m *Manager) Resume(ctx context.Context) error {
	unlock, err := m.control(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.paused = false
	m.signal()
	return nil
}

// Control calls serialize: Resume cannot release scheduling while an earlier
// Pause is still waiting for its cancelled work to finish.
func (m *Manager) control(ctx context.Context) (func(), error) {
	select {
	case m.controls <- struct{}{}:
		return func() { <-m.controls }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.life.Done():
		return nil, ErrClosed
	}
}

// begin shares Pause's mutex so scheduling cannot race the pause boundary.
func (m *Manager) begin(ctx context.Context) (context.Context, func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, nil, ErrClosed
		}
		if m.paused {
			changed := m.changed
			m.mu.Unlock()
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		m.mu.Unlock()
		select {
		case m.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
		m.mu.Lock()
		if m.paused || m.closed {
			m.mu.Unlock()
			<-m.sem
			continue
		}
		m.next++
		id := m.next
		active, cancel := context.WithCancel(ctx)
		m.active[id] = cancel
		m.mu.Unlock()
		return active, func() {
			cancel()
			m.mu.Lock()
			delete(m.active, id)
			m.signal()
			m.mu.Unlock()
			<-m.sem
		}, nil
	}
}

func (m *Manager) keyLock(ctx context.Context, id model.PayloadIdentity) (func(), error) {
	m.mu.Lock()
	key := m.keys[id]
	if key == nil {
		key = make(chan struct{}, 1)
		m.keys[id] = key
	}
	m.mu.Unlock()
	select {
	case key <- struct{}{}:
		return func() { <-key }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// FetchOne verifies a cache hit or materializes this payload. On a cache miss,
// an expired locator or HTTP 401/403 returns ErrRefresh; it never fabricates a
// source manifest or invokes Options.Refresh without that complete context.
func (m *Manager) FetchOne(ctx context.Context, payload model.Payload, locator Locator, emit model.Emit) (CachedFile, error) {
	owned, done, err := m.start(ctx)
	if err != nil {
		return CachedFile{}, err
	}
	defer done()
	return m.fetchOne(owned, payload, &locatorSet{locators: model.Locators{payload.Identity: locator}}, emit)
}

func (m *Manager) Fetch(ctx context.Context, manifest model.PayloadManifest, locators model.Locators, emit model.Emit) (Materialized, error) {
	owned, done, err := m.start(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if manifest.Validate() != nil {
		return nil, ErrInvalidInput
	}
	frozen := manifest
	frozen.Payloads = slices.Clone(manifest.Payloads)
	frozen.Queries = model.CloneSourceQueries(manifest.Queries)
	set := &locatorSet{frozen: frozen, locators: make(model.Locators), refresh: m.opts.Refresh}
	members := make(map[model.PayloadIdentity]bool)
	for _, p := range frozen.Payloads {
		members[p.Identity] = true
	}
	for id, loc := range locators {
		if !members[id] {
			return nil, ErrInvalidInput
		}
		set.locators[id] = loc
	}
	work, cancel := context.WithCancel(owned)
	defer cancel()
	queue := make(chan model.Payload, len(frozen.Payloads))
	for _, p := range frozen.Payloads {
		queue <- p
	}
	close(queue)
	result := make(Materialized)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	for range min(m.opts.ParallelFiles, len(frozen.Payloads)) {
		wg.Go(func() {
			for p := range queue {
				file, err := m.fetchOne(work, p, set, emit)
				mu.Lock()
				if err != nil {
					if first == nil {
						first = err
						cancel()
					}
					mu.Unlock()
					return
				}
				result[p.Identity] = file
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if first != nil {
		return nil, first
	}
	return result, nil
}
