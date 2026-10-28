//go:build windows

package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"uupbuilder/internal/model"
	windows "uupbuilder/internal/platform/windows"
)

var fixture = []byte("the exact bytes of a verified resumable payload\n")

func sha(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func payload(t *testing.T, data []byte, name string) model.Payload {
	t.Helper()
	p, err := model.NewPayload(model.PayloadIdentity{
		Digest: model.Digest{Algorithm: model.DigestSHA256, Value: sha(data)}, Size: int64(len(data)),
		Provenance: model.PackageProvenance{Source: "local-fixture", Name: name},
	}, name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testOptions(t *testing.T) Options {
	t.Helper()
	cache, err := windows.CreateWorkspace(t.TempDir(), "cache")
	if err != nil {
		t.Fatal(err)
	}
	job, err := windows.CreateWorkspace(t.TempDir(), "job")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { job.Close(); cache.Close() })
	return Options{Cache: cache, Job: job, ParallelFiles: 2, Retries: 3,
		RetryDelay: time.Millisecond, RequestTimeout: 5 * time.Second, Proxy: model.ProxySettings{Mode: model.ProxyDirect}}
}

func manager(t *testing.T, opts Options) *Manager {
	t.Helper()
	m, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	return m
}

func assertFile(t *testing.T, got CachedFile, p model.Payload, want []byte) {
	t.Helper()
	data, err := os.ReadFile(got.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(want) {
		t.Fatalf("final bytes = %q, want %q", data, want)
	}
	if got.SHA256 != sha(want) || got.Identity != p.Identity {
		t.Fatalf("wrong verified identity: %+v", got)
	}
}

func initial(w http.ResponseWriter, data []byte, prefix int) {
	w.Header().Set("ETag", `"original"`)
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.Write(data[:prefix]) // A deliberately truncated HTTP body, not an injected transfer result.
}

func ranged(w http.ResponseWriter, data []byte, offset int, etag string) {
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, len(data)-1, len(data)))
	w.Header().Set("Content-Length", fmt.Sprint(len(data)-offset))
	w.WriteHeader(http.StatusPartialContent)
	w.Write(data[offset:])
}

func TestInterruptedTransferResumesWithValidContentRange(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			initial(w, fixture, 13)
			return
		}
		if got := r.Header.Get("Range"); got != "bytes=13-" {
			t.Errorf("Range = %q, want bytes=13-", got)
		}
		ranged(w, fixture, 13, `"original"`)
	}))
	defer srv.Close()
	m := manager(t, testOptions(t))
	p := payload(t, fixture, "payload.bin")
	got, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, got, p, fixture)
	if count.Load() != 2 {
		t.Fatalf("requests = %d, want 2", count.Load())
	}
}

func TestRangeIgnoredRestartsInsteadOfAppending(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			initial(w, fixture, 13)
			return
		}
		w.Header().Set("ETag", `"original"`)
		w.Write(fixture)
	}))
	defer srv.Close()
	m := manager(t, testOptions(t))
	p := payload(t, fixture, "payload.bin")
	got, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, got, p, fixture)
}

func TestChangedValidatorOrWrongRangeRestarts(t *testing.T) {
	for _, kind := range []string{"validator", "range", "total", "length", "missing-validator"} {
		t.Run(kind, func(t *testing.T) {
			var count atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch count.Add(1) {
				case 1:
					initial(w, fixture, 13)
				case 2:
					etag := `"original"`
					start := 13
					if kind == "validator" {
						etag = `"changed"`
					}
					if kind == "range" {
						start = 12
					}
					w.Header().Set("ETag", etag)
					if kind == "missing-validator" {
						w.Header().Del("ETag")
					}
					total := len(fixture)
					if kind == "total" {
						total++
					}
					w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(fixture)-1, total))
					length := len(fixture) - start
					if kind == "length" {
						length++
					}
					w.Header().Set("Content-Length", fmt.Sprint(length))
					w.WriteHeader(206)
					w.Write(fixture[start:])
				default:
					if r.Header.Get("Range") != "" {
						t.Error("unsafe partial survived rejection")
					}
					w.Header().Set("ETag", `"original"`)
					w.Write(fixture)
				}
			}))
			defer srv.Close()
			m := manager(t, testOptions(t))
			p := payload(t, fixture, "payload.bin")
			got, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
			if err != nil {
				t.Fatal(err)
			}
			assertFile(t, got, p, fixture)
			if count.Load() != 3 {
				t.Fatalf("requests = %d, want restart request", count.Load())
			}
		})
	}
}

func seedPartial(t *testing.T, opts Options, p model.Payload, data []byte) {
	t.Helper()
	key := p.Identity.Key()
	f, err := opts.Job.OpenFile(key+".part", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(data); err != nil {
		t.Fatal(err)
	}
	f.Close()
	b, _ := json.Marshal(map[string]any{"version": 1, "key": key, "validator_kind": "etag", "validator_hash": sha([]byte(`"original"`))})
	f, err = opts.Job.OpenFile(key+".resume.json", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(b)
	f.Close()
}

func Test416VerifiesOrRestarts(t *testing.T) {
	for _, kind := range []string{"complete", "corrupt", "incomplete"} {
		t.Run(kind, func(t *testing.T) {
			opts := testOptions(t)
			p := payload(t, fixture, "payload.bin")
			data := append([]byte(nil), fixture...)
			if kind == "corrupt" {
				data[0] = 'X'
			}
			if kind == "incomplete" {
				data = data[:13]
			}
			seedPartial(t, opts, p, data)
			var count atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if count.Add(1) == 1 {
					w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(fixture)))
					w.WriteHeader(416)
					return
				}
				if r.Header.Get("Range") != "" {
					t.Error("416 did not reset invalid partial")
				}
				w.Write(fixture)
			}))
			defer srv.Close()
			m := manager(t, opts)
			got, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
			if err != nil {
				t.Fatal(err)
			}
			assertFile(t, got, p, fixture)
			want := int32(2)
			if kind == "complete" {
				want = 1
			}
			if count.Load() != want {
				t.Fatalf("requests=%d want=%d", count.Load(), want)
			}
		})
	}
}

func TestResumeOffsetBeyond4GiB(t *testing.T) {
	// Injected offset evidence only; this does not claim a real >4GiB transfer.
	const offset int64 = 1<<32 + 17
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Range"); got != "bytes=4294967313-" {
			t.Errorf("Range=%q", got)
		}
		w.WriteHeader(416)
	}))
	defer srv.Close()
	m := manager(t, testOptions(t))
	resp, err := m.request(context.Background(), Locator{URL: srv.URL}, offset)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	start, end, total, err := parseContentRange("bytes 4294967313-4294967322/4294967323")
	if err != nil || start != offset || end != 4294967322 || total != 4294967323 {
		t.Fatalf("lost int64 range: %d %d %d %v", start, end, total, err)
	}
}

func TestDigestMismatchNeverPublishesCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("X", len(fixture)))) }))
	defer srv.Close()
	opts := testOptions(t)
	m := manager(t, opts)
	p := payload(t, fixture, "payload.bin")
	if _, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("expected integrity failure, got %v", err)
	}
	for _, suffix := range []string{".data", ".json"} {
		if _, err := os.Stat(filepath.Join(opts.Cache.Path(), p.Identity.Key()+suffix)); !os.IsNotExist(err) {
			t.Fatalf("published unverified cache %s: %v", suffix, err)
		}
	}
}

func TestSameFilenameDifferentDigestsRemainDistinct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/two" {
			w.Write([]byte("second"))
			return
		}
		w.Write(fixture)
	}))
	defer srv.Close()
	m := manager(t, testOptions(t))
	p1 := payload(t, fixture, "same.bin")
	p2 := payload(t, []byte("second"), "same.bin")
	f1, e1 := m.FetchOne(context.Background(), p1, Locator{URL: srv.URL}, nil)
	f2, e2 := m.FetchOne(context.Background(), p2, Locator{URL: srv.URL + "/two"}, nil)
	if e1 != nil || e2 != nil {
		t.Fatalf("fetch: %v %v", e1, e2)
	}
	if f1.Path == f2.Path {
		t.Fatal("filename-only cache collision")
	}
	assertFile(t, f1, p1, fixture)
	assertFile(t, f2, p2, []byte("second"))
}

func TestTamperedCacheRejected(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write(fixture) }))
	defer srv.Close()
	opts := testOptions(t)
	m := manager(t, opts)
	p := payload(t, fixture, "payload.bin")
	got, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := opts.Cache.OpenFile(p.Identity.Key()+".data", os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt([]byte("X"), 0)
	f.Close()
	got, err = m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, got, p, fixture)
	if calls.Load() != 2 {
		t.Fatalf("tampered bytes reused, calls=%d", calls.Load())
	}
}

func manifest(t *testing.T, ps ...model.Payload) model.PayloadManifest {
	t.Helper()
	m, e := model.NewPayloadManifest(model.SourceIdentity{UpdateID: "fixture-revision", BuildLabel: "fixture", Architecture: model.ArchitectureAMD64, Language: "en-us"}, ps)
	if e != nil {
		t.Fatal(e)
	}
	return m
}

func TestExpiredURLRefreshPreservesManifestDigest(t *testing.T) {
	p := payload(t, fixture, "payload.bin")
	frozen := manifest(t, p)
	original := frozen.Digest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(fixture) }))
	defer srv.Close()
	for _, kind := range []string{"valid", "changed-identity", "mutates-input", "http-expiry"} {
		t.Run(kind, func(t *testing.T) {
			opts := testOptions(t)
			var refreshes atomic.Int32
			opts.Refresh = func(ctx context.Context, got model.PayloadManifest) (model.Locators, error) {
				refreshes.Add(1)
				if got.Digest != original || got.Validate() != nil {
					t.Error("refresh lost frozen identity")
				}
				id := p.Identity
				if kind == "changed-identity" {
					id.Size++
				}
				if kind == "mutates-input" {
					got.Payloads[0].Identity.Size++
				}
				return model.Locators{id: {URL: srv.URL}}, nil
			}
			m := manager(t, opts)
			loc := Locator{URL: "http://expired.invalid/?signed=secret", ExpiresAt: time.Now().Add(-time.Hour)}
			if kind == "http-expiry" {
				expired := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
				defer expired.Close()
				loc = Locator{URL: expired.URL + "/?signed=secret"}
			}
			got, err := m.Fetch(context.Background(), frozen, model.Locators{p.Identity: loc}, nil)
			if kind == "changed-identity" {
				if !errors.Is(err, ErrRefresh) {
					t.Fatalf("expected changed identity rejection, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertFile(t, got[p.Identity], p, fixture)
			if frozen.Digest != original || frozen.Validate() != nil {
				t.Fatal("caller frozen manifest mutated")
			}
			if refreshes.Load() != 1 {
				t.Fatalf("refreshes=%d", refreshes.Load())
			}
		})
	}
}

// Caller edits made after a first transfer must not change the query snapshot
// supplied to a later payload's refresh callback.
func TestFetchFreezesQueriesBeforeTransfers(t *testing.T) {
	first, second := payload(t, fixture, "first.bin"), payload(t, []byte("second"), "second.bin")
	base := manifest(t, first, second)
	frozen, err := model.NewPayloadManifest(base.Source, base.Payloads, model.SourceQuery{UpdateID: base.Source.UpdateID, Language: base.Source.Language, Edition: "CORE"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/second" {
			w.Write([]byte("second"))
		} else {
			w.Write(fixture)
		}
	}))
	defer srv.Close()
	opts := testOptions(t)
	opts.ParallelFiles = 1
	refreshed := false
	opts.Refresh = func(_ context.Context, got model.PayloadManifest) (model.Locators, error) {
		refreshed = true
		if got.Validate() != nil || got.Queries[0].Edition != "CORE" {
			t.Error("Fetch did not freeze caller queries")
			return nil, ErrRefresh
		}
		return model.Locators{first.Identity: {URL: srv.URL}, second.Identity: {URL: srv.URL + "/second"}}, nil
	}
	m := manager(t, opts)
	_, err = m.Fetch(context.Background(), frozen, model.Locators{first.Identity: {URL: srv.URL}, second.Identity: {URL: srv.URL + "/second", ExpiresAt: time.Now().Add(-time.Hour)}}, func(model.Event) { frozen.Queries[0].Edition = "mutated" })
	if err != nil || !refreshed {
		t.Fatalf("snapshot test did not complete refresh: %v", err)
	}
}

func TestPauseQuiescesTransfersAndScheduling(t *testing.T) {
	var requests atomic.Int32
	var resumed atomic.Int32
	started := make(chan struct{}, 4)
	persisted := make(chan struct{}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		if n <= 2 {
			w.Header().Set("ETag", `"original"`)
			w.Header().Set("Content-Length", fmt.Sprint(len(fixture)))
			w.Write(fixture[:7])
			w.(http.Flusher).Flush()
			started <- struct{}{}
			<-r.Context().Done()
			return
		}
		if r.URL.Path != "/three" {
			if r.Header.Get("Range") != "bytes=7-" {
				t.Error("pause lost retained partial")
			}
			resumed.Add(1)
			ranged(w, fixture, 7, `"original"`)
			return
		}
		w.Write(fixture)
	}))
	defer srv.Close()
	opts := testOptions(t)
	m := manager(t, opts)
	p1 := payload(t, fixture, "one.bin")
	p2 := payload(t, fixture, "two.bin")
	p3 := payload(t, fixture, "zthree.bin")
	done := make(chan error, 1)
	frozen := manifest(t, p1, p2, p3)
	go func() {
		_, e := m.Fetch(context.Background(), frozen, model.Locators{p1.Identity: {URL: srv.URL + "/one"}, p2.Identity: {URL: srv.URL + "/two"}, p3.Identity: {URL: srv.URL + "/three"}}, func(event model.Event) {
			if event.CompletedBytes != nil && *event.CompletedBytes == 7 {
				persisted <- struct{}{}
			}
		})
		done <- e
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("transfers did not start")
		}
		select {
		case <-persisted:
		case <-time.After(3 * time.Second):
			t.Fatal("partial bytes did not reach disk")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := m.Pause(ctx); e != nil {
		t.Fatal(e)
	}
	before := requests.Load()
	time.Sleep(40 * time.Millisecond)
	if requests.Load() != before {
		t.Fatal("scheduled network while paused")
	}
	select {
	case e := <-done:
		t.Fatalf("pause ended Fetch: %v", e)
	default:
	}
	if e := m.Resume(context.Background()); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("resume did not complete")
	}
	if resumed.Load() != 2 {
		t.Fatalf("resumed partials=%d", resumed.Load())
	}
}

type proxyResolverFunc func(context.Context, *url.URL) (*url.URL, error)

func (f proxyResolverFunc) Resolve(c context.Context, u *url.URL) (*url.URL, error) { return f(c, u) }

func TestSystemProxyUsesWindowsResolver(t *testing.T) {
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "origin.invalid:4321" || r.URL.Path != "/payload" {
			t.Errorf("proxy received wrong target: %s", r.URL.Redacted())
		}
		calls.Add(1)
		w.Write(fixture)
	}))
	defer proxy.Close()
	u, _ := url.Parse(proxy.URL)
	opts := testOptions(t)
	opts.Proxy = model.ProxySettings{Mode: model.ProxySystem}
	key := struct{}{}
	ctx := context.WithValue(context.Background(), key, "request-context")
	opts.SystemProxy = proxyResolverFunc(func(c context.Context, target *url.URL) (*url.URL, error) {
		if c.Value(key) != "request-context" {
			t.Error("resolver lost request context")
		}
		if target.String() != "http://origin.invalid:4321/payload" {
			t.Errorf("resolver target=%s", target.Redacted())
		}
		return u, nil
	})
	m := manager(t, opts)
	p := payload(t, fixture, "payload.bin")
	got, e := m.FetchOne(ctx, p, Locator{URL: "http://origin.invalid:4321/payload"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	assertFile(t, got, p, fixture)
	if calls.Load() != 1 {
		t.Fatal("request did not use URL-specific proxy port")
	}
}

func TestManagerLeaseAndCacheReopen(t *testing.T) {
	opts := testOptions(t)
	m := manager(t, opts)
	if other, e := NewManager(opts); e == nil {
		other.Close()
		t.Fatal("two managers own same workspaces")
	}
	for _, same := range []Options{{Cache: opts.Cache, Job: opts.Cache}, {Cache: opts.Job, Job: opts.Job}} {
		if other, e := NewManager(same); e == nil {
			other.Close()
			t.Fatal("same roots accepted")
		}
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write(fixture) }))
	defer srv.Close()
	p := payload(t, fixture, "payload.bin")
	got, e := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
	if e != nil {
		t.Fatal(e)
	}
	assertFile(t, got, p, fixture)
	if e = m.Close(); e != nil {
		t.Fatal(e)
	}
	cache, e := windows.OpenWorkspace(opts.Cache.Identity())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cache.Close() })
	job, e := windows.OpenWorkspace(opts.Job.Identity())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { job.Close() })
	opts.Cache = cache
	opts.Job = job
	m2 := manager(t, opts)
	got, e = m2.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
	if e != nil {
		t.Fatal(e)
	}
	assertFile(t, got, p, fixture)
	if calls.Load() != 1 {
		t.Fatal("restart did not reuse verified cache")
	}
}

func TestCancelAndCloseQuiesce(t *testing.T) {
	for _, kind := range []string{"cancel", "close", "paused-cancel"} {
		t.Run(kind, func(t *testing.T) {
			started := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
			defer srv.Close()
			opts := testOptions(t)
			m := manager(t, opts)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			if kind == "paused-cancel" {
				if e := m.Pause(ctx); e != nil {
					t.Fatal(e)
				}
			}
			go func() { _, e := m.FetchOne(ctx, payload(t, fixture, "p.bin"), Locator{URL: srv.URL}, nil); done <- e }()
			if kind != "paused-cancel" {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("not started")
				}
			}
			if kind == "close" {
				if e := m.Close(); e != nil {
					t.Fatal(e)
				}
			} else {
				cancel()
			}
			select {
			case e := <-done:
				if !errors.Is(e, context.Canceled) && !errors.Is(e, ErrClosed) {
					t.Fatalf("cancellation=%v", e)
				}
			case <-time.After(time.Second):
				t.Fatal("unbounded cancel")
			}
		})
	}
}

func TestPublicAndPersistentDataRedactLocators(t *testing.T) {
	const secret = "signed-credential-secret"
	opts := testOptions(t)
	opts.Retries = 0
	m := manager(t, opts)
	p := payload(t, fixture, "payload.bin")
	var events []model.Event
	var mu sync.Mutex
	_, e := m.FetchOne(context.Background(), p, Locator{URL: "http://127.0.0.1:1/?signature=" + secret}, func(e model.Event) { mu.Lock(); defer mu.Unlock(); events = append(events, e) })
	if !errors.Is(e, ErrTransfer) {
		t.Fatalf("expected network failure, got %v", e)
	}
	if strings.Contains(e.Error(), secret) {
		t.Fatal("error leaks locator")
	}
	b, _ := json.Marshal(events)
	if strings.Contains(string(b), secret) {
		t.Fatal("event leaks locator")
	}
	for _, w := range []*windows.Workspace{opts.Job, opts.Cache} {
		entries, _ := os.ReadDir(w.Path())
		for _, entry := range entries {
			if entry.IsDir() || entry.Name() == ".uupbuilder-owner.json" {
				continue
			}
			f, err := w.OpenFile(entry.Name(), os.O_RDONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(f)
			f.Close()
			if strings.Contains(string(data), secret) {
				t.Fatal("persistent data leaks locator")
			}
		}
	}
}
