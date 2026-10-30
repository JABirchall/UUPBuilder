//go:build windows

package download

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"uupbuilder/internal/model"
)

type downloadEventSnapshot struct {
	Download       *struct{ ID, Name, State string } `json:"download"`
	CompletedBytes *int64                            `json:"completed_bytes"`
	TotalBytes     *int64                            `json:"total_bytes"`
}

func snapshotEvent(t *testing.T, e model.Event) downloadEventSnapshot {
	t.Helper()
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var got downloadEventSnapshot
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestDownloadEventsIdentifyConcurrentFilesAndFinishAfterPublication(t *testing.T) {
	// Generic messages cannot distinguish parallel files. Completion must only
	// be observable once the verified cache entry is actually reusable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(fixture) }))
	defer srv.Close()
	p, q := payload(t, fixture, "packages/source.esd"), payload(t, fixture, "apps/source.esd")
	m := manager(t, testOptions(t))
	var mu sync.Mutex
	var events []downloadEventSnapshot
	emit := func(e model.Event) {
		got := snapshotEvent(t, e)
		if got.Download != nil && got.Download.State == "completed" {
			id := p.Identity
			if got.Download.Name == q.Destination {
				id = q.Identity
			}
			if _, found, err := m.cached(context.Background(), id); err != nil || !found {
				t.Errorf("completed event preceded verified publication: found=%t err=%v", found, err)
			}
		}
		mu.Lock()
		defer mu.Unlock()
		events = append(events, got)
	}
	_, err := m.Fetch(context.Background(), manifest(t, p, q), model.Locators{p.Identity: {URL: srv.URL + "?signature=private-a"}, q.Identity: {URL: srv.URL + "?signature=private-b"}}, emit)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	finished := map[string]bool{}
	for _, e := range events {
		if e.Download == nil || e.Download.ID == "" {
			t.Fatalf("event has no file identity: %+v", e)
		}
		if strings.Contains(e.Download.Name, "private") || strings.Contains(e.Download.ID, "private") {
			t.Fatal("event exposed signed locator")
		}
		ids[e.Download.Name] = e.Download.ID
		if e.Download.State == "completed" {
			if e.CompletedBytes == nil || *e.CompletedBytes != int64(len(fixture)) || e.TotalBytes == nil || *e.TotalBytes != int64(len(fixture)) {
				t.Fatalf("completed event lost counters: %+v", e)
			}
			finished[e.Download.Name] = true
		}
	}
	if ids[p.Destination] == "" || ids[q.Destination] == "" || ids[p.Destination] == ids[q.Destination] || !finished[p.Destination] || !finished[q.Destination] {
		t.Fatalf("parallel files lack distinct lifecycle: ids=%v completed=%v", ids, finished)
	}
	// A verified cache hit must also produce a terminal row, without requiring IO.
	var hit []downloadEventSnapshot
	if _, err := m.FetchOne(context.Background(), p, Locator{}, func(e model.Event) { hit = append(hit, snapshotEvent(t, e)) }); err != nil {
		t.Fatal(err)
	}
	if len(hit) == 0 || hit[len(hit)-1].Download == nil || hit[len(hit)-1].Download.State != "completed" {
		t.Fatalf("cache hit has no completion: %+v", hit)
	}
}

func TestBadDigestNeverEmitsDownloadCompleted(t *testing.T) {
	bad := bytes.Repeat([]byte{'x'}, len(fixture))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(bad) }))
	defer srv.Close()
	m := manager(t, testOptions(t))
	var events []downloadEventSnapshot
	_, err := m.FetchOne(context.Background(), payload(t, fixture, "bad.bin"), Locator{URL: srv.URL}, func(e model.Event) { events = append(events, snapshotEvent(t, e)) })
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("expected digest failure, got %v", err)
	}
	for _, e := range events {
		if e.Download != nil && e.Download.State == "completed" {
			t.Fatal("digest failure reported completion")
		}
	}
	if len(events) == 0 || events[len(events)-1].Download == nil || events[len(events)-1].Download.State != "failed" {
		t.Fatalf("failed transfer has no terminal event: %+v", events)
	}
}

func TestDownloadProgressRetainsIdentityAndResumeOffsetAcrossRetry(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			initial(w, fixture, 13)
			return
		}
		ranged(w, fixture, 13, `"original"`)
	}))
	defer srv.Close()
	m := manager(t, testOptions(t))
	var events []downloadEventSnapshot
	_, err := m.FetchOne(context.Background(), payload(t, fixture, "resume.bin"), Locator{URL: srv.URL}, func(e model.Event) { events = append(events, snapshotEvent(t, e)) })
	if err != nil {
		t.Fatal(err)
	}
	var id string
	resumed, retrying := false, false
	for _, e := range events {
		if e.Download == nil {
			t.Fatalf("retry event lacks file identity: %+v", e)
		}
		if id == "" {
			id = e.Download.ID
		}
		if e.Download.ID != id {
			t.Fatal("retry created a different progress row")
		}
		if e.Download.State == "retrying" {
			retrying = true
		}
		if retrying && e.Download.State == "downloading" && e.CompletedBytes != nil && *e.CompletedBytes == 13 {
			resumed = true
		}
	}
	if !retrying || !resumed {
		t.Fatalf("retry did not announce existing prefix: %+v", events)
	}
}

func TestDownloadProgressThrottlesChunksAndPreservesCompletion(t *testing.T) {
	// The clock is frozen so only lifecycle and the first data sample should be
	// emitted, even when the real HTTP body spans hundreds of bounded reads.
	data := bytes.Repeat([]byte("payload"), 512*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(data) }))
	defer srv.Close()
	opts := testOptions(t)
	opts.Now = func() time.Time { return time.Unix(100, 0) }
	m := manager(t, opts)
	var events []downloadEventSnapshot
	_, err := m.FetchOne(context.Background(), payload(t, data, "large.bin"), Locator{URL: srv.URL}, func(e model.Event) { events = append(events, snapshotEvent(t, e)) })
	if err != nil {
		t.Fatal(err)
	}
	if len(events) > 8 {
		t.Fatalf("unthrottled transfer emitted %d events", len(events))
	}
	if len(events) == 0 || events[len(events)-1].Download == nil || events[len(events)-1].Download.State != "completed" || events[len(events)-1].CompletedBytes == nil || *events[len(events)-1].CompletedBytes != int64(len(data)) {
		t.Fatalf("throttling lost final progress: %+v", events)
	}
}

func TestCancelledDownloadEmitsTerminalProgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture[:7])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	opts := testOptions(t)
	m := manager(t, opts)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []downloadEventSnapshot
	_, err := m.FetchOne(ctx, payload(t, fixture, "cancel.bin"), Locator{URL: srv.URL}, func(e model.Event) {
		events = append(events, snapshotEvent(t, e))
		if e.CompletedBytes != nil && *e.CompletedBytes == 7 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if len(events) == 0 || events[len(events)-1].Download == nil || events[len(events)-1].Download.State != "cancelled" || events[len(events)-1].CompletedBytes == nil || *events[len(events)-1].CompletedBytes != 7 {
		t.Fatalf("cancellation lost final bytes/state: %+v", events)
	}
}
