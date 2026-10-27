//go:build windows

package download

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"uupbuilder/internal/model"
)

func TestResumeWaitsForPendingPause(t *testing.T) {
	var requests atomic.Int32
	cancelled := make(chan struct{})
	observing := make(chan struct{})
	release := make(chan struct{})
	var once, releaseOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("ETag", `"original"`)
			w.Header().Set("Content-Length", fmt.Sprint(len(fixture)))
			w.Write(fixture[:7])
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(cancelled)
			return
		}
		ranged(w, fixture, 7, `"original"`)
	}))
	defer srv.Close()
	m := manager(t, testOptions(t))
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	p := payload(t, fixture, "p.bin")
	fetchDone := make(chan error, 1)
	go func() {
		_, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, func(model.Event) { once.Do(func() { close(observing); <-release }) })
		fetchDone <- err
	}()
	select {
	case <-observing:
	case <-time.After(2 * time.Second):
		t.Fatal("transfer did not report bytes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	paused := make(chan error, 1)
	go func() { paused <- m.Pause(ctx) }()
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("pause did not cancel IO")
	}
	resumed := make(chan error, 1)
	go func() { resumed <- m.Resume(ctx) }()
	select {
	case err := <-resumed:
		t.Fatalf("Resume completed before pending Pause quiesced: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	for _, done := range []chan error{paused, resumed, fetchDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("control call did not complete")
		}
	}
}
