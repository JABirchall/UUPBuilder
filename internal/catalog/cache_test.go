package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheReportsStaleFetchFailure(t *testing.T) {
	var requests atomic.Int32
	var fail atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if fail.Load() {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"response":{"error":"REFRESH_FAILED"}}`))
			return
		}
		_, _ = w.Write(fixture(t, "builds-sparse.json"))
	}))
	defer s.Close()
	clock := &testClock{now: time.Unix(1700000000, 0)}
	c := New(s.Client(), s.URL)
	c.Clock = clock
	initial, err := c.Search(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	initial[0].Title = "caller mutation"
	fail.Store(true)
	if _, err := c.Search(context.Background(), "test"); err != nil || requests.Load() != 1 {
		t.Fatalf("fresh cache: %v, %d requests", err, requests.Load())
	}
	clock.now = clock.now.Add(24 * time.Hour)
	stale, err := c.Search(context.Background(), "test")
	var staleErr *StaleError
	var apiErr *APIError
	if len(stale) != 3 || stale[0].Title == "caller mutation" || !errors.As(err, &staleErr) || !errors.As(err, &apiErr) || apiErr.Code != "REFRESH_FAILED" {
		t.Fatalf("stale data and refresh failure must travel together: %+v, %v", stale, err)
	}
	if staleErr.FetchedAt.Unix() != 1700000000 {
		t.Fatalf("wrong freshness: %v", staleErr.FetchedAt)
	}
	_, err = c.Search(WithRefresh(context.Background()), "test")
	if err == nil || requests.Load() != 3 {
		t.Fatalf("explicit refresh missing: %d requests, %v", requests.Load(), err)
	}
}

func TestDefaultCacheBoundsSearchHistory(t *testing.T) {
	cache := NewMemoryCache()
	for i := 0; i < 256; i++ {
		cache.Store(strconv.Itoa(i), CacheEntry{Data: []byte(strings.Repeat("x", 1024)), FetchedAt: time.Unix(int64(i), 0)})
	}
	if _, exists := cache.Load("0"); exists {
		t.Fatal("unbounded cache retained oldest search")
	}
	if entry, exists := cache.Load("255"); !exists || len(entry.Data) != 1024 {
		t.Fatal("cache evicted newest search")
	}
	if len(cache.entries) > 128 {
		t.Fatalf("discovery cache exceeds documented entry bound: %d", len(cache.entries))
	}
}

func TestDiscoveryCacheStoresOnlyPublicFields(t *testing.T) {
	data := strings.Replace(string(fixture(t, "builds-array.json")), `"jsonApiVersion":"0.2.3"`, `"debug":{"url":"https://payload.invalid/?token=private"},"jsonApiVersion":"0.2.3"`, 1)
	s := serveJSON(t, []byte(data))
	c := New(s.Client(), s.URL)
	if _, err := c.Search(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	cache := c.Cache.(*MemoryCache)
	for _, entry := range cache.entries {
		if strings.Contains(string(entry.Data), "private") {
			t.Fatal("cache retained an unknown response field containing a locator")
		}
		if !json.Valid(entry.Data) {
			t.Fatal("cache must contain sanitized JSON")
		}
	}
}
