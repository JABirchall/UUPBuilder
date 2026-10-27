package catalog

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequestTimeoutRetainsDeadlineCause(t *testing.T) {
	var requests atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); <-r.Context().Done() }))
	defer s.Close()
	c := New(s.Client(), s.URL)
	c.RequestTimeout = 10 * time.Millisecond
	c.Clock = &testClock{now: time.Unix(1700000000, 0)}
	_, err := c.Search(context.Background(), "")
	if !errors.Is(err, context.DeadlineExceeded) || requests.Load() != 3 {
		t.Fatalf("timeout cause/retry bound lost: %v, requests=%d", err, requests.Load())
	}
}

func TestInjectedHTTPTimeoutRetainsDeadlineCause(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	httpClient := s.Client()
	httpClient.Timeout = 10 * time.Millisecond
	c := New(httpClient, s.URL)
	c.Clock = &testClock{now: time.Unix(1700000000, 0)}
	if _, err := c.Search(context.Background(), ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("injected timeout cause lost: %v", err)
	}
}

func TestResponseBoundsAndEnvelopeFailures(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		status     int
		limit      int64
	}{
		{"oversize", strings.Repeat("x", 129), 200, 128},
		{"missing-response", `{"builds":[]}`, 200, 1024},
		{"null-response", `{"response":null}`, 200, 1024},
		{"bad-json", `{"response":`, 200, 1024},
		{"invalid-builds", `{"response":{"builds":null}}`, 200, 1024},
		{"error-at-success", `{"response":{"error":"UNKNOWN_UPDATE"}}`, 200, 1024},
		{"error-status", `{"response":{}}`, 404, 1024},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var count atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer s.Close()
			c := New(s.Client(), s.URL)
			c.MaxBodyBytes = tt.limit
			if _, err := c.Search(context.Background(), ""); err == nil || count.Load() != 1 {
				t.Fatalf("bad response accepted/retried: err=%v requests=%d", err, count.Load())
			}
		})
	}
}

func TestDefaultEndpointAndInputValidation(t *testing.T) {
	if c := New(nil, ""); c.base.String() != "https://api.uupdump.net/" {
		t.Fatal("official HTTPS default changed")
	}
	var requests atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer s.Close()
	c := New(s.Client(), s.URL)
	for _, id := range []string{"", "123", sourceID + "_rev.0", sourceID + "&secret=bad"} {
		if _, err := c.Languages(context.Background(), id); err == nil {
			t.Fatalf("invalid ID accepted: %q", id)
		}
	}
	if _, err := c.Editions(context.Background(), sourceID, "en-us&x=1"); err == nil {
		t.Fatal("invalid language accepted")
	}
	if _, err := c.Files(context.Background(), sourceID, "en-us", ""); err == nil {
		t.Fatal("empty edition accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("invalid selection reached upstream")
	}
	for _, base := range []string{"file:///tmp", "https://user:secret@example.invalid", "https://example.invalid/?token=secret"} {
		_, err := New(nil, base).Search(context.Background(), "")
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid base accepted/leaked: %v", err)
		}
	}
}

func TestUpstreamErrorsDoNotLeakSecrets(t *testing.T) {
	s := serveJSON(t, []byte(`{"response":{"error":"https://payload.invalid/?token=private"}}`))
	_, err := New(s.Client(), s.URL).Search(context.Background(), "")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "UPSTREAM_ERROR" || strings.Contains(err.Error(), "private") {
		t.Fatalf("unsafe error: %v", err)
	}
}
