//go:build windows

package download

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMalformedETagCannotAuthorizeResume(t *testing.T) {
	// Accepting a non-RFC entity tag here would append under an invalid validator.
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"invalid space"`)
		if count.Add(1) == 1 {
			w.Header().Set("Content-Length", fmt.Sprint(len(fixture)))
			w.Write(fixture[:13])
			return
		}
		if r.Header.Get("Range") != "" {
			t.Error("malformed ETag authorized Range")
		}
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

func TestLastModifiedRequiresStrongDateEvidence(t *testing.T) {
	for _, kind := range []string{"old", "same-second", "no-date"} {
		t.Run(kind, func(t *testing.T) {
			var count atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
				switch kind {
				case "old":
					w.Header().Set("Date", "Wed, 21 Oct 2015 07:30:00 GMT")
				case "same-second":
					w.Header().Set("Date", "Wed, 21 Oct 2015 07:28:00 GMT")
				case "no-date":
					w.Header()["Date"] = nil
				}
				if count.Add(1) == 1 {
					w.Header().Set("Content-Length", fmt.Sprint(len(fixture)))
					w.Write(fixture[:13])
					return
				}
				if kind == "old" {
					if r.Header.Get("Range") != "bytes=13-" {
						t.Error("old Last-Modified not resumed")
					}
					w.Header().Set("Content-Range", fmt.Sprintf("bytes 13-%d/%d", len(fixture)-1, len(fixture)))
					w.WriteHeader(206)
					w.Write(fixture[13:])
					return
				}
				if r.Header.Get("Range") != "" {
					t.Error("weak modification date authorized Range")
				}
				w.Write(fixture)
			}))
			defer srv.Close()
			m := manager(t, testOptions(t))
			p := payload(t, fixture, "p.bin")
			got, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
			if err != nil {
				t.Fatal(err)
			}
			assertFile(t, got, p, fixture)
		})
	}
}

func TestStreamRefusesOversizedChunkedPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		w.Write(append(append([]byte(nil), fixture...), byte('X')))
	}))
	defer srv.Close()
	m := manager(t, testOptions(t))
	_, err := m.FetchOne(context.Background(), payload(t, fixture, "p.bin"), Locator{URL: srv.URL}, nil)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("oversized object=%v", err)
	}
}

func TestEmptyPayloadVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Length", "0") }))
	defer srv.Close()
	m := manager(t, testOptions(t))
	p := payload(t, nil, "empty.bin")
	got, err := m.FetchOne(context.Background(), p, Locator{URL: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, got, p, nil)
}

func TestRetryCountAndRequestTimeoutAreBounded(t *testing.T) {
	for _, kind := range []string{"status", "body-timeout"} {
		t.Run(kind, func(t *testing.T) {
			var count atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				if kind == "status" {
					w.WriteHeader(503)
					return
				}
				w.Header().Set("Content-Length", fmt.Sprint(len(fixture)))
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			defer srv.Close()
			opts := testOptions(t)
			opts.Retries = 1
			opts.RequestTimeout = 100 * time.Millisecond
			m := manager(t, opts)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err := m.FetchOne(ctx, payload(t, fixture, "p.bin"), Locator{URL: srv.URL + "/?secret=private"}, nil)
			if !errors.Is(err, ErrTransfer) {
				t.Fatalf("bounded retry result=%v", err)
			}
			if count.Load() != 2 {
				t.Fatalf("requests=%d, want exactly 2", count.Load())
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("timeout leaked URL")
			}
		})
	}
}
