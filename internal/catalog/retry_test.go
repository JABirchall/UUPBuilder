package catalog

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type testClock struct {
	now     time.Time
	waits   []time.Duration
	onSleep func()
}

func TestRetryAfterDateAndLongDelay(t *testing.T) {
	for _, tt := range []struct {
		name, header string
		wantRequests int32
		wantWait     time.Duration
	}{
		{"date", "Tue, 14 Nov 2023 22:13:29 GMT", 3, 9 * time.Second},
		{"too-long", "3600", 1, 0},
		{"overflow", "99999999999999999999999999999999999999", 1, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Retry-After", tt.header)
				w.WriteHeader(429)
				_, _ = w.Write([]byte(`{"response":{"error":"USER_RATE_LIMITED"}}`))
			}))
			defer s.Close()
			clock := &testClock{now: time.Unix(1700000000, 0)}
			c := New(s.Client(), s.URL)
			c.Clock = clock
			if _, err := c.Search(context.Background(), ""); err == nil {
				t.Fatal("rate limit accepted")
			}
			if requests.Load() != tt.wantRequests {
				t.Fatalf("server retry boundary ignored: %d", requests.Load())
			}
			if tt.wantWait > 0 && (len(clock.waits) == 0 || clock.waits[0] != tt.wantWait) {
				t.Fatalf("HTTP date ignored: %v", clock.waits)
			}
		})
	}
}

func (c *testClock) Now() time.Time { return c.now }
func (c *testClock) Sleep(ctx context.Context, d time.Duration) error {
	c.waits = append(c.waits, d)
	if c.onSleep != nil {
		c.onSleep()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.now = c.now.Add(d)
	return nil
}

func TestRetryAfterAndCancellation(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "bounded", true: "cancelled"}[cancel], func(t *testing.T) {
			var requests atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Retry-After", "7")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"response":{"error":"USER_RATE_LIMITED"},"jsonApiVersion":"0.2.3"}`))
			}))
			defer s.Close()
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			clock := &testClock{now: time.Unix(1700000000, 0)}
			if cancel {
				clock.onSleep = stop
			}
			c := New(s.Client(), s.URL)
			c.Clock = clock
			_, err := c.Search(ctx, "")
			if cancel {
				if !errors.Is(err, context.Canceled) || requests.Load() != 1 {
					t.Fatalf("cancellation: requests=%d error=%v", requests.Load(), err)
				}
			} else {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.Code != "USER_RATE_LIMITED" || requests.Load() != 3 {
					t.Fatalf("bounded retries: requests=%d error=%v", requests.Load(), err)
				}
				if len(clock.waits) != 2 || clock.waits[0] != 7*time.Second || clock.waits[1] != 7*time.Second {
					t.Fatalf("Retry-After ignored: %v", clock.waits)
				}
			}
		})
	}
}
