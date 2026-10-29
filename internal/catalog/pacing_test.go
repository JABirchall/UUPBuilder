package catalog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// suppliedLimiter models the user's PHP function, including the write before
// rejecting a repeated resource. Its timestamps come from the test clock.
type suppliedLimiter struct {
	resource string
	last     time.Time
}

func (s *suppliedLimiter) limited(resource string, now time.Time) bool {
	if s.resource == "" {
		s.resource = resource
	}
	if s.last.Add(10*time.Second).After(now) && s.resource != resource {
		return true
	}
	last, previous := s.last, s.resource
	s.last, s.resource = now, resource
	return last.Add(time.Second).After(now) && previous == resource
}

func TestSuppliedLimiterStateMachine(t *testing.T) {
	start := time.Unix(1700000000, 0)
	t.Run("resource switch does not reset timer", func(t *testing.T) {
		var s suppliedLimiter
		if s.limited("A", start) || !s.limited("B", start.Add(9999*time.Millisecond)) || s.resource != "A" || !s.last.Equal(start) || s.limited("B", start.Add(10*time.Second)) {
			t.Fatal("different-resource state differs from supplied PHP")
		}
	})
	t.Run("rejected repeat resets timer", func(t *testing.T) {
		var s suppliedLimiter
		if s.limited("A", start) || !s.limited("A", start.Add(500*time.Millisecond)) || !s.last.Equal(start.Add(500*time.Millisecond)) || !s.limited("A", start.Add(1250*time.Millisecond)) || s.limited("A", start.Add(2250*time.Millisecond)) {
			t.Fatal("same-resource rejection lost its timer mutation")
		}
	})
}

func TestGetRequestsRespectSuppliedIPLimiter(t *testing.T) {
	clock := &testClock{now: time.Unix(1700000000, 0)}
	var limiter suppliedLimiter
	var sends []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends = append(sends, clock.Now())
		if limiter.limited(r.URL.Query().Get("resource"), clock.Now()) {
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"response":{"error":"USER_RATE_LIMITED"}}`)
			return
		}
		fmt.Fprint(w, `{"response":{}}`)
	}))
	defer server.Close()
	c := New(server.Client(), server.URL)
	c.Clock = clock
	c.Pacer = NewGetPacer(clock)
	for _, resource := range []string{"A", "B", "B", "C"} {
		if _, err := c.fetch(context.Background(), "get.php", url.Values{"resource": {resource}}); err != nil {
			t.Fatalf("resource %s failed against supplied limiter: %v", resource, err)
		}
	}
	for i := 1; i < len(sends); i++ {
		if gap := sends[i].Sub(sends[i-1]); gap < 10250*time.Millisecond {
			t.Fatalf("actual send gap %v is below 10.25s", gap)
		}
	}
}

type pacingClock struct {
	mu      sync.Mutex
	now     time.Time
	onSleep func(context.Context)
}

func newPacingClock() *pacingClock    { return &pacingClock{now: time.Unix(1700000000, 0)} }
func (c *pacingClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *pacingClock) Sleep(ctx context.Context, d time.Duration) error {
	if c.onSleep != nil {
		c.onSleep(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	return nil
}

func TestGetPacerSerializesClientsAndRetries(t *testing.T) {
	clock := newPacingClock()
	var mu sync.Mutex
	var sends []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sends = append(sends, clock.Now())
		count := len(sends)
		mu.Unlock()
		if count == 1 {
			fmt.Fprint(w, `{"response":{"error":"USER_RATE_LIMITED"}}`)
			return
		}
		fmt.Fprint(w, `{"response":{}}`)
	}))
	defer server.Close()
	pacer := NewGetPacer(clock)
	errs := make(chan error, 2)
	for range 2 {
		c := New(server.Client(), server.URL)
		c.Clock, c.Pacer = clock, pacer
		go func() { _, err := c.fetch(context.Background(), "get.php", nil); errs <- err }()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if len(sends) != 3 {
		t.Fatalf("wanted three actual attempts, got %d", len(sends))
	}
	for i := 1; i < len(sends); i++ {
		if gap := sends[i].Sub(sends[i-1]); gap < 10250*time.Millisecond {
			t.Fatalf("concurrent/retried send gap %v", gap)
		}
	}
}

func TestGetPacerRetainsCooldownAfterCancellation(t *testing.T) {
	clock := newPacingClock()
	start := clock.Now()
	p := NewGetPacer(clock)
	ctx, cancel := context.WithCancel(context.Background())
	_, err := p.Do(ctx, func(context.Context) (*http.Response, error) { cancel(); return nil, ctx.Err() })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	_, err = p.Do(context.Background(), func(context.Context) (*http.Response, error) {
		if gap := clock.Now().Sub(start); gap != 10250*time.Millisecond {
			t.Fatalf("sent cancellation erased cooldown: %v", gap)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetPacerDoesNotReserveUnsentRequest(t *testing.T) {
	clock := newPacingClock()
	start := clock.Now()
	p := NewGetPacer(clock)
	_, _ = p.Do(context.Background(), func(context.Context) (*http.Response, error) { return nil, nil })
	ctx, cancel := context.WithCancel(context.Background())
	clock.onSleep = func(context.Context) { cancel() }
	_, err := p.Do(ctx, func(context.Context) (*http.Response, error) {
		t.Fatal("canceled queued request was sent")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	clock.onSleep = nil
	_, err = p.Do(context.Background(), func(context.Context) (*http.Response, error) {
		if gap := clock.Now().Sub(start); gap != 10250*time.Millisecond {
			t.Fatalf("unsent request reserved an extra interval: %v", gap)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetPacerCancelsWhileAnotherSendOwnsAdmission(t *testing.T) {
	p := NewGetPacer(newPacingClock())
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = p.Do(context.Background(), func(context.Context) (*http.Response, error) { close(started); <-release; return nil, nil })
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := p.Do(ctx, func(context.Context) (*http.Response, error) {
		t.Error("canceled queued call was sent")
		return nil, nil
	})
	close(release)
	<-finished
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued admission ignored cancellation: %v", err)
	}
}

func TestGetPacerHonorsLongerRetryAfter(t *testing.T) {
	for _, tt := range []struct {
		header string
		want   time.Duration
		later  bool
	}{
		{"", 10250 * time.Millisecond, false}, {"0", 10250 * time.Millisecond, false},
		{"20", 20 * time.Second, false}, {"Tue, 14 Nov 2023 22:13:40 GMT", 20 * time.Second, false},
		{"121", 0, true}, {"18446744073709551616", 0, true},
	} {
		t.Run(tt.header, func(t *testing.T) {
			clock := newPacingClock()
			start := clock.Now()
			p := NewGetPacer(clock)
			_, _ = p.Do(context.Background(), func(context.Context) (*http.Response, error) {
				return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {tt.header}}}, nil
			})
			called := false
			_, err := p.Do(context.Background(), func(context.Context) (*http.Response, error) { called = true; return nil, nil })
			var later *RetryLaterError
			if tt.later {
				if !errors.As(err, &later) || called || !clock.Now().Equal(start) {
					t.Fatalf("excessive cooldown was waited/bypassed: %v sent=%v", err, called)
				}
			} else if err != nil || !called || clock.Now().Sub(start) != tt.want {
				t.Fatalf("cooldown ignored: %v elapsed=%v", err, clock.Now().Sub(start))
			}
		})
	}
}

func TestEndpointReloadSharesGetCooldown(t *testing.T) {
	clock := newPacingClock()
	var sends []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends = append(sends, clock.Now())
		fmt.Fprint(w, `{"response":{}}`)
	}))
	defer server.Close()
	first := New(server.Client(), server.URL+"/api/")
	first.Pacer.clock = clock
	first.Clock = clock
	if _, err := first.fetch(context.Background(), "get.php", nil); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{server.URL + "/api", server.URL + "/other/"} {
		reloaded := New(server.Client(), endpoint)
		reloaded.Clock = clock
		if _, err := reloaded.fetch(context.Background(), "get.php", nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(sends) != 3 || sends[1].Sub(sends[0]) != 10250*time.Millisecond || sends[2].Sub(sends[1]) != 10250*time.Millisecond {
		t.Fatalf("recomposition reset shared timing: %v", sends)
	}
}

func TestGetQueueDoesNotConsumeRequestTimeoutOrPaceDiscovery(t *testing.T) {
	clock := newPacingClock()
	start := clock.Now()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"response":{}}`) }))
	defer server.Close()
	c := New(server.Client(), server.URL)
	c.Clock, c.Pacer = clock, NewGetPacer(clock)
	c.RequestTimeout = 30 * time.Millisecond
	if _, err := c.fetch(context.Background(), "get.php", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.fetch(context.Background(), "listeditions.php", nil); err != nil || !clock.Now().Equal(start) {
		t.Fatalf("unrelated discovery was delayed: %v", err)
	}
	clock.onSleep = func(context.Context) { time.Sleep(60 * time.Millisecond) }
	if _, err := c.fetch(context.Background(), "get.php", nil); err != nil {
		t.Fatalf("queue consumed HTTP timeout: %v", err)
	}
}

func TestGetRateLimitRetriesAreBoundedWithoutHeader(t *testing.T) {
	for _, status := range []int{200, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			clock := newPacingClock()
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(status)
				fmt.Fprint(w, `{"response":{"error":"USER_RATE_LIMITED"}}`)
			}))
			defer server.Close()
			c := New(server.Client(), server.URL)
			c.Clock, c.Pacer = clock, NewGetPacer(clock)
			_, err := c.fetch(context.Background(), "get.php", nil)
			var api *APIError
			if !errors.As(err, &api) || api.Code != "USER_RATE_LIMITED" || calls != 3 {
				t.Fatalf("unbounded/unretried API limit: %v calls=%d", err, calls)
			}
		})
	}
}

func TestMetadataOnlySkipsLimiterButUpdatesSharedCooldown(t *testing.T) {
	clock := newPacingClock()
	start := clock.Now()
	var limiter suppliedLimiter
	var sends []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends = append(sends, clock.Now())
		// The wrapper evaluates the limiter before checking noLinks.
		limited := limiter.limited(r.URL.Query().Get("resource"), clock.Now())
		if limited && r.URL.Query().Get("noLinks") != "1" {
			w.WriteHeader(429)
			fmt.Fprint(w, `{"response":{"error":"USER_RATE_LIMITED"}}`)
			return
		}
		fmt.Fprint(w, `{"response":{}}`)
	}))
	defer server.Close()
	c := New(server.Client(), server.URL)
	c.Clock, c.Pacer = clock, NewGetPacer(clock)
	for _, resource := range []string{"A", "A", "B"} {
		if _, err := c.fetch(context.Background(), "get.php", url.Values{"resource": {resource}, "noLinks": {"1"}}); err != nil {
			t.Fatal(err)
		}
	}
	if !clock.Now().Equal(start) {
		t.Fatal("metadata-only requests were needlessly paced")
	}
	if _, err := c.fetch(context.Background(), "get.php", url.Values{"resource": {"C"}, "noLinks": {"0"}}); err != nil {
		t.Fatal(err)
	}
	if len(sends) != 4 || sends[3].Sub(sends[2]) != 10250*time.Millisecond {
		t.Fatalf("metadata lost shared cooldown: %v", sends)
	}
}
