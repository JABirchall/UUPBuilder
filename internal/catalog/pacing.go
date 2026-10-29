package catalog

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const getInterval = 10*time.Second + 250*time.Millisecond
const maximumRetryWait = 2 * time.Minute

// RetryLaterError reports a server cooldown that exceeds this call's bounded
// waiting budget. The shared cooldown remains in force for later calls.
type RetryLaterError struct{ RetryAt time.Time }

func (e *RetryLaterError) Error() string {
	return fmt.Sprintf("service cooldown: retry later (after %s)", e.RetryAt.UTC().Format(time.RFC3339))
}

// GetPacer serializes get.php attempts for one service. Metadata-only requests
// bypass its interval but still update timing: the upstream wrapper invokes
// checkIfUserIsRateLimited even when noLinks=1 suppresses its rejection.
type GetPacer struct {
	gate          chan struct{}
	clock         Clock
	next, retryAt time.Time
}

func NewGetPacer(clock Clock) *GetPacer {
	if clock == nil {
		clock = systemClock{}
	}
	return &GetPacer{gate: make(chan struct{}, 1), clock: clock}
}

var servicePacers sync.Map

func sharedGetPacer(base *url.URL) *GetPacer {
	// Paths and scheme spelling do not create independent server IP limits.
	host := strings.ToLower(strings.TrimSuffix(base.Hostname(), "."))
	port := base.Port()
	if port != "" && port != "80" && port != "443" {
		host += ":" + port
	}
	p, _ := servicePacers.LoadOrStore(host, NewGetPacer(nil))
	return p.(*GetPacer)
}

func (p *GetPacer) Do(ctx context.Context, send func(context.Context) (*http.Response, error)) (*http.Response, error) {
	return p.do(ctx, false, send)
}

func (p *GetPacer) DoMetadata(ctx context.Context, send func(context.Context) (*http.Response, error)) (*http.Response, error) {
	return p.do(ctx, true, send)
}

func (p *GetPacer) do(ctx context.Context, metadataOnly bool, send func(context.Context) (*http.Response, error)) (*http.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case p.gate <- struct{}{}:
	}
	defer func() { <-p.gate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	next := p.retryAt
	if !metadataOnly && p.next.After(next) {
		next = p.next
	}
	delay := next.Sub(p.clock.Now())
	if delay > maximumRetryWait {
		return nil, &RetryLaterError{RetryAt: next}
	}
	if delay > 0 {
		if err := p.clock.Sleep(ctx, delay); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resp, err := send(ctx)
	// Even a canceled/failed send may have reached the server. An unsent
	// canceled admission returns above, leaving the previous state intact.
	now := p.clock.Now()
	p.next = now.Add(getInterval)
	if resp != nil {
		if until := retryDeadline(resp.Header.Get("Retry-After"), now); until.After(p.retryAt) {
			p.retryAt = until
		}
	}
	return resp, err
}

func retryDeadline(raw string, now time.Time) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if seconds, err := strconv.ParseUint(raw, 10, 64); err == nil {
		const maxDelay = time.Duration(1<<63 - 1)
		if seconds > uint64(maxDelay/time.Second) {
			return now.Add(maxDelay)
		}
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if strings.Trim(raw, "0123456789") == "" {
		return now.Add(time.Duration(1<<63 - 1))
	}
	if date, err := http.ParseTime(raw); err == nil {
		return date
	}
	return time.Time{}
}
