// Package catalog provides the official UUP Dump discovery and metadata client.
package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const DefaultBaseURL = "https://api.uupdump.net/"

// Client settings and injected ports must be configured before concurrent use.
// The default discovery cache is in memory; get.php bodies are never cached.
type Client struct {
	Clock          Clock
	Cache          Cache
	CacheTTL       time.Duration
	RequestTimeout time.Duration
	MaxBodyBytes   int64
	Pacer          *GetPacer
	// MetadataOnly requests noLinks=1. Its success proves metadata availability,
	// not the availability of payload bodies or online locators.
	MetadataOnly bool
	http         *http.Client
	base         *url.URL
	initErr      error
}

// New uses the official HTTPS service when baseURL is empty. A custom HTTP
// service is allowed for local tests and explicit caller-selected endpoints.
func New(client *http.Client, baseURL string) *Client {
	if client == nil {
		client = &http.Client{}
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	c := &Client{http: client, Clock: systemClock{}, Cache: NewMemoryCache(), CacheTTL: 5 * time.Minute, RequestTimeout: 45 * time.Second, MaxBodyBytes: 32 << 20}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		c.initErr = errors.New("catalog base URL must be an HTTP(S) origin/path without credentials, query or fragment")
		return c
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/"
	c.base = u
	c.Pacer = sharedGetPacer(u)
	return c
}

var updatePattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(_rev\.[1-9][0-9]*)?$`)
var selectorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func validUpdateID(id string) error {
	if len(id) > 128 || !updatePattern.MatchString(id) {
		return errors.New("catalog update ID must be a UUID with an optional positive _rev.N suffix")
	}
	return nil
}

func validSelector(name, value string) error {
	if len(value) > 128 || !selectorPattern.MatchString(value) {
		return fmt.Errorf("catalog %s must be a nonempty upstream identifier", name)
	}
	return nil
}

func (c *Client) clock() Clock {
	if c.Clock != nil {
		return c.Clock
	}
	return systemClock{}
}

func (c *Client) fetch(ctx context.Context, endpoint string, query url.Values) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.initErr != nil {
		return nil, c.initErr
	}
	u := *c.base
	u.Path += endpoint
	u.RawQuery = query.Encode()
	clock := c.clock()
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var data []byte
		var retryAfter string
		var retry bool
		send := func(sendCtx context.Context) (*http.Response, error) {
			resp, body, shouldRetry, err := c.fetchAttempt(sendCtx, &u, endpoint)
			data, retry = body, shouldRetry
			if resp != nil {
				retryAfter = resp.Header.Get("Retry-After")
			}
			return resp, err
		}
		var err error
		if endpoint == "get.php" {
			pacer := c.Pacer
			if pacer == nil {
				pacer = sharedGetPacer(c.base)
			}
			if query.Get("noLinks") == "1" {
				_, err = pacer.DoMetadata(ctx, send)
			} else {
				_, err = pacer.Do(ctx, send)
			}
		} else {
			_, err = send(ctx)
		}
		if err == nil {
			return data, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !retry || attempt == 2 {
			return nil, err
		}
		delay, allowed := retryDelay(retryAfter, attempt, clock.Now())
		if !allowed {
			if endpoint == "get.php" {
				return nil, &RetryLaterError{RetryAt: retryDeadline(retryAfter, clock.Now())}
			}
			return nil, err
		}
		if sleepErr := clock.Sleep(ctx, delay); sleepErr != nil {
			return nil, sleepErr
		}
	}
	panic("unreachable")
}

// fetchAttempt starts the HTTP timeout only after shared pacing admission.
// It reads/closes the bounded body before releasing the pacer, so the next
// attempt waits from completion, after any possible server timer update.
func (c *Client) fetchAttempt(ctx context.Context, u *url.URL, endpoint string) (*http.Response, []byte, bool, error) {
	timeout := c.RequestTimeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, false, errors.New("catalog request could not be constructed")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "UUPBuilder/catalog")
	resp, err := c.http.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return resp, nil, true, attemptError(ctx, requestCtx, endpoint, "transport failed", err)
	}
	defer resp.Body.Close()
	limit := c.MaxBodyBytes
	if limit <= 0 {
		limit = 32 << 20
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp, nil, true, attemptError(ctx, requestCtx, endpoint, "response body read failed", err)
	}
	if int64(len(data)) > limit {
		return resp, nil, false, fmt.Errorf("catalog %s: response exceeds %d-byte limit", endpoint, limit)
	}
	_, err = decodeEnvelope(data, endpoint, resp.StatusCode)
	var api *APIError
	retry := resp.StatusCode == 429 || resp.StatusCode >= 500 || errors.As(err, &api) && api.Code == "USER_RATE_LIMITED"
	return resp, data, retry, err
}

func attemptError(ctx, requestCtx context.Context, endpoint, message string, cause error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := requestCtx.Err(); err != nil {
		return fmt.Errorf("catalog %s: %w", endpoint, err)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return fmt.Errorf("catalog %s: %w", endpoint, context.DeadlineExceeded)
	}
	return fmt.Errorf("catalog %s: %s", endpoint, message)
}
