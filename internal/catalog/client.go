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
		timeout := c.RequestTimeout
		if timeout <= 0 {
			timeout = 45 * time.Second
		}
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, u.String(), nil)
		if err != nil {
			cancel()
			return nil, errors.New("catalog request could not be constructed")
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "UUPBuilder/catalog")
		resp, err := c.http.Do(req)
		var data []byte
		var retryAfter string
		var retry bool
		if err != nil {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			if ctx.Err() != nil {
				cancel()
				return nil, ctx.Err()
			}
			timedOut := errors.Is(err, context.DeadlineExceeded)
			err = fmt.Errorf("catalog %s: transport failed", endpoint)
			if timedOut {
				err = fmt.Errorf("catalog %s: %w", endpoint, context.DeadlineExceeded)
			}
			if requestCtx.Err() != nil {
				err = fmt.Errorf("catalog %s: %w", endpoint, requestCtx.Err())
			}
			retry = true
		} else {
			limit := c.MaxBodyBytes
			if limit <= 0 {
				limit = 32 << 20
			}
			data, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
			_ = resp.Body.Close()
			retryAfter = resp.Header.Get("Retry-After")
			if err != nil {
				if ctx.Err() != nil {
					cancel()
					return nil, ctx.Err()
				}
				timedOut := errors.Is(err, context.DeadlineExceeded)
				err = fmt.Errorf("catalog %s: response body read failed", endpoint)
				if timedOut {
					err = fmt.Errorf("catalog %s: %w", endpoint, context.DeadlineExceeded)
				}
				if requestCtx.Err() != nil {
					err = fmt.Errorf("catalog %s: %w", endpoint, requestCtx.Err())
				}
				retry = true
			} else if int64(len(data)) > limit {
				err = fmt.Errorf("catalog %s: response exceeds %d-byte limit", endpoint, limit)
			} else {
				_, err = decodeEnvelope(data, endpoint, resp.StatusCode)
				retry = resp.StatusCode == 429 || resp.StatusCode >= 500
			}
		}
		cancel()
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
			return nil, err
		}
		if sleepErr := clock.Sleep(ctx, delay); sleepErr != nil {
			return nil, sleepErr
		}
	}
	panic("unreachable")
}
