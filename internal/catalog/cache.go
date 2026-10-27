package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"time"
)

// Cache stores sanitized JSON of validated public discovery values, never raw
// response envelopes, unknown upstream fields, or get.php responses.
// Implementations must support concurrent use and return independent byte slices.
type Cache interface {
	Load(string) (CacheEntry, bool)
	Store(string, CacheEntry)
}
type CacheEntry struct {
	Data      []byte
	FetchedAt time.Time
}
type MemoryCache struct {
	mu      sync.Mutex
	entries map[string]CacheEntry
	bytes   int64
}

// NewMemoryCache bounds discovery history to 128 entries and 64 MiB, evicting
// the oldest fetched entries. An oversized individual entry is not cached.
func NewMemoryCache() *MemoryCache { return &MemoryCache{entries: make(map[string]CacheEntry)} }
func (c *MemoryCache) Load(key string) (CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	entry.Data = slices.Clone(entry.Data)
	return entry, ok
}
func (c *MemoryCache) Store(key string, entry CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const byteLimit = 64 << 20
	if len(entry.Data) > byteLimit {
		return
	}
	entry.Data = slices.Clone(entry.Data)
	if c.entries == nil {
		c.entries = make(map[string]CacheEntry)
	}
	if previous, exists := c.entries[key]; exists {
		c.bytes -= int64(len(previous.Data))
	}
	c.entries[key] = entry
	c.bytes += int64(len(entry.Data))
	for len(c.entries) > 128 || c.bytes > byteLimit {
		oldest := ""
		var fetchedAt time.Time
		for candidate, value := range c.entries {
			if oldest == "" || value.FetchedAt.Before(fetchedAt) {
				oldest = candidate
				fetchedAt = value.FetchedAt
			}
		}
		c.bytes -= int64(len(c.entries[oldest].Data))
		delete(c.entries, oldest)
	}
}

// StaleError accompanies usable cached data when its refresh failed. Unwrap
// retains the refresh cause; FetchedAt reports when the old data was retrieved.
type StaleError struct {
	FetchedAt time.Time
	Err       error
}

func (e *StaleError) Error() string {
	return fmt.Sprintf("catalog data from %s is stale: %v", e.FetchedAt.UTC().Format(time.RFC3339), e.Err)
}
func (e *StaleError) Unwrap() error { return e.Err }

type refreshKey struct{}

// WithRefresh forces a discovery refresh even when the cache entry is fresh.
func WithRefresh(ctx context.Context) context.Context {
	return context.WithValue(ctx, refreshKey{}, true)
}

func cached[T any](ctx context.Context, c *Client, endpoint string, query url.Values, parse func([]byte) (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if c.initErr != nil {
		return zero, c.initErr
	}
	key := "catalog:v1:" + c.base.String() + endpoint + "?" + query.Encode()
	var entry CacheEntry
	var old T
	var exists bool
	if c.Cache != nil {
		entry, exists = c.Cache.Load(key)
		if exists {
			exists = json.Unmarshal(entry.Data, &old) == nil
		}
	}
	force, _ := ctx.Value(refreshKey{}).(bool)
	age := c.clock().Now().Sub(entry.FetchedAt)
	if exists && !force && c.CacheTTL > 0 && age >= 0 && age < c.CacheTTL {
		return old, nil
	}
	data, err := c.fetch(ctx, endpoint, query)
	if err == nil {
		var fresh T
		fresh, err = parse(data)
		if err == nil {
			if c.Cache != nil {
				// T contains only public validated structs. Marshal cannot copy an
				// upstream debug field or a future signed-link field into storage.
				if sanitized, marshalErr := json.Marshal(fresh); marshalErr == nil {
					c.Cache.Store(key, CacheEntry{Data: sanitized, FetchedAt: c.clock().Now()})
				}
			}
			return fresh, nil
		}
	}
	if exists {
		return old, &StaleError{FetchedAt: entry.FetchedAt, Err: err}
	}
	return zero, err
}
