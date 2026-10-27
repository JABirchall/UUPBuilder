//go:build windows

package download

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"sync"
	"time"

	"uupbuilder/internal/model"
)

var (
	errRestart = errors.New("download partial requires restart")
	errExpired = errors.New("download locator expired")
)

type locatorSet struct {
	mu       sync.Mutex
	frozen   model.PayloadManifest
	locators model.Locators
	refresh  func(context.Context, model.PayloadManifest) (model.Locators, error)
}

func (s *locatorSet) get(ctx context.Context, id model.PayloadIdentity, now time.Time, force bool) (Locator, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	loc, ok := s.locators[id]
	if !force && ok && (loc.ExpiresAt.IsZero() || now.Before(loc.ExpiresAt)) {
		return loc, nil
	}
	if s.refresh == nil {
		return Locator{}, ErrRefresh
	}
	frozen := s.frozen
	frozen.Payloads = slices.Clone(s.frozen.Payloads)
	fresh, err := s.refresh(ctx, frozen)
	if ctx.Err() != nil {
		return Locator{}, ctx.Err()
	}
	if err != nil {
		return Locator{}, ErrRefresh
	}
	members := make(map[model.PayloadIdentity]bool)
	for _, p := range s.frozen.Payloads {
		members[p.Identity] = true
	}
	if len(fresh) != len(members) {
		return Locator{}, ErrRefresh
	}
	copy := make(model.Locators, len(fresh))
	for key, value := range fresh {
		u, err := url.Parse(value.URL)
		if !members[key] || err != nil || !validURL(u) || (!value.ExpiresAt.IsZero() && !now.Before(value.ExpiresAt)) {
			return Locator{}, ErrRefresh
		}
		copy[key] = value
	}
	s.locators = copy
	return copy[id], nil
}

func (m *Manager) fetchOne(ctx context.Context, payload model.Payload, set *locatorSet, emit model.Emit) (CachedFile, error) {
	if payload.Validate() != nil {
		return CachedFile{}, ErrInvalidInput
	}
	unlock, err := m.keyLock(ctx, payload.Identity)
	if err != nil {
		return CachedFile{}, err
	}
	defer unlock()
	forceRefresh := false
	challengeRefreshed := false
	for attempt := 0; ; {
		active, finish, err := m.begin(ctx)
		if err != nil {
			return CachedFile{}, err
		}
		file, found, err := m.cached(active, payload.Identity)
		if err == nil && !found {
			var loc Locator
			loc, err = set.get(active, payload.Identity, m.opts.Now(), forceRefresh)
			if err == nil {
				forceRefresh = false
				file, err = m.transfer(active, payload, loc, emit)
			}
		}
		interrupted := active.Err() != nil
		finish()
		if ctx.Err() != nil {
			return CachedFile{}, ctx.Err()
		}
		if interrupted {
			continue
		}
		if err == nil {
			return file, nil
		}
		if errors.Is(err, ErrIntegrity) || errors.Is(err, ErrStorage) || errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrRefresh) {
			return CachedFile{}, err
		}
		if errors.Is(err, errExpired) {
			// Refresh one authorization/expiry challenge independently of the
			// transport retry policy, then fail closed if the fresh link also
			// fails. A zero retry policy must still permit locator renewal.
			if challengeRefreshed || set.refresh == nil {
				return CachedFile{}, ErrRefresh
			}
			challengeRefreshed = true
			forceRefresh = true
			continue
		}
		if attempt >= m.opts.Retries {
			return CachedFile{}, ErrTransfer
		}
		attempt++
		if err := waitRetry(ctx, m.opts.RetryDelay); err != nil {
			return CachedFile{}, err
		}
	}
}

func waitRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
