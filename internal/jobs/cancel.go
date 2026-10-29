//go:build windows

package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uupbuilder/internal/jobstore"
)

var errCleanup = errors.New("active resources preserved because safe cleanup was not established")

func cleanupActive(store *jobstore.Store, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.Discard(ctx, id); err != nil {
		return fmt.Errorf("%w: %w", errCleanup, err)
	}
	return nil
}
func containsCleanupFailure(err error) bool { return errors.Is(err, errCleanup) }
func (c *Controller) Cancel(ctx context.Context, jobID string) error {
	c.mu.Lock()
	active := c.active
	if active == nil || active.id != jobID {
		c.mu.Unlock()
		return ErrUnknownJob
	}
	active.cancel()
	done := active.done
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}
	if containsCleanupFailure(active.err) {
		return active.err
	}
	return nil
}
func (c *Controller) Close(ctx context.Context) error {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	if active == nil {
		return nil
	}
	return c.Cancel(ctx, active.id)
}
