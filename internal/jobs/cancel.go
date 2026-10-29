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
	if active != nil {
		active.cancel()
	}
	c.mu.Unlock()
	if active != nil {
		// Wait on the captured job rather than looking it up again: it may
		// finish between this snapshot and cancellation/teardown.
		select {
		case <-ctx.Done():
			c.mu.Lock()
			defer c.mu.Unlock()
			return errors.Join(ctx.Err(), c.cleanupErr)
		case <-active.done:
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cleanupErr
}
