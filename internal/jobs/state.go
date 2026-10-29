//go:build windows

// Package jobs owns the single active conversion and its resource lifetime.
package jobs

import (
	"context"
	"errors"
	"slices"
	"time"
	"uupbuilder/internal/model"
)

type State string

const (
	Running   State = "running"
	Succeeded State = "succeeded"
	Cancelled State = "cancelled"
	Failed    State = "failed"
)

type Action string

const CancelAction Action = "cancel"

type JobView struct {
	ID        string
	State     State
	Stage     string
	Error     string
	Artifacts []model.Artifact
	Actions   []Action
}

var (
	ErrBusy                   = errors.New("a conversion job is already active")
	ErrUnknownJob             = errors.New("job is not owned by this active controller")
	ErrPublicationUnavailable = errors.New("verified ISO publication producer unavailable; U10 completion evidence is required")
)

func cloneView(v JobView) JobView {
	v.Artifacts = slices.Clone(v.Artifacts)
	v.Actions = slices.Clone(v.Actions)
	return v
}
func (c *Controller) View(jobID string) (JobView, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last.ID != jobID {
		return JobView{}, ErrUnknownJob
	}
	return cloneView(c.last), nil
}

func (c *Controller) Wait(ctx context.Context, jobID string) (JobView, error) {
	c.mu.Lock()
	active := c.active
	if c.last.ID != jobID {
		c.mu.Unlock()
		return JobView{}, ErrUnknownJob
	}
	if active == nil {
		v := cloneView(c.last)
		c.mu.Unlock()
		return v, nil
	}
	done := active.done
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := c.Cancel(cleanupCtx, jobID)
		view, _ := c.View(jobID)
		return view, errors.Join(ctx.Err(), err)
	case <-done:
		return c.View(jobID)
	}
}
