//go:build windows

package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/worker"
)

type Options struct {
	Registry       *worker.Registry
	InspectStorage func(context.Context, string) (planner.Volume, error)
	MountInspector jobstore.MountInspector
}
type activeJob struct {
	id     string
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}
type Controller struct {
	mu         sync.Mutex
	options    Options
	active     *activeJob
	last       JobView
	cleanupErr error
}

func NewController(options Options) *Controller { return &Controller{options: options} }

func (c *Controller) Start(ctx context.Context, plan planner.ReadyPlan) (JobView, error) {
	if ctx == nil {
		return JobView{}, planner.ErrInvalidPlan
	}
	if err := ctx.Err(); err != nil {
		return JobView{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil {
		return JobView{}, ErrBusy
	}
	if err := plan.Validate(); err != nil {
		return JobView{}, err
	}
	registry, err := c.options.Registry.Snapshot(plan)
	if err != nil {
		return JobView{}, err
	}
	// Only the fixed publication handler may enable the build completion path.
	if plan.Intent() == planner.BuildMedia && !registry.SupportsPublication() {
		return JobView{}, ErrPublicationUnavailable
	}
	if err := plan.RecheckStorage(ctx, c.options.InspectStorage); err != nil {
		return JobView{}, err
	}
	self, err := platform.CurrentPeerIdentity()
	if err != nil {
		return JobView{}, err
	}
	if registry.RequiresElevation() && !self.Elevated {
		return JobView{}, errors.New("registered stage requires a restricted worker; elevation dispatch is not available for this stage")
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return JobView{}, err
	}
	id := "job-" + hex.EncodeToString(token[:])
	store, err := jobstore.Create(plan.EffectiveSettings().Storage.Workspace, id, c.options.MountInspector)
	if err != nil {
		return JobView{}, fmt.Errorf("create active job workspace: %w", err)
	}
	descriptor := platform.WorkerDescriptor{Version: 1, JobID: id, PlanDigest: plan.Digest(), Workspace: store.Identity()}
	session, err := worker.NewSession(plan, descriptor, self, self, store, registry)
	if err != nil {
		store.Close()
		return JobView{}, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	active := &activeJob{id: id, cancel: cancel, done: make(chan struct{})}
	c.active = active
	c.last = JobView{ID: id, State: Running, Actions: []Action{CancelAction}}
	go c.execute(runCtx, active, plan, descriptor, self, store, session)
	return cloneView(c.last), nil
}
func (c *Controller) execute(ctx context.Context, active *activeJob, plan planner.ReadyPlan, d platform.WorkerDescriptor, self platform.PeerIdentity, store *jobstore.Store, session *worker.Session) {
	var runErr error
	var artifacts []model.Artifact
	var lastKind planner.OperationKind
	for _, op := range plan.Operations() {
		lastKind = op.Kind
		c.mu.Lock()
		c.last.Stage = op.ID
		c.mu.Unlock()
		var result worker.Result
		result, runErr = session.Dispatch(ctx, self, worker.RequestFor(d, plan.Intent(), op.ID))
		if runErr == nil && op.Kind == planner.PublishISO {
			var artifact model.Artifact
			artifact, runErr = verifiedCompletion(ctx, plan, result)
			if runErr == nil {
				artifacts = []model.Artifact{artifact}
			}
		}
		if runErr != nil {
			break
		}
	}
	cancelled := ctx.Err() != nil
	if cancelled && runErr == nil {
		runErr = ctx.Err()
	}
	if runErr == nil && plan.Intent() == planner.BuildMedia && len(artifacts) != 1 {
		runErr = ErrPublicationUnavailable
	}
	if runErr != nil {
		if lastKind == planner.PublishISO {
			runErr = fmt.Errorf("%w; local ISO and active workspace retained at %s", runErr, store.Identity().Path)
		} else {
			runErr = errors.Join(runErr, cleanupActive(store, active.id))
		}
	}
	if closeErr := store.Close(); closeErr != nil {
		runErr = errors.Join(runErr, fmt.Errorf("%w: %w", errCleanup, closeErr))
	}
	active.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last.Actions = nil
	if runErr == nil {
		c.last.State = Succeeded
		c.last.Artifacts = artifacts
	} else {
		c.last.State = Failed
		c.last.Error = runErr.Error()
		if cancelled && errors.Is(runErr, context.Canceled) && !containsCleanupFailure(runErr) {
			c.last.State = Cancelled
		}
	}
	active.err = runErr
	if containsCleanupFailure(runErr) {
		c.cleanupErr = errors.Join(c.cleanupErr, runErr)
	}
	c.active = nil
	close(active.done)
}

func verifiedCompletion(ctx context.Context, plan planner.ReadyPlan, result worker.Result) (model.Artifact, error) {
	if result.Publication == nil {
		return model.Artifact{}, ErrPublicationUnavailable
	}
	return result.Publication.Artifact(ctx, plan.Digest(), plan.Manifest().Source)
}
