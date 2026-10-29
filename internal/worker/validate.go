//go:build windows

package worker

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"sync"

	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
)

var (
	ErrUnauthorized   = errors.New("worker operation is not authorized by the active peer, capability, workspace, plan and intent")
	ErrMissingHandler = errors.New("operation handler unavailable")
	ErrAppBarrier     = errors.New("source-bound deferred app inspection barrier incomplete")
)

func samePeer(a, b platform.PeerIdentity) bool {
	return a.ProcessID != 0 && a.CreationTime != 0 && a.UserSID != "" && a.Executable != "" && a.ProcessID == b.ProcessID && a.CreationTime == b.CreationTime && a.UserSID == b.UserSID && a.SessionID == b.SessionID && a.Elevated == b.Elevated && strings.EqualFold(a.Executable, b.Executable)
}
func sameWorkspace(a, b platform.WorkspaceIdentity) bool {
	return a.JobID == b.JobID && strings.EqualFold(a.Path, b.Path) && subtle.ConstantTimeCompare([]byte(a.Token), []byte(b.Token)) == 1
}

type Session struct {
	mu          sync.Mutex
	plan        planner.ReadyPlan
	descriptor  platform.WorkerDescriptor
	peer        platform.PeerIdentity
	self        platform.PeerIdentity
	store       *jobstore.Store
	registry    *Registry
	next        int
	checkpoints map[string]jobstore.Checkpoint
	barrier     *AppBarrierEvidence
	started     bool
}

func NewSession(plan planner.ReadyPlan, d platform.WorkerDescriptor, peer, self platform.PeerIdentity, store *jobstore.Store, registry *Registry) (*Session, error) {
	if plan.Validate() != nil || d.Validate() != nil || plan.Digest() != d.PlanDigest || store == nil || !sameWorkspace(d.Workspace, store.Identity()) || !samePeer(peer, peer) || !samePeer(self, self) {
		return nil, ErrUnauthorized
	}
	if platform.ValidateWorkspaceParent(d.Workspace, plan.EffectiveSettings().Storage.Workspace) != nil {
		return nil, ErrUnauthorized
	}
	if err := plan.RecheckStorage(context.Background(), nativeStorage); err != nil {
		return nil, err
	}
	sealed, err := registry.Snapshot(plan)
	if err != nil {
		return nil, err
	}
	for _, h := range sealed.handlers {
		if h.RequiresElevation && !self.Elevated {
			return nil, ErrUnauthorized
		}
	}
	return &Session{plan: plan, descriptor: d, peer: peer, self: self, store: store, registry: sealed, checkpoints: map[string]jobstore.Checkpoint{}}, nil
}

func nativeStorage(ctx context.Context, path string) (planner.Volume, error) {
	if err := ctx.Err(); err != nil {
		return planner.Volume{}, err
	}
	v, err := platform.InspectStorage(path)
	return planner.Volume{Path: v.Path, ID: v.ID, FileSystem: v.Capabilities, AvailableBytes: v.AvailableBytes, MaxFileBytes: v.MaxFileBytes}, err
}
func (s *Session) authorize(actual platform.PeerIdentity, r OperationRequest) (planner.Operation, error) {
	if !samePeer(s.peer, actual) || r.Version != 1 || r.JobID != s.descriptor.JobID || r.PlanDigest != s.plan.Digest() || r.Intent != s.plan.Intent() || !sameWorkspace(r.Workspace, s.descriptor.Workspace) || subtle.ConstantTimeCompare([]byte(r.Capability), []byte(s.descriptor.Workspace.Token)) != 1 {
		return planner.Operation{}, ErrUnauthorized
	}
	ops := s.plan.Operations()
	if s.next >= len(ops) || ops[s.next].ID != r.OperationID {
		return planner.Operation{}, ErrUnauthorized
	}
	op := ops[s.next]
	for _, id := range op.DependsOn {
		if _, ok := s.checkpoints[id]; !ok {
			return planner.Operation{}, ErrUnauthorized
		}
	}
	if op.Kind != planner.DownloadPayloads && op.Kind != planner.AssembleImage && op.Kind != planner.InspectApps {
		for _, dep := range op.DependsOn {
			if dep == string(planner.InspectApps) && s.barrier == nil {
				return planner.Operation{}, ErrAppBarrier
			}
		}
	}
	return op, nil
}
