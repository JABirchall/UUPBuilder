//go:build windows

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"uupbuilder/internal/engine/output"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
)

type AppBarrierEvidence struct {
	PlanDigest               string
	ManifestDigest           string
	DraftRevision            uint64
	AssemblyCheckpointDigest string
	RequestedSettingsDigest  string
	ObservationDigest        string
}
type Stage struct {
	Plan         planner.ReadyPlan
	Operation    planner.Operation
	Transaction  *jobstore.Transaction
	Predecessors []jobstore.Checkpoint
}
type Result struct {
	Outputs     []jobstore.OutputIdentity
	AppBarrier  *AppBarrierEvidence
	Artifacts   []model.Artifact
	Publication *output.PublishedArtifact
}
type Handler struct {
	RequiresElevation bool
	Run               func(context.Context, Stage) (Result, error)
	publishes         bool
}
type Registry struct {
	mu       sync.Mutex
	handlers map[planner.OperationKind]Handler
	sealed   bool
}

func NewRegistry() *Registry { return &Registry{handlers: map[planner.OperationKind]Handler{}} }

func (r *Registry) SupportsPublication() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.handlers[planner.PublishISO].publishes
}
func (r *Registry) Register(kind planner.OperationKind, h Handler) error {
	if r == nil || h.Run == nil {
		return ErrMissingHandler
	}
	switch kind {
	case planner.DownloadPayloads, planner.AssembleImage, planner.InspectApps, planner.ServiceImage, planner.CustomizeImage, planner.ExportImage, planner.MasterISO, planner.PublishISO:
	default:
		return ErrUnauthorized
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sealed {
		return errors.New("active handler registry is immutable")
	}
	if _, exists := r.handlers[kind]; exists {
		return errors.New("handler already registered")
	}
	r.handlers[kind] = h
	return nil
}

// Snapshot pins the exact handler authority for this plan. Later registration
// on the application registry cannot change an already authorized operation.
func (r *Registry) Snapshot(plan planner.ReadyPlan) (*Registry, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("%w: %s", ErrMissingHandler, plan.Operations()[0].Kind)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := NewRegistry()
	out.sealed = true
	for _, op := range plan.Operations() {
		h, ok := r.handlers[op.Kind]
		if !ok || h.Run == nil {
			return nil, fmt.Errorf("%w: %s", ErrMissingHandler, op.Kind)
		}
		out.handlers[op.Kind] = h
	}
	return out, nil
}
func (r *Registry) RequiresElevation() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range r.handlers {
		if h.RequiresElevation {
			return true
		}
	}
	return false
}

func identityDigest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (s *Session) Dispatch(ctx context.Context, actual platform.PeerIdentity, request OperationRequest) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	op, err := s.authorize(actual, request)
	if err != nil {
		return Result{}, err
	}
	liveBefore, err := s.store.InspectRecovery(ctx, s.descriptor.JobID)
	if err != nil {
		return Result{}, err
	}
	if len(liveBefore.Preserved) > 0 {
		return Result{}, errors.New("active resources preserved: actual mount or ownership state is unresolved")
	}
	in := jobstore.MutationIntent{JobID: s.descriptor.JobID, PlanDigest: s.plan.Digest(), ConfigDigest: identityDigest(s.plan.RequestedSettings()), StageID: op.ID, OwnedPaths: op.OwnedPaths}
	for _, v := range op.Inputs {
		in.Inputs = append(in.Inputs, jobstore.NamedDigest{Name: v.Name, Digest: v.Digest})
	}
	for _, v := range op.Rules {
		in.Rules = append(in.Rules, jobstore.VersionedIdentity{Name: v.Name, Version: v.Version, Digest: v.Digest})
	}
	for i, v := range op.ToolDigests {
		in.Tools = append(in.Tools, jobstore.VersionedIdentity{Name: fmt.Sprintf("tool-%d", i), Version: "1", Digest: v})
	}
	stage := Stage{Plan: s.plan, Operation: op}
	for _, id := range op.DependsOn {
		cp := s.checkpoints[id]
		in.Predecessors = append(in.Predecessors, jobstore.PredecessorIdentity{StageID: id, Digest: cp.Digest})
		stage.Predecessors = append(stage.Predecessors, cp)
	}
	tx, err := s.store.Begin(ctx, in)
	if err != nil {
		return Result{}, err
	}
	stage.Transaction = tx
	s.started = true
	result, err := s.registry.handlers[op.Kind].Run(ctx, stage)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if op.Kind == planner.InspectApps {
		if !s.validBarrier(result) {
			return Result{}, ErrAppBarrier
		}
	}
	if err := tx.Commit(ctx, result.Outputs); err != nil {
		return Result{}, err
	}
	// This is inspection of the currently owned writer's committed stage, never
	// startup discovery or restart/replay. Commit independently verifies bytes.
	live, err := s.store.InspectRecovery(ctx, s.descriptor.JobID)
	if err != nil {
		return Result{}, err
	}
	for _, status := range live.Checkpoints {
		if status.Valid && status.Checkpoint.Intent.StageID == op.ID {
			s.checkpoints[op.ID] = status.Checkpoint
		}
	}
	if _, ok := s.checkpoints[op.ID]; !ok {
		return Result{}, errors.New("active stage checkpoint not validated")
	}
	if op.Kind == planner.InspectApps && result.AppBarrier != nil {
		e := *result.AppBarrier
		s.barrier = &e
	}
	s.next++
	return result, nil
}
func (s *Session) validBarrier(result Result) bool {
	e := result.AppBarrier
	if e == nil {
		return false
	}
	assembly, ok := s.checkpoints[string(planner.AssembleImage)]
	if !ok {
		return false
	}
	if e.PlanDigest != s.plan.Digest() || e.ManifestDigest != s.plan.Manifest().Digest || e.DraftRevision != s.plan.DraftRevision() || e.AssemblyCheckpointDigest != assembly.Digest || e.RequestedSettingsDigest != identityDigest(s.plan.RequestedSettings()) {
		return false
	}
	for _, output := range result.Outputs {
		if output.SHA256 == e.ObservationDigest {
			return true
		}
	}
	return false
}
