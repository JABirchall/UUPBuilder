//go:build windows

package worker

import (
	"context"
	"errors"
	"io"
	"time"

	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
)

// Entry uses only the restricted same-executable bootstrap and authenticated
// native pipe. The parent must release its jobstore writer before dispatch.
func Entry(ctx context.Context, args []string, registry *Registry) error {
	b, err := platform.ParseWorkerArguments(args)
	if err != nil {
		return err
	}
	conn, err := platform.ConnectWorker(ctx, b)
	if err != nil {
		return err
	}
	defer conn.Close()
	return Serve(ctx, b, conn, registry, nil)
}
func Serve(ctx context.Context, b platform.WorkerBootstrap, conn platform.WorkerConnection, registry *Registry, inspector jobstore.MountInspector) (resultErr error) {
	if err := b.Validate(); err != nil {
		return err
	}
	if !samePeer(b.Parent, conn.PeerIdentity()) {
		return ErrUnauthorized
	}
	// Closing the owned connection interrupts a blocked read on cancellation.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	var envelope PlanEnvelope
	if err := ReadFrame(conn, &envelope); err != nil {
		return err
	}
	plan, err := planner.DecodeReadyPlan(envelope.TOML)
	if err != nil {
		return err
	}
	if plan.Digest() != b.Descriptor.PlanDigest {
		return ErrUnauthorized
	}
	if _, err := registry.Snapshot(plan); err != nil {
		return err
	}
	// Opening a descriptor path proves its private capability and excludes a
	// concurrent parent writer. No transaction survives this custody transfer.
	store, err := jobstore.Open(b.Descriptor.Workspace, inspector)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	self, err := platform.CurrentPeerIdentity()
	if err != nil {
		return err
	}
	session, err := NewSession(plan, b.Descriptor, b.Parent, self, store, registry)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil && session.started {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := store.Discard(cleanupCtx, b.Descriptor.JobID); err != nil {
				resultErr = errors.Join(resultErr, errors.New("active worker resources preserved: safe cleanup was not established"), err)
			}
		}
	}()
	for range plan.Operations() {
		var request OperationRequest
		if err := ReadFrame(conn, &request); err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("worker disconnected before active graph completed")
			}
			return err
		}
		_, err := session.Dispatch(ctx, conn.PeerIdentity(), request)
		response := OperationResponse{OperationID: request.OperationID}
		if err != nil {
			response.Error = "active operation rejected or failed"
		} else {
			response.CheckpointDigest = session.checkpoints[request.OperationID].Digest
		}
		if writeErr := WriteFrame(conn, response); writeErr != nil {
			return writeErr
		}
		if err != nil {
			return err
		}
	}
	return nil
}
