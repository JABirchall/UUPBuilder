package service

import (
	"context"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

func (e *Executor) cleanup(ctx context.Context, req ServiceRequest, mount platform.OwnedMount, emit model.Emit) error {
	if !req.Plan.Cleanup {
		return nil
	}
	// Pending-action and generation constraints are reported by native DISM.
	// A requested cleanup failure cannot silently become a successful stage.
	return e.Backend.Cleanup(ctx, mount, req.Plan.ResetBase, emit)
}
