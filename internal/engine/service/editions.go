package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"uupbuilder/internal/engine/rules"
	"uupbuilder/internal/model"
)

func (e *Executor) serviceOne(ctx context.Context, req ServiceRequest, path, mountName, edition string, derive, final bool, updates map[string]string, emit model.Emit) (out Inspection, err error) {
	mount, err := req.Transaction.ClaimMount(mountName)
	if err != nil {
		return out, err
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
			defer cancel()
			err = errors.Join(err, e.Backend.Unmount(cleanup, mount, false, emit))
		}
	}()
	if err = e.Backend.Mount(ctx, path, mount, emit); err != nil {
		return out, err
	}
	if derive {
		if err = e.Backend.SetEdition(ctx, mount, edition, emit); err != nil {
			return out, err
		}
	}
	if !final || req.Plan.Strategy == model.ServicingPerEdition {
		if req.Plan.SourceEdge != nil {
			if err = e.Backend.(SourceEdgeBackend).ApplySourceEdge(ctx, mount, updates["source-edge-content"], emit); err != nil {
				return out, err
			}
		}
		for _, update := range req.Plan.Updates {
			if !update.Integrate || !rules.Applies(update, edition) {
				continue
			}
			if err = ctx.Err(); err != nil {
				return out, err
			}
			if err = e.Backend.Apply(ctx, mount, update, updates[update.ID], emit); err != nil {
				return out, err
			}
			out, err = e.Backend.Inspect(ctx, mount, emit)
			if err != nil {
				return out, err
			}
			if err = verifyPackages(out.Packages, update.Packages); err != nil {
				return out, err
			}
		}
	}
	if final {
		if req.Plan.SourceEdge != nil {
			if err = e.Backend.(SourceEdgeBackend).VerifySourceEdge(ctx, mount, updates["source-edge-content"], emit); err != nil {
				return out, err
			}
		}
		if err = e.cleanup(ctx, req, mount, emit); err != nil {
			return out, err
		}
	}
	out, err = e.Backend.Inspect(ctx, mount, emit)
	if err != nil {
		return out, err
	}
	if !strings.EqualFold(out.Edition, edition) {
		return out, fmt.Errorf("%w: expected edition %s, observed %s", ErrVerification, edition, out.Edition)
	}
	for _, update := range req.Plan.Updates {
		if update.Integrate && rules.Applies(update, edition) {
			if err = verifyPackages(out.Packages, update.Packages); err != nil {
				return out, err
			}
		}
	}
	if err = e.Backend.Unmount(ctx, mount, true, emit); err != nil {
		return out, err
	}
	committed = true
	return out, nil
}
