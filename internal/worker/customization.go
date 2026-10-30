package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"uupbuilder/internal/engine/service"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
)

var ErrCustomizationInputsUnavailable = errors.New("customization requires inspected serviced images and verified app/feature/driver inputs")

type CustomizationInputProvider interface {
	CustomizationInputs(context.Context, Stage) (service.CustomizationRequest, error)
}
type AppInspectionProvider interface {
	InspectApps(context.Context, Stage) (metadata.Inventory, error)
}

func writeStageResult(stage Stage, value any, role string) (jobstore.OutputIdentity, error) {
	data, e := json.Marshal(value)
	if e != nil {
		return jobstore.OutputIdentity{}, e
	}
	file, e := stage.Transaction.OpenFile("result.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return jobstore.OutputIdentity{}, e
	}
	_, writeErr := file.Write(data)
	e = errors.Join(writeErr, file.Sync(), file.Close())
	return jobstore.OutputIdentity{Path: "result.json", Size: int64(len(data)), SHA256: identityDigest(value), Role: role}, e
}
func AppInspectionHandler(provider AppInspectionProvider) Handler {
	return Handler{Run: func(ctx context.Context, stage Stage) (Result, error) {
		if stage.Transaction == nil || stage.Plan.Validate() != nil || stage.Operation.Kind != planner.InspectApps {
			return Result{}, planner.ErrInvalidPlan
		}
		if provider == nil {
			return Result{}, ErrAppBarrier
		}
		inv, e := provider.InspectApps(ctx, stage)
		if e != nil {
			return Result{}, e
		}
		if inv.Source != stage.Plan.Manifest().Source || inv.Manifest.Digest != stage.Plan.Manifest().Digest {
			return Result{}, planner.ErrIdentityChanged
		}
		apps, e := planner.PlanApps(inv, stage.Plan.RequestedSettings().Apps)
		if e != nil {
			return Result{}, e
		}
		if apps.Deferred {
			return Result{}, ErrAppBarrier
		}
		var assembly string
		for _, cp := range stage.Predecessors {
			if cp.Intent.StageID == string(planner.AssembleImage) {
				assembly = cp.Digest
			}
		}
		if assembly == "" {
			return Result{}, ErrAppBarrier
		}
		output, e := writeStageResult(stage, apps, "inspected-app-plan")
		if e != nil {
			return Result{}, e
		}
		return Result{Outputs: []jobstore.OutputIdentity{output}, AppBarrier: &AppBarrierEvidence{PlanDigest: stage.Plan.Digest(), ManifestDigest: stage.Plan.Manifest().Digest, DraftRevision: stage.Plan.DraftRevision(), AssemblyCheckpointDigest: assembly, RequestedSettingsDigest: identityDigest(stage.Plan.RequestedSettings()), ObservationDigest: output.SHA256}}, ctx.Err()
	}}
}
func barrierAppPlan(ctx context.Context, stage Stage) (*planner.AppPlan, error) {
	for _, cp := range stage.Predecessors {
		if cp.Intent.StageID != string(planner.InspectApps) {
			continue
		}
		for _, out := range cp.Outputs {
			if out.Role != "inspected-app-plan" {
				continue
			}
			r, e := stage.Transaction.OpenPredecessor(ctx, jobstore.PredecessorIdentity{StageID: cp.Intent.StageID, Digest: cp.Digest}, out, 1<<60)
			if e != nil {
				return nil, e
			}
			data, e := io.ReadAll(io.NewSectionReader(r, 0, min(out.Size, (8<<20)+1)))
			e = errors.Join(e, r.Close())
			if e != nil {
				return nil, e
			}
			if len(data) > 8<<20 {
				return nil, ErrAppBarrier
			}
			var apps planner.AppPlan
			if e = json.Unmarshal(data, &apps); e != nil {
				return nil, e
			}
			return &apps, nil
		}
	}
	return nil, ErrAppBarrier
}
func CustomizationHandler(executor *service.CustomizationExecutor, inputs CustomizationInputProvider, emit model.Emit) Handler {
	return Handler{RequiresElevation: true, Run: func(ctx context.Context, stage Stage) (Result, error) {
		if stage.Transaction == nil || stage.Plan.Validate() != nil || stage.Operation.Kind != planner.CustomizeImage {
			return Result{}, planner.ErrInvalidPlan
		}
		if inputs == nil {
			return Result{}, ErrCustomizationInputsUnavailable
		}
		if executor == nil || executor.Backend == nil {
			return Result{}, service.ErrProviderUnavailable
		}
		plan := stage.Plan.CustomizationPlan()
		if plan == nil {
			return Result{}, planner.ErrInvalidPlan
		}
		bound := false
		for _, input := range stage.Operation.Inputs {
			bound = bound || input.Name == "customization-plan" && input.Digest == plan.Digest
		}
		if !bound {
			return Result{}, planner.ErrIdentityChanged
		}
		req, e := inputs.CustomizationInputs(ctx, stage)
		if e != nil {
			return Result{}, e
		}
		req.Plan = *plan
		req.Transaction = stage.Transaction
		req.ResolvedApps = nil
		if plan.Apps.Deferred {
			if req.ResolvedApps, e = barrierAppPlan(ctx, stage); e != nil {
				return Result{}, e
			}
		}
		result, e := executor.Execute(ctx, req, emit)
		if e != nil {
			return Result{}, e
		}
		result.WIMPath = filepath.Base(result.WIMPath)
		if result.BootWIMPath != "" {
			result.BootWIMPath = filepath.Base(result.BootWIMPath)
		}
		output, e := writeStageResult(stage, result, "customized-images")
		if e != nil {
			return Result{}, e
		}
		return Result{Outputs: append(result.Outputs, output)}, ctx.Err()
	}}
}
