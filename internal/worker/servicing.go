package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"uupbuilder/internal/engine/service"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
)

var ErrServiceInputsUnavailable = errors.New("servicing requires an inspected assembled-image input provider")

type ServiceInputs struct {
	Images  []service.InspectedImage
	Updates []service.UpdateInput
}
type ServiceInputProvider interface {
	ServiceInputs(context.Context, Stage) (ServiceInputs, error)
}

// ServicingHandler supplies only the frozen plan and active transaction. The
// predecessor producer materializes inspected images/payloads, never commands or
// replacement plan authority. A missing assembler remains a concrete blocker.
func ServicingHandler(executor *service.Executor, inputs ServiceInputProvider, emit model.Emit) Handler {
	return Handler{RequiresElevation: true, Run: func(ctx context.Context, stage Stage) (Result, error) {
		if inputs == nil {
			return Result{}, ErrServiceInputsUnavailable
		}
		if executor == nil || executor.Backend == nil {
			return Result{}, service.ErrProviderUnavailable
		}
		if stage.Transaction == nil || stage.Plan.Validate() != nil || stage.Operation.Kind != planner.ServiceImage {
			return Result{}, planner.ErrInvalidPlan
		}
		plan := stage.Plan.ServicePlan()
		if plan == nil {
			return Result{}, planner.ErrInvalidPlan
		}
		bound := false
		for _, input := range stage.Operation.Inputs {
			bound = bound || input.Name == "service-plan" && input.Digest == plan.Digest
		}
		if !bound {
			return Result{}, planner.ErrIdentityChanged
		}
		materialized, err := inputs.ServiceInputs(ctx, stage)
		if err != nil {
			return Result{}, err
		}
		serviced, err := executor.Execute(ctx, service.ServiceRequest{Plan: *plan, Images: materialized.Images, Payloads: materialized.Updates, Transaction: stage.Transaction}, emit)
		if err != nil {
			return Result{}, err
		}
		// Checkpoint paths are relative. Consumers resolve them from the committed
		// predecessor outputs, never from an obsolete absolute scratch receipt.
		serviced.WIMPath = "serviced.wim"
		for i := range serviced.RetainedUpdates {
			serviced.RetainedUpdates[i].Path = filepath.Base(serviced.RetainedUpdates[i].Path)
		}
		for i := range serviced.RetainedBases {
			serviced.RetainedBases[i] = filepath.Base(serviced.RetainedBases[i])
		}
		data, err := json.Marshal(serviced)
		if err != nil {
			return Result{}, err
		}
		file, err := stage.Transaction.OpenFile("result.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return Result{}, err
		}
		_, writeErr := file.Write(data)
		err = errors.Join(writeErr, file.Sync(), file.Close())
		if err != nil {
			return Result{}, fmt.Errorf("write servicing result: %w", err)
		}
		sum := sha256.Sum256(data)
		outputs := append(serviced.Outputs, jobstore.OutputIdentity{Path: "result.json", Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Role: "serviced-images"})
		return Result{Outputs: outputs}, ctx.Err()
	}}
}
