package worker

import (
	"context"
	"errors"
	"testing"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/planner"
)

func TestServicingHandlerMissingAssemblyProviderIsConcreteBlocker(t *testing.T) {
	plan, store, _, _ := workerFixture(t)
	tx, err := store.Begin(context.Background(), jobstore.MutationIntent{JobID: "job-a", PlanDigest: plan.Digest(), ConfigDigest: plan.Digest(), StageID: "service-image", OwnedPaths: []string{"result.json"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ServicingHandler(nil, nil, nil).Run(context.Background(), Stage{Plan: plan, Operation: planner.Operation{Kind: planner.ServiceImage}, Transaction: tx})
	if !errors.Is(err, ErrServiceInputsUnavailable) {
		t.Fatalf("missing provider hidden: %v", err)
	}
}
