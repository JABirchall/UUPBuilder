package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/planner"
)

type appInspectionFixture struct{ inv metadata.Inventory }

func (f appInspectionFixture) InspectApps(context.Context, Stage) (metadata.Inventory, error) {
	return f.inv, nil
}

func TestAppInspectionBarrierBindsSourceDraftAndPreservedRequest(t *testing.T) {
	plan, store, _, _ := workerFixture(t)
	tx, e := store.Begin(context.Background(), jobstore.MutationIntent{JobID: "job-a", PlanDigest: plan.Digest(), ConfigDigest: plan.Digest(), StageID: string(planner.InspectApps), OwnedPaths: []string{"result.json"}})
	if e != nil {
		t.Fatal(e)
	}
	ref := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: plan.Manifest().Payloads[0].Identity}, SHA256: strings.Repeat("a", 64)}
	evidence := metadata.Evidence{Source: plan.Manifest().Source, Document: ref, Selector: "/Package/Identity"}
	family := metadata.AppFamily{Name: "Example", Publisher: "CN=Publisher"}
	inv := metadata.Inventory{Source: plan.Manifest().Source, Manifest: plan.Manifest(), Documents: []metadata.Document{{Reference: ref}}, Apps: metadata.AppInventory{Packages: []metadata.AppPackage{{Identity: metadata.AppIdentity{Name: family.Name, Publisher: family.Publisher, Version: "1.0.0.0", Architecture: "neutral"}, Family: family, Phase: metadata.PhaseOfflineProvisioning, Evidence: evidence}}, SelectionRules: []metadata.AppSelectionRule{{ID: "Source.Feature", Family: family, Default: true, LicenseFree: true, Evidence: evidence}}}}
	stage := Stage{Plan: plan, Operation: planner.Operation{Kind: planner.InspectApps}, Transaction: tx, Predecessors: []jobstore.Checkpoint{{Digest: strings.Repeat("b", 64), Intent: jobstore.MutationIntent{StageID: string(planner.AssembleImage)}}}}
	result, e := AppInspectionHandler(appInspectionFixture{inv}).Run(context.Background(), stage)
	if e != nil {
		t.Fatal(e)
	}
	barrier := result.AppBarrier
	if barrier == nil || barrier.PlanDigest != plan.Digest() || barrier.DraftRevision != plan.DraftRevision() || barrier.RequestedSettingsDigest != identityDigest(plan.RequestedSettings()) || barrier.ObservationDigest != result.Outputs[0].SHA256 {
		t.Fatalf("unbound barrier: %+v", result)
	}
}
func TestCustomizationHandlerRetainsConcreteMissingInputFailure(t *testing.T) {
	plan, store, _, _ := workerFixture(t)
	tx, e := store.Begin(context.Background(), jobstore.MutationIntent{JobID: "job-a", PlanDigest: plan.Digest(), ConfigDigest: plan.Digest(), StageID: string(planner.CustomizeImage), OwnedPaths: []string{"result.json"}})
	if e != nil {
		t.Fatal(e)
	}
	_, e = CustomizationHandler(nil, nil, nil).Run(context.Background(), Stage{Plan: plan, Operation: planner.Operation{Kind: planner.CustomizeImage}, Transaction: tx})
	if !errors.Is(e, ErrCustomizationInputsUnavailable) {
		t.Fatalf("missing inspected inputs hidden: %v", e)
	}
}
