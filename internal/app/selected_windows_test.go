package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
	"uupbuilder/internal/download"
	"uupbuilder/internal/engine/output"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
	"uupbuilder/internal/worker"
)

func actualSelectedPlan(t *testing.T) (planner.ReadyPlan, download.Materialized) {
	t.Helper()
	dir := os.Getenv("UUP_BUILDER_U09_PLAN_WORKSPACE")
	if dir == "" {
		t.Skip("actual selected source inputs not configured")
	}
	read := func(name string, v any) {
		t.Helper()
		raw, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(raw, v); e != nil {
			t.Fatal(e)
		}
	}
	var base, apps struct {
		Manifest model.PayloadManifest
		Files    []download.CachedFile
	}
	var snapshot source.AppCatalogSnapshot
	read("prepared-selected-source.json", &base)
	read("prepared-selected-apps.json", &apps)
	read("selected-app-catalog.json", &snapshot)
	appQuery := snapshot.AppQuery
	appQuery.Projection = apps.Manifest.Payloads
	manifest, _, err := source.Union(base.Manifest.Source, []catalog.FileSet{{Source: base.Manifest.Source, Payloads: base.Manifest.Payloads}, {Source: snapshot.AppSource, Payloads: apps.Manifest.Payloads}}, model.SourceQuery{UpdateID: base.Manifest.Source.UpdateID, Language: base.Manifest.Source.Language, Edition: "PROFESSIONAL"}, appQuery)
	if err != nil {
		t.Fatal(err)
	}
	files := download.Materialized{}
	for _, f := range append(base.Files, apps.Files...) {
		files[f.Identity] = f
	}
	raw, err := os.ReadFile(filepath.Join(dir, "source-metadata/apps/desktoptargetcompdb_app_neutral.xml.cab"))
	if err != nil {
		t.Fatal(err)
	}
	var docs []metadata.Document
	for _, ref := range snapshot.Documents {
		if strings.Contains(strings.ToLower(ref.Resource.Member), "app_neutral") {
			docs = append(docs, metadata.Document{Reference: ref, Format: metadata.FormatCompositionXML, Original: raw, Provenance: "actual selected source component check"})
		}
	}
	inv, err := source.InspectSelected(context.Background(), manifest, files, docs)
	if err != nil {
		t.Fatal(err)
	}
	for _, gap := range inv.Gaps {
		if gap.Code != "app-dependency-unresolved" {
			t.Fatalf("selected inventory gap: %+v", gap)
		}
	}
	cfg, err := config.Load(filepath.Join(dir, "iso-settings.toml"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cfg.Storage.Cache = root
	cfg.Storage.Workspace = root
	cfg.Output.Directory = root
	selection, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	host, err := platform.DetectHost(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := &planner.Planner{InspectStorage: inspectBuildStorage, DefaultCache: root, DefaultWorkspace: root, ManagedSelected: true}
	plan, err := p.Resolve(context.Background(), planner.Request{Selection: selection, Settings: settings, Resolution: source.Resolution{Selection: selection, Settings: settings, Manifest: manifest, Inventory: inv, Classification: inv.Classification, AppPhase: metadata.PhaseOfflineProvisioning}, Host: host, DraftRevision: 1, Intent: planner.BuildMedia})
	if err != nil {
		t.Fatal(err)
	}
	return plan, files
}

type actualSelectedFetcher struct{ files download.Materialized }

func (f actualSelectedFetcher) Fetch(context.Context, model.PayloadManifest, model.Locators, model.Emit) (download.Materialized, error) {
	return f.files, nil
}

type selectedNoMounts struct{}

func (selectedNoMounts) Inspect(context.Context, string) (jobstore.MountSnapshot, error) {
	return jobstore.MountSnapshot{Complete: true}, nil
}
func TestSelectedActualAssemblyCheckpoint(t *testing.T) {
	if os.Getenv("UUP_SELECTED_ASSEMBLY") != "1" {
		t.Skip("set UUP_SELECTED_ASSEMBLY=1 for actual non-elevated source assembly")
	}
	ctx := context.Background()
	plan, files := actualSelectedPlan(t)
	store, err := jobstore.Create(plan.EffectiveSettings().Storage.Workspace, "selected-component", selectedNoMounts{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	native, err := platform.CreateWorkspace(os.TempDir(), "selected-assembly-component")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := removeSelectedScratch(native); err != nil {
			t.Error(err)
		}
	}()
	pipeline := &worker.CheckpointPipeline{Workspace: native, Native: &output.Native{Workspace: native, WIMLib: filepath.Join(os.Getenv("UUP_BUILDER_U09_PLAN_WORKSPACE"), "managed-tools/wimlib/wimlib-imagex.exe")}}
	var predecessors []jobstore.Checkpoint
	for _, op := range plan.Operations()[:2] {
		intent := jobstore.MutationIntent{JobID: "selected-component", PlanDigest: plan.Digest(), ConfigDigest: plan.Digest(), StageID: op.ID, OwnedPaths: op.OwnedPaths}
		for _, cp := range predecessors {
			intent.Predecessors = append(intent.Predecessors, jobstore.PredecessorIdentity{StageID: cp.Intent.StageID, Digest: cp.Digest})
		}
		for _, input := range op.Inputs {
			intent.Inputs = append(intent.Inputs, jobstore.NamedDigest{Name: input.Name, Digest: input.Digest})
		}
		for _, rule := range op.Rules {
			intent.Rules = append(intent.Rules, jobstore.VersionedIdentity{Name: rule.Name, Version: rule.Version, Digest: rule.Digest})
		}
		tx, err := store.Begin(ctx, intent)
		if err != nil {
			t.Fatal(err)
		}
		stage := worker.Stage{Plan: plan, Operation: op, Transaction: tx, Predecessors: predecessors}
		handler := worker.PreparationHandler(actualSelectedFetcher{files}, nil)
		if op.Kind == planner.AssembleImage {
			handler = pipeline.AssemblyHandler()
		}
		t.Logf("running actual component stage %s", op.Kind)
		result, err := handler.Run(ctx, stage)
		if err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx, result.Outputs); err != nil {
			t.Fatal(err)
		}
		live, err := store.InspectRecovery(ctx, "selected-component")
		if err != nil {
			t.Fatal(err)
		}
		for _, status := range live.Checkpoints {
			if status.Valid && status.Checkpoint.Intent.StageID == op.ID {
				predecessors = append(predecessors, status.Checkpoint)
			}
		}
	}
	if len(predecessors) != 2 || len(predecessors[1].Outputs) != 4 {
		t.Fatal("actual assembly checkpoint incomplete")
	}
	for _, file := range predecessors[1].Outputs {
		t.Logf("assembled checkpoint %s bytes=%d sha256=%s", file.Role, file.Size, file.SHA256)
	}
}
func TestSelectedActualFrozenPlan(t *testing.T) {
	plan, _ := actualSelectedPlan(t)
	serviceJSON, _ := json.Marshal(plan.ServicePlan())
	if !strings.Contains(string(serviceJSON), "43587b49ad0402924340c616021c23c369720668b22be54a59371cb14eb4dd4d") {
		t.Fatal("source-default EdgeContent payload absent from frozen servicing plan")
	}
	encoded, err := plan.MarshalTOML()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := planner.DecodeReadyPlan(encoded)
	if err != nil || decoded.Digest() != plan.Digest() {
		t.Fatal(err)
	}
	if len(plan.ServicePlan().Updates) != 2 || len(plan.ServicePlan().Editions) != 2 || len(plan.CustomizationPlan().Apps.Provision) != 17 {
		t.Fatal("settings closure changed")
	}
	if _, err := operationRegistry().Snapshot(plan); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual source frozen: %d payloads, %d update containers, %d editions, %d app/framework operations; %d byte plan; native servicing pending", len(plan.Manifest().Payloads), len(plan.ServicePlan().Updates), len(plan.ServicePlan().Editions), len(plan.CustomizationPlan().Apps.Provision), len(encoded))
}

func TestSelectedPreparationHonorsRetainedDownloads(t *testing.T) {
	w, err := platform.CreateWorkspace(t.TempDir(), "retained-selected-downloads")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(w.Path(), "retained.data")
	f, err := w.OpenFile("retained.data", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("verified input fixture"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	p := &sourcePreparation{cache: w, cacheReady: true, retainDownloads: true}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("requested retained download removed", err)
	}
}
