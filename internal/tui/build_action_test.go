package tui

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"uupbuilder/internal/catalog"

	"uupbuilder/internal/config"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	"uupbuilder/internal/source"
	"uupbuilder/internal/tools"
)

type blockedBuild struct {
	prepare func(context.Context, BuildDraft) (planner.ReadyPlan, error)
}

type preparedBuild struct {
	plan  planner.ReadyPlan
	calls *int
}

func (b preparedBuild) CheckTools(context.Context, BuildDraft) ([]string, error) {
	return []string{"tools available"}, nil
}
func (b blockedBuild) CheckTools(context.Context, BuildDraft) ([]string, error) {
	return []string{"tools available"}, nil
}

func (b preparedBuild) Prepare(context.Context, BuildDraft) (planner.ReadyPlan, error) {
	return b.plan, nil
}
func (b preparedBuild) Execute(context.Context, planner.ReadyPlan) (BuildResult, error) {
	*b.calls++
	return BuildResult{JobID: "job-a", State: "failed", Error: "master-iso handler unavailable"}, nil
}
func preparedModel(t *testing.T, intent planner.JobIntent, appEvidence ...bool) (Model, *int) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Image.UpdateID = "revision"
	cfg.Storage.Workspace = t.TempDir()
	cfg.Storage.Cache = t.TempDir()
	cfg.Output.Directory = t.TempDir()
	selection, settings, _ := cfg.Request()
	manifest, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: selection.UpdateID, BuildLabel: "build", Architecture: selection.Architecture, Language: selection.Language}, []model.Payload{{Destination: "payload", Identity: model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: strings.Repeat("a", 64)}, Size: 1, Provenance: model.PackageProvenance{Source: "uup", Name: "payload"}}}})
	if err != nil {
		t.Fatal(err)
	}
	p := planner.Planner{InspectStorage: func(_ context.Context, path string) (planner.Volume, error) {
		return planner.Volume{Path: path, ID: path, AvailableBytes: 1 << 40, MaxFileBytes: 1 << 40, FileSystem: model.FileSystemCapabilities{Name: "NTFS", Local: true, ACLs: true, AlternateStreams: true, HardLinks: true}}, nil
	}, SelectTools: func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }}
	inv := metadata.Inventory{Source: manifest.Source, Manifest: manifest, Images: []metadata.Image{{Index: 1, Edition: selection.Editions[0], Build: "10.0.28000.1", Architecture: selection.Architecture}}, Classification: metadata.ClassificationSemanticInventory}
	if len(appEvidence) > 0 && appEvidence[0] {
		ref := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: manifest.Payloads[0].Identity}, SHA256: strings.Repeat("a", 64)}
		ev := metadata.Evidence{Source: manifest.Source, Document: ref, Selector: "/Package/Identity"}
		family := metadata.AppFamily{Name: "Example", Publisher: "CN=Publisher"}
		inv.Documents = []metadata.Document{{Reference: ref}}
		inv.Apps = metadata.AppInventory{Packages: []metadata.AppPackage{{Identity: metadata.AppIdentity{Name: family.Name, Publisher: family.Publisher, Version: "1.0.0.0", Architecture: "neutral"}, Family: family, Phase: metadata.PhaseOfflineProvisioning, Evidence: ev}}, SelectionRules: []metadata.AppSelectionRule{{ID: "Source.Feature", Family: family, Default: true, LicenseFree: true, Evidence: ev}}}
	}
	plan, err := p.Resolve(context.Background(), planner.Request{Selection: selection, Settings: settings, Resolution: source.Resolution{Selection: selection, Settings: settings, Manifest: manifest, Inventory: inv, Classification: metadata.ClassificationSemanticInventory, AppPhase: metadata.PhaseOfflineProvisioning}, Host: model.Host{WindowsBuild: 26100, NativeArchitecture: "amd64", ProcessArchitecture: "amd64"}, DraftRevision: 1, Intent: intent})
	if err != nil {
		t.Fatal(err)
	}
	calls := new(int)
	m := New(Dependencies{Catalog: testCatalog{}, ConfigPath: filepath.Join(t.TempDir(), "config.toml"), Builder: preparedBuild{plan: plan, calls: calls}}, cfg)
	m.area = Conversion
	m.image.sourceChecked = true
	m.image.languageChecked = true
	m.image.editionsChecked = true
	m.image.editions = []catalog.Edition{{ID: "professional"}}
	return m, calls
}

func TestAppsApplicableRequiresMatchingValidatedSourceAndDraft(t *testing.T) {
	m, _ := preparedModel(t, planner.BuildMedia, true)
	if m.Snapshot().AppsApplicable {
		t.Fatal("unprepared draft is applicable")
	}
	m, prepare := step(m, BuildMsg{})
	m, _ = step(m, prepare())
	if m.Snapshot().AppsApplicable {
		t.Fatal("tool check asserted app applicability")
	}
	m, execute := step(m, StartBuildMsg{})
	m = drainBuild(t, m, execute)
	if !m.Snapshot().AppsApplicable {
		t.Fatalf("matching semantic plan not bound: %s", m.notice)
	}
	m.setAppStub(model.AppStub)
	if m.Snapshot().AppsApplicable || m.Snapshot().AppsNotice == "" {
		t.Fatal("app edit retained stale applicability")
	}
	m, _ = preparedModel(t, planner.BuildMedia, true)
	m, prepare = step(m, BuildMsg{})
	m, _ = step(m, prepare())
	m, execute = step(m, StartBuildMsg{})
	m = drainBuild(t, m, execute)
	m.cfg.Image.Language = "de-de"
	if m.Snapshot().AppsApplicable {
		t.Fatal("source change retained applicability")
	}
}
func TestCancelledPreflightCannotExecuteLatePlan(t *testing.T) {
	m, calls := preparedModel(t, planner.BuildMedia)
	m, cmd := step(m, BuildMsg{})
	prepared := cmd()
	m, _ = step(m, BuildMsg{})
	m, next := step(m, prepared)
	if next != nil {
		next()
	}
	if *calls != 0 || !strings.Contains(m.notice, "cancelled") {
		t.Fatalf("cancelled preflight executed %d times: %s", *calls, m.notice)
	}
}
func TestConversionBuildRequiresBuildMediaIntent(t *testing.T) {
	m, calls := preparedModel(t, planner.DownloadOnly)
	m, cmd := step(m, BuildMsg{})
	m, _ = step(m, cmd())
	m, next := step(m, StartBuildMsg{})
	m = drainBuild(t, m, next)
	if *calls != 0 || !strings.Contains(m.notice, "identity") {
		t.Fatalf("wrong user intent executed %d times: %s", *calls, m.notice)
	}
}
func TestConversionBuildConnectsFrozenRequestAndResult(t *testing.T) {
	m, calls := preparedModel(t, planner.BuildMedia)
	m, cmd := step(m, conversionFocusMsg{index: 3})
	if cmd == nil {
		t.Fatalf("Conversion action did not invoke preflight: %s", m.notice)
	}
	m, next := step(m, cmd())
	if next != nil || m.area != Review {
		t.Fatalf("tool check did not wait in Review: %s", m.notice)
	}
	m, execute := step(m, StartBuildMsg{})
	m = drainBuild(t, m, execute)
	if *calls != 1 || m.area != Progress || !strings.Contains(m.notice, "master-iso handler unavailable") {
		t.Fatalf("result connection: %d %s", *calls, m.notice)
	}
}

func (b blockedBuild) Prepare(ctx context.Context, d BuildDraft) (planner.ReadyPlan, error) {
	return b.prepare(ctx, d)
}
func (blockedBuild) Execute(context.Context, planner.ReadyPlan) (BuildResult, error) {
	panic("rejected draft executed")
}
func TestConversionBuildRejectsUncheckedAndInvalidDrafts(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	m, cmd := step(m, BuildMsg{})
	if cmd != nil || !strings.Contains(m.notice, "image choices") {
		t.Fatalf("unchecked source started: %s", m.notice)
	}
	m.cfg.Image.UpdateID = "revision"
	m.cfg.Image.Language = "en-us"
	m.cfg.Image.Editions = []string{"professional"}
	m.image.sourceChecked = true
	m.image.languageChecked = true
	m.image.editionsChecked = true
	m.image.editions = []catalog.Edition{{ID: "professional"}}
	m.conversion.set("downloads.parallel_files", "0")
	m, cmd = step(m, BuildMsg{})
	if cmd != nil || !strings.Contains(m.notice, "parallel_files") {
		t.Fatalf("invalid settings started: %s", m.notice)
	}
}
func TestConversionBuildShowsSpecificBlockerAndDiscardsStalePlanning(t *testing.T) {
	cfg := config.Defaults()
	cfg.Image.UpdateID = "revision"
	m := New(Dependencies{Catalog: testCatalog{}, ConfigPath: filepath.Join(t.TempDir(), "config.toml"), Builder: blockedBuild{prepare: func(context.Context, BuildDraft) (planner.ReadyPlan, error) {
		return planner.ReadyPlan{}, errors.New("metadata-discovery-unavailable: source discovery producer missing")
	}}}, cfg)
	m.image.sourceChecked = true
	m.image.languageChecked = true
	m.image.editionsChecked = true
	m.image.editions = []catalog.Edition{{ID: "professional"}}
	m, cmd := step(m, BuildMsg{})
	if cmd == nil {
		t.Fatalf("no build command: %s", m.notice)
	}
	result := cmd()
	m = send(m, result)
	m, cmd = step(m, StartBuildMsg{})
	m = drainBuild(t, m, cmd)
	if !strings.Contains(m.notice, "metadata-discovery-unavailable") {
		t.Fatalf("specific blocker hidden: %s", m.notice)
	}
	m, cmd = step(m, BuildMsg{})
	result = cmd()
	m.revision++
	m = send(m, result)
	if !strings.Contains(m.notice, "draft changed") {
		t.Fatalf("stale plan was accepted: %s", m.notice)
	}
}
