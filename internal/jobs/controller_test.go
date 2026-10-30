//go:build windows

package jobs

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"uupbuilder/internal/config"
	"uupbuilder/internal/engine/output"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
	"uupbuilder/internal/tools"
	"uupbuilder/internal/worker"
)

type mounts struct{ complete bool }
type changingMounts struct{ complete atomic.Bool }

func (m *changingMounts) Inspect(context.Context, string) (jobstore.MountSnapshot, error) {
	return jobstore.MountSnapshot{Complete: m.complete.Load()}, nil
}

func (m mounts) Inspect(context.Context, string) (jobstore.MountSnapshot, error) {
	return jobstore.MountSnapshot{Complete: m.complete}, nil
}
func storage(_ context.Context, path string) (planner.Volume, error) {
	v, e := platform.InspectStorage(path)
	return planner.Volume{Path: v.Path, ID: v.ID, FileSystem: v.Capabilities, AvailableBytes: v.AvailableBytes, MaxFileBytes: v.MaxFileBytes}, e
}
func jobPlan(t *testing.T) planner.ReadyPlan {
	t.Helper()
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.Image.UpdateID = "revision"
	cfg.Storage.Workspace = root
	cfg.Storage.Cache = root
	cfg.Output.Directory = root
	sel, settings, _ := cfg.Request()
	manifest, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: sel.UpdateID, BuildLabel: "build", Architecture: sel.Architecture, Language: sel.Language}, []model.Payload{{Destination: "payload", Identity: model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: strings.Repeat("a", 64)}, Size: 1, Provenance: model.PackageProvenance{Source: "uup", Name: "payload"}}}})
	if err != nil {
		t.Fatal(err)
	}
	host, err := platform.DetectHost(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := planner.Planner{InspectStorage: storage}
	plan, err := p.Resolve(context.Background(), planner.Request{Selection: sel, Settings: settings, Resolution: source.Resolution{Selection: sel, Settings: settings, Manifest: manifest}, Host: host, Intent: planner.DownloadOnly})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func TestOneConversionAtATime(t *testing.T) {
	plan := jobPlan(t)
	entered := make(chan struct{})
	registry := worker.NewRegistry()
	if err := registry.Register(planner.DownloadPayloads, worker.Handler{Run: func(ctx context.Context, s worker.Stage) (worker.Result, error) {
		close(entered)
		<-ctx.Done()
		return worker.Result{}, ctx.Err()
	}}); err != nil {
		t.Fatal(err)
	}
	c := NewController(Options{Registry: registry, InspectStorage: storage, MountInspector: mounts{true}})
	view, err := c.Start(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler not entered")
	}
	if _, err := c.Start(context.Background(), plan); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent conversion: %v", err)
	}
	if err := c.Cancel(context.Background(), "foreign"); err == nil {
		t.Fatal("foreign cancellation accepted")
	}
	if err := c.Cancel(context.Background(), view.ID); err != nil {
		t.Fatal(err)
	}
	final, err := c.View(view.ID)
	if err != nil || final.State != Cancelled {
		t.Fatalf("cancel snapshot: %#v %v", final, err)
	}
	if len(final.Actions) != 0 {
		t.Fatal("finished job still offers cancellation")
	}
}
func TestMissingHandlerBlocksBeforeWorkspace(t *testing.T) {
	plan := jobPlan(t)
	parent := plan.EffectiveSettings().Storage.Workspace
	before, _ := os.ReadDir(parent)
	c := NewController(Options{Registry: worker.NewRegistry(), InspectStorage: storage})
	if _, err := c.Start(context.Background(), plan); !errors.Is(err, worker.ErrMissingHandler) || !strings.Contains(err.Error(), "download-payloads") {
		t.Fatalf("missing producer: %v", err)
	}
	after, _ := os.ReadDir(parent)
	if len(before) != len(after) {
		t.Fatal("missing handler created a workspace")
	}
}
func TestCancellationPreservesUnknownMountState(t *testing.T) {
	plan := jobPlan(t)
	inspector := &changingMounts{}
	inspector.complete.Store(true)
	entered := make(chan struct{})
	var ownedFile string
	registry := worker.NewRegistry()
	_ = registry.Register(planner.DownloadPayloads, worker.Handler{Run: func(ctx context.Context, s worker.Stage) (worker.Result, error) {
		file, err := s.Transaction.OpenFile("result.json", os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return worker.Result{}, err
		}
		file.Close()
		ownedFile, _ = s.Transaction.ScratchPath("result.json")
		inspector.complete.Store(false)
		close(entered)
		<-ctx.Done()
		return worker.Result{}, ctx.Err()
	}})
	c := NewController(Options{Registry: registry, InspectStorage: storage, MountInspector: inspector})
	view, err := c.Start(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler not entered")
	}
	if err := c.Cancel(context.Background(), view.ID); err == nil {
		t.Fatal("unknown mount cleanup reported success")
	}
	final, _ := c.View(view.ID)
	if final.State != Failed || !strings.Contains(final.Error, "preserved") {
		t.Fatalf("unknown resources: %#v", final)
	}
	if _, err := os.Stat(ownedFile); err != nil {
		t.Fatalf("unknown-state owned file was removed: %v", err)
	}
}

func TestNoOpHandlerCannotCompleteAJob(t *testing.T) {
	plan := jobPlan(t)
	registry := worker.NewRegistry()
	_ = registry.Register(planner.DownloadPayloads, worker.Handler{Run: func(context.Context, worker.Stage) (worker.Result, error) { return worker.Result{}, nil }})
	c := NewController(Options{Registry: registry, InspectStorage: storage, MountInspector: mounts{true}})
	view, err := c.Start(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	final, err := c.Wait(context.Background(), view.ID)
	if err != nil || final.State != Failed || !strings.Contains(final.Error, "nonempty outputs") {
		t.Fatalf("no-op reported success: %#v %v", final, err)
	}
}
func TestUnverifiedArtifactDescriptorCannotCompleteISO(t *testing.T) {
	download := jobPlan(t)
	host, err := platform.DetectHost(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := planner.Planner{InspectStorage: storage, SelectTools: func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }}
	selection, settings, manifest := download.Selection(), download.RequestedSettings(), download.Manifest()
	plan, err := p.Resolve(context.Background(), planner.Request{Selection: selection, Settings: settings, Resolution: source.Resolution{Selection: selection, Settings: settings, Manifest: manifest, Inventory: metadata.Inventory{Source: manifest.Source, Manifest: manifest, Images: []metadata.Image{{Index: 1, Edition: selection.Editions[0], Build: "10.0.28000.1", Architecture: selection.Architecture}}, Classification: metadata.ClassificationSemanticInventory}, Classification: metadata.ClassificationSemanticInventory, AppPhase: metadata.PhaseOfflineProvisioning}, Host: host, Intent: planner.BuildMedia})
	if err != nil {
		t.Fatal(err)
	}
	registry := worker.NewRegistry()
	for _, op := range plan.Operations() {
		_ = registry.Register(op.Kind, worker.Handler{Run: func(context.Context, worker.Stage) (worker.Result, error) {
			t.Error("unverified ISO producer entered mutation")
			return worker.Result{Artifacts: []model.Artifact{{Kind: model.OutputISO, Path: "fake.iso"}}}, nil
		}})
	}
	c := NewController(Options{Registry: registry, InspectStorage: storage})
	before, _ := os.ReadDir(settings.Storage.Workspace)
	if _, err := c.Start(context.Background(), plan); !errors.Is(err, ErrPublicationUnavailable) {
		t.Fatalf("unverified ISO completion: %v", err)
	}
	after, _ := os.ReadDir(settings.Storage.Workspace)
	if len(before) != len(after) {
		t.Fatal("unverified publication created workspace")
	}
}

func TestCompletionRejectsDescriptorsAndEmptyPublicationCapability(t *testing.T) {
	plan := jobPlan(t)
	for _, result := range []worker.Result{{Artifacts: []model.Artifact{{Kind: model.OutputISO, Path: "fake.iso"}}}, {Publication: &output.PublishedArtifact{}}} {
		if _, err := verifiedCompletion(context.Background(), plan, result); err == nil {
			t.Fatal("unverified destination completed")
		}
	}
}

func TestCloseRetainsCompletedCleanupFailure(t *testing.T) {
	plan := jobPlan(t)
	inspector := &changingMounts{}
	inspector.complete.Store(true)
	entered := make(chan struct{})
	registry := worker.NewRegistry()
	_ = registry.Register(planner.DownloadPayloads, worker.Handler{Run: func(ctx context.Context, stage worker.Stage) (worker.Result, error) {
		file, err := stage.Transaction.OpenFile("result.json", os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return worker.Result{}, err
		}
		if err := file.Close(); err != nil {
			return worker.Result{}, err
		}
		inspector.complete.Store(false)
		close(entered)
		<-ctx.Done()
		return worker.Result{}, ctx.Err()
	}})
	c := NewController(Options{Registry: registry, InspectStorage: storage, MountInspector: inspector})
	view, err := c.Start(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler not entered")
	}
	if err := c.Cancel(context.Background(), view.ID); !errors.Is(err, errCleanup) {
		t.Fatalf("cancel did not retain preservation failure: %v", err)
	}
	// The job has already completed before teardown observes the controller.
	if err := c.Close(context.Background()); !errors.Is(err, errCleanup) {
		t.Fatalf("completed cleanup failure disappeared during close: %v", err)
	}
	if err := c.Close(context.Background()); !errors.Is(err, errCleanup) {
		t.Fatalf("repeated close forgot cleanup failure: %v", err)
	}
}

func TestCloseReportsActiveCancellationTimeout(t *testing.T) {
	plan := jobPlan(t)
	entered, release := make(chan struct{}), make(chan struct{})
	registry := worker.NewRegistry()
	_ = registry.Register(planner.DownloadPayloads, worker.Handler{Run: func(ctx context.Context, _ worker.Stage) (worker.Result, error) {
		close(entered)
		<-release
		return worker.Result{}, ctx.Err()
	}})
	c := NewController(Options{Registry: registry, InspectStorage: storage, MountInspector: mounts{true}})
	view, err := c.Start(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(release); _ = c.Cancel(context.Background(), view.ID) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler not entered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("active cleanup wait timeout was lost: %v", err)
	}
}
