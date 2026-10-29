package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/jobs"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
	"uupbuilder/internal/worker"

	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
	"uupbuilder/internal/tui"
)

func TestDefaultBuildRejectsExcludedSettingsBeforeSourcePreparation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Image.UpdateID = "revision"
	cfg.Output.Directory = t.TempDir()
	opts := Options{Config: cfg}
	closeBuild := composeInteractiveBuild(&opts)
	defer closeBuild()
	cfg.Output.Kind = model.OutputDirectory
	_, err := opts.Dependencies.Builder.Prepare(context.Background(), tui.BuildDraft{Config: cfg, Revision: 5})
	if err == nil || !strings.Contains(err.Error(), "output.kind") {
		t.Fatalf("explicit excluded setting: %v", err)
	}
}
func TestPrivateWorkerModeRejectsMalformedBootstrap(t *testing.T) {
	handled, err := runPrivateWorker(context.Background(), []string{"--uup-worker", "invalid"})
	if !handled || err == nil {
		t.Fatalf("private mode reached interactive config path: %v %v", handled, err)
	}
}

type shutdownMounts struct{ complete atomic.Bool }

func (m *shutdownMounts) Inspect(context.Context, string) (jobstore.MountSnapshot, error) {
	return jobstore.MountSnapshot{Complete: m.complete.Load()}, nil
}

func shutdownPlan(t *testing.T) planner.ReadyPlan {
	t.Helper()
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.Image.UpdateID = "shutdown-revision"
	cfg.Storage.Workspace = root
	cfg.Storage.Cache = root
	cfg.Output.Directory = root
	selection, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: selection.UpdateID, BuildLabel: "shutdown-fixture", Architecture: selection.Architecture, Language: selection.Language}, []model.Payload{{Destination: "payload", Identity: model.PayloadIdentity{Size: 1, Digest: model.Digest{Algorithm: model.DigestSHA256, Value: strings.Repeat("a", 64)}, Provenance: model.PackageProvenance{Source: "uup", Name: "payload"}}}})
	if err != nil {
		t.Fatal(err)
	}
	host, err := platform.DetectHost(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := planner.Planner{InspectStorage: inspectBuildStorage}
	plan, err := p.Resolve(context.Background(), planner.Request{Selection: selection, Settings: settings, Resolution: source.Resolution{Selection: selection, Settings: settings, Manifest: manifest}, Host: host, Intent: planner.DownloadOnly})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestInteractiveExitReportsPreservedBuildResources(t *testing.T) {
	for _, completedBeforeQuit := range []bool{false, true} {
		name := "active-at-quit"
		if completedBeforeQuit {
			name = "completed-before-quit"
		}
		t.Run(name, func(t *testing.T) {
			plan := shutdownPlan(t)
			inspector := &shutdownMounts{}
			inspector.complete.Store(true)
			entered, readyToQuit := make(chan struct{}), make(chan struct{})
			var ownedFile string
			registry := worker.NewRegistry()
			if err := registry.Register(planner.DownloadPayloads, worker.Handler{Run: func(ctx context.Context, stage worker.Stage) (worker.Result, error) {
				file, err := stage.Transaction.OpenFile("result.json", os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					return worker.Result{}, err
				}
				if _, err = file.WriteString("active operation data"); err != nil {
					file.Close()
					return worker.Result{}, err
				}
				if err = file.Close(); err != nil {
					return worker.Result{}, err
				}
				ownedFile, err = stage.Transaction.ScratchPath("result.json")
				if err != nil {
					return worker.Result{}, err
				}
				inspector.complete.Store(false)
				close(entered)
				<-ctx.Done()
				return worker.Result{}, ctx.Err()
			}}); err != nil {
				t.Fatal(err)
			}
			controller := jobs.NewController(jobs.Options{Registry: registry, InspectStorage: inspectBuildStorage, MountInspector: inspector})
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = controller.Close(ctx)
			})
			startResult := make(chan error, 1)
			deps := tui.Dependencies{Builder: &buildService{controller: controller}, Catalog: startupCatalog{search: func(ctx context.Context, _ string) ([]catalog.Build, error) {
				view, err := controller.Start(context.Background(), plan)
				if err != nil {
					startResult <- err
					close(readyToQuit)
					return nil, err
				}
				select {
				case <-entered:
				case <-ctx.Done():
					startResult <- ctx.Err()
					close(readyToQuit)
					return nil, ctx.Err()
				}
				if completedBeforeQuit {
					err = controller.Cancel(ctx, view.ID)
					if err == nil {
						err = errors.New("expected cancellation to preserve unknown resources")
					}
					startResult <- err
				} else {
					startResult <- nil
				}
				close(readyToQuit)
				return nil, nil
			}}}
			options := append(headlessProgramOptions(), tea.WithFilter(func(_ tea.Model, msg tea.Msg) tea.Msg {
				select {
				case <-readyToQuit:
					return tea.Quit()
				default:
					return msg
				}
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := runInteractive(ctx, Options{Config: config.Defaults(), ConfigPath: filepath.Join(t.TempDir(), "config.toml"), Dependencies: deps}, options...)
			select {
			case startErr := <-startResult:
				if startErr != nil && (!completedBeforeQuit || !strings.Contains(startErr.Error(), "preserved")) {
					t.Fatalf("active handler setup: %v", startErr)
				}
			case <-ctx.Done():
				t.Fatalf("active handler setup did not finish: %v", ctx.Err())
			}
			if err == nil || !strings.Contains(err.Error(), "resources preserved") {
				t.Fatalf("interactive exit lost preservation failure: %v", err)
			}
			data, readErr := os.ReadFile(ownedFile)
			if readErr != nil || string(data) != "active operation data" {
				t.Fatalf("unknown-state resources were removed or changed: %q %v", data, readErr)
			}
		})
	}
}
