package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/download"
	"uupbuilder/internal/engine/output"
	"uupbuilder/internal/engine/service"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
	"uupbuilder/internal/tools"
	"uupbuilder/internal/tui"
	"uupbuilder/internal/worker"
)

type selectedEnvironment struct {
	source     *sourcePreparation
	native     *platform.Workspace
	runtime    *tools.SelectedRuntime
	dism       *service.DISM
	pipeline   *worker.CheckpointPipeline
	catalog    *catalog.Client
	planDigest string
}

func newSelectedEnvironment(ctx context.Context, settings model.ResolvedSettings, endpoint string) (e *selectedEnvironment, err error) {
	e = &selectedEnvironment{source: &sourcePreparation{inspect: inspectBuildStorage, retainDownloads: settings.Storage.KeepDownloads}}
	defer func() {
		if err != nil {
			err = errors.Join(err, e.Close())
			e = nil
		}
	}()
	base, _ := os.UserCacheDir()
	cache := settings.Storage.Cache
	if cache == "auto" {
		cache = base
	}
	job := settings.Storage.Workspace
	if job == "auto" {
		job = base
	}
	e.source.cache, err = platform.CreateWorkspace(cache, "selected-source-cache")
	if err != nil {
		return
	}
	e.source.cacheReady = true
	e.source.job, err = platform.CreateWorkspace(job, "selected-source-transfer")
	if err != nil {
		return
	}
	e.source.jobReady = true
	e.source.transport, err = download.NewTransport(settings.Downloads.Proxy)
	if err != nil {
		return
	}
	e.catalog = catalog.New(&http.Client{Transport: e.source.transport}, endpoint)
	resolver := &source.Resolver{Catalog: e.catalog}
	e.source.manager, err = NewSourceManager(download.Options{Cache: e.source.cache, Job: e.source.job, Transport: e.source.transport, ParallelFiles: settings.Downloads.ParallelFiles, Retries: settings.Downloads.Retries, Proxy: settings.Downloads.Proxy}, resolver)
	if err != nil {
		return
	}
	e.native, err = platform.CreateWorkspace(os.TempDir(), "selected-native")
	if err != nil {
		return
	}
	return e, nil
}
func (e *selectedEnvironment) acquireRuntime(ctx context.Context) error {
	if e.runtime != nil {
		return nil
	}
	runtime, err := tools.AcquireSelected(ctx, e.native, e.source, nil)
	if err != nil {
		return err
	}
	e.runtime = runtime
	e.dism, err = service.NewManagedDISM(ctx, e.native, runtime)
	if err != nil {
		return err
	}
	digest, version := runtime.DISMIdentity()
	e.pipeline = &worker.CheckpointPipeline{Workspace: e.native, Runtime: runtime, Native: &output.Native{Workspace: e.native, WIMLib: runtime.WIMLib(), AdditionalTools: []output.ToolIdentity{{Name: "DISM", Version: version, SHA256: digest}, {Name: "DISM EdgeProvider (selected source)", Version: "10.0.28000.1", SHA256: "3b38d4cc77de1befabbcaf0ccf45964a022f760dd2caa58fb81df67da8155f54"}}}}
	return nil
}
func (e *selectedEnvironment) Close() error {
	if e == nil {
		return nil
	}
	var err error
	if e.dism != nil {
		err = errors.Join(err, e.dism.Close())
		e.dism = nil
	}
	if e.runtime != nil {
		err = errors.Join(err, e.runtime.Close())
		e.runtime = nil
	}
	if e.source != nil {
		err = errors.Join(err, e.source.Close())
		e.source = nil
	}
	if e.native != nil {
		// Only this active operation's fresh workspace is enumerated. Rooted,
		// single-entry removes never touch historical/pre-existing CAB scratch.
		if err == nil {
			err = removeSelectedScratch(e.native)
		} else {
			err = errors.Join(err, e.native.Close())
		}
		e.native = nil
	}
	return err
}
func removeSelectedScratch(w *platform.Workspace) error {
	var names []string
	err := filepath.WalkDir(w.Path(), func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == w.Path() {
			return nil
		}
		if de.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected link in selected scratch; preserving %s", w.Path())
		}
		rel, err := filepath.Rel(w.Path(), path)
		if err != nil {
			return err
		}
		if rel != ".uupbuilder-owner.json" {
			names = append(names, filepath.ToSlash(rel))
		}
		return nil
	})
	if err == nil {
		for i := len(names) - 1; i >= 0; i-- {
			if err = w.Remove(names[i]); err != nil {
				break
			}
		}
	}
	if err == nil {
		return w.RemoveEmpty()
	}
	return errors.Join(err, w.Close())
}
func (s *buildService) prepareSelected(ctx context.Context, draft tui.BuildDraft, selection model.Selection, settings model.ResolvedSettings, host model.Host) (planner.ReadyPlan, error) {
	if s.selected != nil {
		if err := s.selected.Close(); err != nil {
			return planner.ReadyPlan{}, err
		}
		s.selected = nil
	}
	env, err := newSelectedEnvironment(ctx, settings, draft.Config.Catalog.Endpoint)
	if err != nil {
		return planner.ReadyPlan{}, err
	}
	s.ownWorkspace(env.source.cache)
	s.ownWorkspace(env.source.job)
	s.ownWorkspace(env.native)
	resolution, err := source.ResolveSelected(ctx, env.catalog, source.NewAppCatalog(draft.Config.Catalog.Endpoint), env.source, selection, settings, nil)
	if err != nil {
		return planner.ReadyPlan{}, errors.Join(err, env.Close())
	}
	if err = env.acquireRuntime(ctx); err != nil {
		return planner.ReadyPlan{}, errors.Join(err, env.Close())
	}
	p := *s.planner
	p.ManagedSelected = true
	plan, err := p.Resolve(ctx, planner.Request{Selection: selection, Settings: settings, Resolution: resolution, Host: host, DraftRevision: draft.Revision, Intent: planner.BuildMedia})
	if err != nil {
		return plan, errors.Join(err, env.Close())
	}
	env.planDigest = plan.Digest()
	s.selected = env
	return plan, nil
}
func (s *buildService) selectedRegistry() *worker.Registry {
	registry := worker.NewRegistry()
	ensure := func(ctx context.Context, stage worker.Stage) (*selectedEnvironment, error) {
		if stage.Plan.Validate() != nil || len(stage.Plan.Tools()) != 1 || !tools.IsSelectedRequirement(stage.Plan.Tools()[0]) {
			return nil, source.ErrImplementationGap
		}
		if s.selected == nil {
			env, err := newSelectedEnvironment(ctx, stage.Plan.EffectiveSettings(), "")
			if err != nil {
				return nil, err
			}
			s.selected = env
			env.planDigest = stage.Plan.Digest()
			if err = env.acquireRuntime(ctx); err != nil {
				return nil, err
			}
		}
		if s.selected.planDigest != stage.Plan.Digest() {
			return nil, planner.ErrIdentityChanged
		}
		return s.selected, nil
	}
	register := func(kind planner.OperationKind, elevated bool, run func(context.Context, worker.Stage, *selectedEnvironment) (worker.Result, error)) {
		if err := registry.Register(kind, worker.Handler{RequiresElevation: elevated, Run: func(ctx context.Context, stage worker.Stage) (worker.Result, error) {
			env, err := ensure(ctx, stage)
			if err != nil {
				return worker.Result{}, err
			}
			return run(ctx, stage, env)
		}}); err != nil {
			panic(err)
		}
	}
	register(planner.DownloadPayloads, false, func(ctx context.Context, stage worker.Stage, e *selectedEnvironment) (worker.Result, error) {
		return worker.PreparationHandler(e.source, nil).Run(ctx, stage)
	})
	register(planner.AssembleImage, false, func(ctx context.Context, stage worker.Stage, e *selectedEnvironment) (worker.Result, error) {
		return e.pipeline.AssemblyHandler().Run(ctx, stage)
	})
	register(planner.ServiceImage, true, func(ctx context.Context, stage worker.Stage, e *selectedEnvironment) (worker.Result, error) {
		return worker.ServicingHandler(&service.Executor{Backend: e.dism}, e.pipeline, nil).Run(ctx, stage)
	})
	register(planner.CustomizeImage, true, func(ctx context.Context, stage worker.Stage, e *selectedEnvironment) (worker.Result, error) {
		return worker.CustomizationHandler(&service.CustomizationExecutor{Backend: e.dism}, e.pipeline, nil).Run(ctx, stage)
	})
	register(planner.ExportImage, false, func(ctx context.Context, stage worker.Stage, e *selectedEnvironment) (worker.Result, error) {
		return e.pipeline.ExportHandler().Run(ctx, stage)
	})
	register(planner.MasterISO, false, func(ctx context.Context, stage worker.Stage, e *selectedEnvironment) (worker.Result, error) {
		return e.pipeline.MasterHandler().Run(ctx, stage)
	})
	// The fixed publication handler, not a wrapper or descriptor, owns completion.
	if err := registry.Register(planner.PublishISO, worker.PublicationHandler(selectedPublication{ensure: ensure})); err != nil {
		panic(err)
	}
	return registry
}

type selectedPublication struct {
	ensure func(context.Context, worker.Stage) (*selectedEnvironment, error)
}

func (p selectedPublication) PublicationInputs(ctx context.Context, stage worker.Stage) (worker.PublicationInputs, error) {
	e, err := p.ensure(ctx, stage)
	if err != nil {
		return worker.PublicationInputs{}, err
	}
	return e.pipeline.PublicationInputs(ctx, stage)
}

func selectedRequest(selection model.Selection) bool {
	return selection.UpdateID == source.SelectedUpdateID && selection.Architecture == "amd64" && selection.Language == "en-gb" && len(selection.Editions) == 1 && strings.EqualFold(selection.Editions[0], "Professional")
}
