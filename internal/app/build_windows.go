package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/download"
	"uupbuilder/internal/jobs"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
	"uupbuilder/internal/tui"
	"uupbuilder/internal/worker"
)

type buildService struct {
	planner    *planner.Planner
	controller *jobs.Controller
	mu         sync.Mutex
	closed     bool
	active     *buildPreparation
	cleanupErr error
	preserved  []*sourcePreparation
}

type buildPreparation struct {
	cancel    context.CancelFunc
	done      chan struct{}
	resources []string
}

func (s *buildService) ownWorkspace(w *platform.Workspace) {
	if w == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active.resources = append(s.active.resources, fmt.Sprintf("%s [job=%s]", w.Path(), w.Identity().JobID))
}

func inspectBuildStorage(ctx context.Context, path string) (planner.Volume, error) {
	if err := ctx.Err(); err != nil {
		return planner.Volume{}, err
	}
	v, err := platform.InspectStorage(path)
	return planner.Volume{Path: v.Path, ID: v.ID, FileSystem: v.Capabilities, AvailableBytes: v.AvailableBytes, MaxFileBytes: v.MaxFileBytes}, err
}
func composeInteractiveBuild(opts *Options) func() error {
	if opts.Dependencies.Builder != nil {
		return closeBuildService(opts.Dependencies.Builder)
	}
	base, _ := os.UserCacheDir()
	p := &planner.Planner{InspectStorage: inspectBuildStorage, DefaultWorkspace: base, DefaultCache: base}
	controller := jobs.NewController(jobs.Options{Registry: operationRegistry(), InspectStorage: inspectBuildStorage})
	opts.Dependencies.Builder = &buildService{planner: p, controller: controller}
	return closeBuildService(opts.Dependencies.Builder)
}

func (s *buildService) begin(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, planner.ErrInvalidPlan
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, os.ErrClosed
	}
	if s.cleanupErr != nil {
		return nil, nil, s.cleanupErr
	}
	if s.active != nil {
		return nil, nil, jobs.ErrBusy
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	owned, cancel := context.WithCancel(ctx)
	a := &buildPreparation{cancel: cancel, done: make(chan struct{})}
	s.active = a
	return owned, func() {
		cancel()
		s.mu.Lock()
		s.active = nil
		close(a.done)
		s.mu.Unlock()
	}, nil
}

func (s *buildService) Close(ctx context.Context) error {
	if ctx == nil {
		return planner.ErrInvalidPlan
	}
	s.mu.Lock()
	s.closed = true
	a := s.active
	if a != nil {
		a.cancel()
	}
	s.mu.Unlock()
	if a != nil {
		select {
		case <-a.done:
		case <-ctx.Done():
			s.mu.Lock()
			defer s.mu.Unlock()
			return errors.Join(fmt.Errorf("preparation has not quiesced; resources still owned %v: %w", a.resources, ctx.Err()), s.cleanupErr)
		}
	}
	// No new Prepare/Execute can begin after closed. Wait for preflight's
	// catalogue, downloader, parsers and cleanup before closing job resources.
	err := s.controller.Close(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	return errors.Join(err, s.cleanupErr)
}

// All stage registrations are composed here for both the normal application
// and private worker. U06-U10 provide real producers; absence stays a blocker.
func operationRegistry() *worker.Registry {
	registry := worker.NewRegistry()
	// U08's native handler is fixed here. Until U07 supplies inspected mutable
	// images and a verified runtime provider, invocation reports that exact gap.
	if err := registry.Register(planner.ServiceImage, worker.ServicingHandler(nil, nil, nil)); err != nil {
		panic(err)
	}
	if err := registry.Register(planner.InspectApps, worker.AppInspectionHandler(nil)); err != nil {
		panic(err)
	}
	if err := registry.Register(planner.CustomizeImage, worker.CustomizationHandler(nil, nil, nil)); err != nil {
		panic(err)
	}
	return registry
}
func runPrivateWorker(ctx context.Context, args []string) (bool, error) {
	if len(args) == 0 || args[0] != "--uup-worker" {
		return false, nil
	}
	return true, worker.Entry(ctx, args, operationRegistry())
}
func (s *buildService) Prepare(ctx context.Context, draft tui.BuildDraft) (ready planner.ReadyPlan, resultErr error) {
	ctx, finish, err := s.begin(ctx)
	if err != nil {
		return ready, err
	}
	defer finish()
	selection, settings, err := draft.Config.Request()
	if err != nil {
		return planner.ReadyPlan{}, err
	}
	if err := planner.ValidateRequestedSettings(settings); err != nil {
		return ready, err
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		return planner.ReadyPlan{}, fmt.Errorf("host discovery: %w", err)
	}
	owner := &sourcePreparation{inspect: s.planner.InspectStorage}
	defer func() {
		if err := owner.Close(); err != nil {
			resultErr = errors.Join(resultErr, err)
			ready = planner.ReadyPlan{}
			s.mu.Lock()
			s.cleanupErr = errors.Join(s.cleanupErr, err)
			s.preserved = append(s.preserved, owner)
			s.mu.Unlock()
		}
	}()
	workspace, cache := settings.Storage.Workspace, settings.Storage.Cache
	if workspace == "auto" {
		workspace = s.planner.DefaultWorkspace
	}
	if cache == "auto" {
		cache = s.planner.DefaultCache
	}
	owner.cache, err = platform.CreateWorkspace(cache, "source-preflight-cache")
	s.ownWorkspace(owner.cache)
	if err != nil {
		return ready, fmt.Errorf("create semantic cache: %w", err)
	}
	owner.cacheReady = true
	owner.job, err = platform.CreateWorkspace(workspace, "source-preflight-download")
	s.ownWorkspace(owner.job)
	if err != nil {
		return ready, fmt.Errorf("create semantic download workspace: %w", err)
	}
	owner.jobReady = true
	owner.transport, err = download.NewTransport(settings.Downloads.Proxy)
	if err != nil {
		return ready, err
	}
	resolver := source.Resolver{Catalog: catalog.New(&http.Client{Transport: owner.transport}, draft.Config.Catalog.Endpoint)}
	owner.manager, err = NewSourceManager(download.Options{Cache: owner.cache, Job: owner.job, Transport: owner.transport, ParallelFiles: settings.Downloads.ParallelFiles, Retries: settings.Downloads.Retries, Proxy: settings.Downloads.Proxy}, &resolver)
	if err != nil {
		return ready, err
	}
	resolver.Fetcher = owner
	resolution, err := resolver.Resolve(ctx, selection, settings)
	if err != nil {
		return planner.ReadyPlan{}, err
	}
	return s.planner.Resolve(ctx, planner.Request{Selection: selection, Settings: settings, Resolution: resolution, Host: host, DraftRevision: draft.Revision, Intent: planner.BuildMedia})
}
func (s *buildService) Execute(ctx context.Context, plan planner.ReadyPlan) (tui.BuildResult, error) {
	ctx, finish, err := s.begin(ctx)
	if err != nil {
		return tui.BuildResult{}, err
	}
	defer finish()
	view, err := s.controller.Start(ctx, plan)
	if err != nil {
		return tui.BuildResult{}, err
	}
	view, err = s.controller.Wait(ctx, view.ID)
	return tui.BuildResult{JobID: view.ID, State: string(view.State), Error: view.Error, Artifacts: view.Artifacts}, err
}
