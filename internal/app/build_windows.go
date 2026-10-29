package app

import (
	"context"
	"fmt"
	"os"

	"uupbuilder/internal/catalog"
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

func (s *buildService) Close(ctx context.Context) error { return s.controller.Close(ctx) }

// All stage registrations are composed here for both the normal application
// and private worker. U06-U10 provide real producers; absence stays a blocker.
func operationRegistry() *worker.Registry { return worker.NewRegistry() }
func runPrivateWorker(ctx context.Context, args []string) (bool, error) {
	if len(args) == 0 || args[0] != "--uup-worker" {
		return false, nil
	}
	return true, worker.Entry(ctx, args, operationRegistry())
}
func (s *buildService) Prepare(ctx context.Context, draft tui.BuildDraft) (planner.ReadyPlan, error) {
	selection, settings, err := draft.Config.Request()
	if err != nil {
		return planner.ReadyPlan{}, err
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		return planner.ReadyPlan{}, fmt.Errorf("host discovery: %w", err)
	}
	resolver := source.Resolver{Catalog: catalog.New(nil, draft.Config.Catalog.Endpoint)}
	resolution, err := resolver.Resolve(ctx, selection, settings)
	if err != nil {
		return planner.ReadyPlan{}, err
	}
	return s.planner.Resolve(ctx, planner.Request{Selection: selection, Settings: settings, Resolution: resolution, Host: host, DraftRevision: draft.Revision, Intent: planner.BuildMedia})
}
func (s *buildService) Execute(ctx context.Context, plan planner.ReadyPlan) (tui.BuildResult, error) {
	view, err := s.controller.Start(ctx, plan)
	if err != nil {
		return tui.BuildResult{}, err
	}
	view, err = s.controller.Wait(ctx, view.ID)
	return tui.BuildResult{JobID: view.ID, State: string(view.State), Error: view.Error, Artifacts: view.Artifacts}, err
}
