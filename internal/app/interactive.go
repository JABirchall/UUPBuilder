package app

import (
	"context"
	"errors"
	"time"

	tea "charm.land/bubbletea/v2"

	"uupbuilder/internal/config"
	"uupbuilder/internal/tui"
)

// Options supplies the loaded configuration and discovery dependencies for a Workspace.
type Options struct {
	ConfigPath   string
	Config       config.Config
	Dependencies tui.Dependencies
}

// RunInteractive opens the Workspace and runs its Bubble Tea event loop.
func RunInteractive(ctx context.Context, opts Options) error {
	return runInteractive(ctx, opts)
}

func runInteractive(ctx context.Context, opts Options, programOptions ...tea.ProgramOption) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	opts.Dependencies.Context = ctx
	opts.Dependencies.ConfigPath = opts.ConfigPath
	composeInteractiveApps(&opts)
	closeBuild, err := composeInteractiveBuild(&opts)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, closeBuild()) }()
	workspace := tui.New(opts.Dependencies, opts.Config)
	defer workspace.Close()
	programOptions = append(programOptions, tea.WithContext(ctx), tea.WithoutSignalHandler())
	_, err = tea.NewProgram(workspace, programOptions...).Run()
	return err
}

// Build services that own a controller retain responsibility for its active
// resources after the UI context has been cancelled. Preserve their teardown
// result alongside any event-loop error, using an independent bounded context.
func closeBuildService(service tui.BuildService) func() error {
	closer, ok := service.(interface{ Close(context.Context) error })
	if !ok {
		return func() error { return nil }
	}
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return closer.Close(ctx)
	}
}
