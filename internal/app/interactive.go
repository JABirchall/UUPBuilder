package app

import (
	"context"

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

func runInteractive(ctx context.Context, opts Options, programOptions ...tea.ProgramOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	opts.Dependencies.Context = ctx
	opts.Dependencies.ConfigPath = opts.ConfigPath
	workspace := tui.New(opts.Dependencies, opts.Config)
	defer workspace.Close()
	programOptions = append(programOptions, tea.WithContext(ctx), tea.WithoutSignalHandler())
	_, err := tea.NewProgram(workspace, programOptions...).Run()
	return err
}
