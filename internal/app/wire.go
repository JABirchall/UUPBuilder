package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"uupbuilder/internal/config"
)

// Run validates arguments, loads an existing configuration or first-run browsing
// defaults, and launches the Workspace. Startup never saves the configuration.
func Run(ctx context.Context, args []string) error {
	if handled, err := runPrivateWorker(ctx, args); handled {
		return err
	}
	if handled, err := runHeadlessBuild(ctx, args); handled {
		return err
	}
	return run(ctx, args, RunInteractive)
}

func run(ctx context.Context, args []string, launch func(context.Context, Options) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := configPath(args)
	if err != nil {
		return fmt.Errorf("initialize UUP Builder: %w", err)
	}
	cfg, err := config.Load(path)
	// After argument validation, a nonempty argument list always denotes an
	// explicit --config. Only the implicit missing file permits browsing defaults.
	if len(args) == 0 && errors.Is(err, os.ErrNotExist) {
		cfg, err = config.ResolvePaths(config.Defaults(), path)
	}
	if err != nil {
		return fmt.Errorf("initialize UUP Builder: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return launch(ctx, Options{ConfigPath: path, Config: cfg})
}

func configPath(args []string) (string, error) {
	var path string
	seen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--config":
			if seen {
				return "", errors.New("--config may be supplied only once")
			}
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return "", errors.New("--config requires a path")
			}
			path, seen = args[i], true
		case strings.HasPrefix(arg, "--config="):
			if seen {
				return "", errors.New("--config may be supplied only once")
			}
			path, seen = strings.TrimPrefix(arg, "--config="), true
		default:
			return "", fmt.Errorf("unknown argument %q; usage: uupbuilder [--config PATH]", arg)
		}
	}
	if seen && strings.TrimSpace(path) == "" {
		return "", errors.New("--config requires a nonempty path")
	}
	if !seen {
		return config.DefaultPath()
	}
	if strings.ContainsRune(path, 0) {
		return "", errors.New("config path contains NUL")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve config path: %w", err)
	}
	return absolute, nil
}
