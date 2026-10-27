package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Run currently establishes only the cancellable argument/config-path entry
// boundary. Config loading and UI initialization are wired by their owners.
// It performs no downloads, configuration writes, helper calls or conversions.
func Run(ctx context.Context, args []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := configPath(args); err != nil {
		return fmt.Errorf("initialize UUP Builder: %w", err)
	}
	return ctx.Err()
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
		base := os.Getenv("LOCALAPPDATA")
		if strings.TrimSpace(base) == "" {
			return "", errors.New("LOCALAPPDATA is unavailable; specify --config PATH")
		}
		path = filepath.Join(base, "UUPBuilder", "config.toml")
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
