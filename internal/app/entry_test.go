package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEntryRejectsUnknownArgument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-created", "config.toml")
	err := Run(context.Background(), []string{"--config", path, "--unknown"})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected useful unknown-argument error, got %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("argument validation started filesystem work: %v", err)
	}
}

func TestEntryConfigPathBoundary(t *testing.T) {
	for _, args := range [][]string{{"--config"}, {"--config="}, {"--config", "a", "--config", "b"}, {"extra"}} {
		if err := Run(context.Background(), args); err == nil {
			t.Fatalf("accepted invalid arguments %q", args)
		}
	}
	path := filepath.Join(t.TempDir(), "folder with spaces", "配置.toml")
	if err := Run(context.Background(), []string{"--config=" + path}); err != nil {
		t.Fatalf("valid explicit config path: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry created configuration files: %v", err)
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	wantDefault := filepath.Join(os.Getenv("LOCALAPPDATA"), "UUPBuilder", "config.toml")
	if got, err := configPath(nil); err != nil || got != wantDefault {
		t.Fatalf("default path = %q, %v; want %q", got, err, wantDefault)
	}
	wantRelative, err := filepath.Abs("relative/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := configPath([]string{"--config", "relative/config.toml"}); err != nil || got != wantRelative {
		t.Fatalf("relative path = %q, %v; want %q", got, err, wantRelative)
	}
	if err := Run(context.Background(), nil); err != nil {
		t.Fatalf("default config path: %v", err)
	}
	t.Setenv("LOCALAPPDATA", "")
	if err := Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "LOCALAPPDATA") {
		t.Fatalf("missing default config location: %v", err)
	}
}

func TestEntryHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, []string{"--config", "config.toml"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
