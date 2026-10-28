package app

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
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
	if err := Run(context.Background(), []string{"--config=" + path}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing explicit config: %v", err)
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
	t.Setenv("LOCALAPPDATA", "")
	if err := Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "LOCALAPPDATA") {
		t.Fatalf("missing default config location: %v", err)
	}
}

func TestEntryLaunchesWorkspaceWithLoadedConfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "配置 with spaces.toml")
	data := []byte(`schema_version = 1
[image]
update_id = "11111111-1111-1111-1111-111111111111_rev.7"
architecture = "arm64"
language = "en-gb"
editions = ["professional", "enterprise"]
[conversion.drivers]
enabled = true
source = "drivers"
targets = ["os"]
[output]
directory = "output"
[storage]
workspace = "scratch"
cache = "cache"
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	launchCalls := 0
	ctx := context.WithValue(context.Background(), struct{}{}, "startup")
	err := run(ctx, []string{"--config", path}, func(gotCtx context.Context, opts Options) error {
		launchCalls++
		if gotCtx != ctx || opts.ConfigPath != path {
			t.Errorf("launch context/path = %v, %q", gotCtx, opts.ConfigPath)
		}
		cfg := opts.Config
		if cfg.Image.UpdateID != "11111111-1111-1111-1111-111111111111_rev.7" || cfg.Image.Architecture != "arm64" || cfg.Image.Language != "en-gb" || !reflect.DeepEqual(cfg.Image.Editions, []string{"professional", "enterprise"}) {
			t.Errorf("loaded image selection = %+v", cfg.Image)
		}
		if cfg.Conversion.Drivers.Source != filepath.Join(root, "drivers") || cfg.Output.Directory != filepath.Join(root, "output") || cfg.Storage.Workspace != filepath.Join(root, "scratch") || cfg.Storage.Cache != filepath.Join(root, "cache") {
			t.Errorf("loaded paths = %+v, %+v, %+v", cfg.Conversion.Drivers, cfg.Output, cfg.Storage)
		}
		return nil
	})
	if err != nil || launchCalls != 1 {
		t.Fatalf("startup = %v; launchCalls = %d, want 1", err, launchCalls)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("startup rewrote configuration: %q, %v", got, err)
	}
}

func TestMissingDefaultConfigUsesBrowsingDefaultsWithoutSaving(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	launchCalls := 0
	err := run(context.Background(), nil, func(_ context.Context, opts Options) error {
		launchCalls++
		if opts.ConfigPath != filepath.Join(root, "UUPBuilder", "config.toml") || opts.Config.Output.Directory != filepath.Join(root, "UUPBuilder") {
			t.Errorf("default paths = %q, %q", opts.ConfigPath, opts.Config.Output.Directory)
		}
		cfg := opts.Config
		if err := cfg.Validate(); err != nil || cfg.Image.UpdateID != "" || cfg.Downloads.ParallelFiles != 4 || cfg.Downloads.Retries != 5 || cfg.Output.SplitSizeMiB != 3800 || cfg.Storage.Workspace != "auto" || cfg.Storage.Cache != "auto" {
			t.Errorf("invalid browsing defaults: %+v, %v", cfg, err)
		}
		return nil
	})
	if err != nil || launchCalls != 1 {
		t.Fatalf("first run = %v; launchCalls = %d, want 1", err, launchCalls)
	}
	writes := 0
	if err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err == nil && path != root {
			writes++
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatalf("first run created %d files/directories; want writes == 0", writes)
	}
}

func TestExplicitMissingConfigReturnsUsefulError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "config.toml")
	launchCalls := 0
	err := run(context.Background(), []string{"--config=" + path}, func(context.Context, Options) error {
		launchCalls++
		return nil
	})
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), path) || launchCalls != 0 {
		t.Fatalf("missing config = %v; launchCalls = %d", err, launchCalls)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing config created directories: %v", err)
	}
}

func TestMalformedConfigNeverLaunchesOrOverwrites(t *testing.T) {
	for _, data := range []string{"schema_version = [", "schema_version = 1\nunknown_key = true", "schema_version = 2"} {
		t.Run(data, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("LOCALAPPDATA", root)
			if err := os.Mkdir(filepath.Join(root, "UUPBuilder"), 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "UUPBuilder", "config.toml")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{nil, {"--config", path}} {
				launchCalls := 0
				err := run(context.Background(), args, func(context.Context, Options) error {
					launchCalls++
					return nil
				})
				if err == nil || !strings.Contains(err.Error(), path) || launchCalls != 0 {
					t.Fatalf("malformed config = %v; launchCalls = %d", err, launchCalls)
				}
				got, err := os.ReadFile(path)
				if err != nil || string(got) != data {
					t.Fatalf("malformed config was overwritten: %q, %v", got, err)
				}
				entries, err := os.ReadDir(filepath.Dir(path))
				if err != nil || len(entries) != 1 {
					t.Fatalf("malformed config created files: %v, %v", entries, err)
				}
			}
		})
	}
}

func TestEntryReturnsLaunchError(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	want := errors.New("terminal unavailable")
	if err := run(context.Background(), nil, func(context.Context, Options) error { return want }); !errors.Is(err, want) {
		t.Fatalf("launch error = %v, want %v", err, want)
	}
}

func TestEntryHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, []string{"--config", "config.toml"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
