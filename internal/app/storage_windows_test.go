package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uupbuilder/internal/tui"
)

func TestAutomaticStorageIsPortableAndReviewDoesNotInitializeIt(t *testing.T) {
	if portableTestProcess(t) {
		return
	}
	cfg := preflightConfig(t, "http://127.0.0.1:1")
	cfg.Storage.Workspace, cfg.Storage.Cache = "auto", "auto"
	service := defaultBuild(t, cfg).(*buildService)
	want := portableDirectory(t)
	if service.planner.DefaultWorkspace != want || service.planner.DefaultCache != want {
		t.Fatalf("automatic roots = %q, %q; want %q", service.planner.DefaultWorkspace, service.planner.DefaultCache, want)
	}
	if _, err := service.CheckTools(context.Background(), tui.BuildDraft{Config: cfg}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(want); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("composition or Review initialized portable storage: %v", err)
	}
}

func TestSelectedEnvironmentInitializesPortableStorageAfterStart(t *testing.T) {
	if portableTestProcess(t) {
		return
	}
	cfg := preflightConfig(t, "http://127.0.0.1:1")
	cfg.Storage.Workspace, cfg.Storage.Cache = "auto", "auto"
	_, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	env, err := newSelectedEnvironment(context.Background(), settings, cfg.Catalog.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, path := range []string{env.source.cache.Path(), env.source.job.Path(), env.native.Path()} {
		requireWorkspaceParent(t, path, portableDirectory(t))
	}
	if _, err := os.Stat(filepath.Join(portableDirectory(t), "config.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Start saved configuration: %v", err)
	}
}

func TestSelectedEnvironmentHonorsExplicitRootsIncludingNativeScratch(t *testing.T) {
	if portableTestProcess(t) {
		return
	}
	cfg := preflightConfig(t, "http://127.0.0.1:1")
	_, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	env, err := newSelectedEnvironment(context.Background(), settings, cfg.Catalog.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Close(); err != nil {
			t.Error(err)
		}
	})
	requireWorkspaceParent(t, env.source.cache.Path(), cfg.Storage.Cache)
	requireWorkspaceParent(t, env.source.job.Path(), cfg.Storage.Workspace)
	requireWorkspaceParent(t, env.native.Path(), cfg.Storage.Workspace)
	if _, err := os.Stat(portableDirectory(t)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit storage initialized automatic directory: %v", err)
	}
}

func TestStartReportsUnusablePortableDirectoryWithoutFallback(t *testing.T) {
	if portableTestProcess(t) {
		return
	}
	want := portableDirectory(t)
	if err := os.WriteFile(want, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := preflightConfig(t, "http://127.0.0.1:1")
	cfg.Storage.Workspace, cfg.Storage.Cache = "auto", "auto"
	service := defaultBuild(t, cfg)
	_, err := service.Prepare(context.Background(), tui.BuildDraft{Config: cfg})
	if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "automatic storage") {
		t.Fatalf("unusable portable directory error = %v; want path and storage context", err)
	}
	entries, err := os.ReadDir(os.Getenv("LOCALAPPDATA"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("unusable portable directory fell back to AppData: %v, %v", entries, err)
	}
}

func requireWorkspaceParent(t *testing.T, path, want string) {
	t.Helper()
	actual, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.Stat(want)
	if err != nil {
		t.Fatalf("expected storage root %s: %v", want, err)
	}
	if !os.SameFile(actual, expected) {
		t.Fatalf("workspace %s is outside requested parent %s", path, want)
	}
}
