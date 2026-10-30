package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"uupbuilder/internal/model"
	"uupbuilder/internal/tui"
)

func TestReviewToolCheckDoesNotResolveSourceOrCreateWorkspaces(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "source must not be contacted before Start", 500)
	}))
	defer srv.Close()
	cfg := preflightConfig(t, srv.URL)
	service := defaultBuild(t, cfg)
	checker, ok := service.(tui.BuildToolChecker)
	if !ok {
		t.Fatal("production builder has no read-only tool check")
	}
	list, err := checker.CheckTools(context.Background(), tui.BuildDraft{Config: cfg, Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("tool check contacted source catalogue")
	}
	for _, root := range []string{cfg.Storage.Workspace, cfg.Storage.Cache, cfg.Output.Directory} {
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatalf("tool check wrote to %s: %v", root, err)
		}
	}
	if service.(*buildService).selected != nil {
		t.Fatal("tool check acquired runtime")
	}
	text := strings.Join(list, "\n")
	for _, name := range []string{"DISM", "wimlib", "after Start"} {
		if !strings.Contains(text, name) {
			t.Fatalf("missing tool disclosure %q: %s", name, text)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := checker.CheckTools(ctx, tui.BuildDraft{Config: cfg}); err == nil {
		t.Fatal("cancelled tool check succeeded")
	}
}

func TestInteractiveBuilderProvidesPreparationAndExecutionEvents(t *testing.T) {
	cfg := preflightConfig(t, "http://127.0.0.1:1")
	if _, ok := defaultBuild(t, cfg).(tui.EventBuildService); !ok {
		t.Fatal("preparation and execution have no progress event path")
	}
}

func TestConfirmedPreparationStreamsActualDownloadEvents(t *testing.T) {
	body := preflightWIM("9")
	sum := sha256.Sum256(body)
	var origin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/get.php" {
			json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{"build": "28000.1", "arch": "amd64", "files": map[string]any{"professional_en-us.esd": map[string]any{"sha256": hex.EncodeToString(sum[:]), "size": len(body), "expire": 0, "url": origin + "/payload"}}}})
			return
		}
		if r.URL.Path == "/payload" {
			w.Write(body)
			return
		}
		http.Error(w, "unexpected route", 400)
	}))
	defer srv.Close()
	origin = srv.URL
	cfg := preflightConfig(t, origin)
	service := defaultBuild(t, cfg).(tui.EventBuildService)
	var mu sync.Mutex
	var events []model.Event
	_, err := service.PrepareWithEvents(context.Background(), tui.BuildDraft{Config: cfg, Revision: 1}, func(e model.Event) { mu.Lock(); events = append(events, e); mu.Unlock() })
	if err == nil {
		t.Fatal("incomplete source fixture unexpectedly became ready")
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, e := range events {
		found = found || e.Kind == model.EventBytes || strings.Contains(strings.ToLower(e.Message), "download")
	}
	if !found {
		t.Fatalf("actual download produced no progress events: %+v", events)
	}
}

func TestToolAvailabilityReportsMissingInboxFileWithoutLaunchingIt(t *testing.T) {
	root := t.TempDir()
	if _, err := availableBuildTools(context.Background(), root); err == nil || !strings.Contains(err.Error(), "expand.exe") {
		t.Fatalf("missing extractor not reported: %v", err)
	}
	for _, name := range []string{"expand.exe", "WindowsPowerShell/v1.0/powershell.exe", "imapi2fs.dll"} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("intentionally not an executable"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := availableBuildTools(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := availableBuildTools(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
