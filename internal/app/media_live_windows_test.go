package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"uupbuilder/internal/config"
	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
)

func TestLiveAppProjection(t *testing.T) {
	if os.Getenv("UUP_GENERIC_MEDIA_CACHE") == "" {
		t.Skip("live source inspection is opt-in")
	}
	path, err := config.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	selection, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	apps := source.NewAppCatalog(cfg.Catalog.Endpoint)
	snapshot, err := apps.Load(ctx, selection)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := apps.SelectedDocuments(ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := source.SelectedAppPayloads(ctx, snapshot, docs, settings.Apps.Include)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("requested %d features selected %d payloads from %d neutral payloads", len(settings.Apps.Include), len(selected), len(snapshot.AppManifest.Payloads))
	for _, id := range settings.Apps.Include {
		for _, entry := range snapshot.Entries {
			if strings.EqualFold(id, entry.FeatureID) {
				t.Logf("%s: %d media declarations; dependencies=%v", id, len(entry.Media), entry.Dependencies)
			}
		}
	}
	for _, p := range selected {
		if strings.Contains(p.Destination, "WebExperience") || strings.Contains(p.Destination, "SnippingTool") {
			t.Logf("unexpected app selected: %s", p.Destination)
		}
	}
}

// Reuses private observations only to diagnose app planning independently of
// native completion. This cannot authorize a build or stand in for ReadyPlan.
func TestLiveAppPlanSnapshot(t *testing.T) {
	if os.Getenv("UUP_GENERIC_MEDIA_CACHE") == "" {
		t.Skip("retained source observations are opt-in")
	}
	body, err := os.ReadFile(filepath.Join("..", "..", ".superpowers", "live-media-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct{ Inventory metadata.Inventory }
	if err = json.Unmarshal(body, &snapshot); err != nil {
		t.Fatal(err)
	}
	path, err := config.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	selection, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	if selection.UpdateID != snapshot.Inventory.Source.UpdateID || selection.Language != snapshot.Inventory.Source.Language || selection.Architecture != snapshot.Inventory.Source.Architecture {
		t.Fatal("diagnostic observations differ from the requested source")
	}
	plan, err := planner.PlanApps(snapshot.Inventory, settings.Apps)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Deferred {
		t.Fatal("source app planning still requires unexamined metadata")
	}
	t.Logf("requested %d app IDs; %d effective IDs; %d provisioning operations", len(settings.Apps.Include), len(plan.EffectiveIDs), len(plan.Provision))
}

// Explicit opt-in inspects the user's exact source with original retained cache
// bytes. It never mounts/services an image or creates/publishes an ISO.
func TestLiveGenericMediaPlan(t *testing.T) {
	root := os.Getenv("UUP_GENERIC_MEDIA_CACHE")
	if root == "" {
		t.Skip("set UUP_GENERIC_MEDIA_CACHE to retained verified source bytes")
	}
	path, err := config.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	selection, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	env, err := newSelectedEnvironment(ctx, settings, cfg.Catalog.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	// This explicit diagnostic run keeps newly verified payloads for subsequent
	// inspection attempts even when semantic inspection reports a real gap.
	env.source.retainDownloads = settings.Storage.KeepDownloads
	defer func() {
		if err := env.Close(); err != nil {
			t.Error(err)
		}
	}()
	retained := retainedMediaFetcher{live: env.source, root: root, files: map[model.PayloadIdentity]download.CachedFile{}}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var record struct {
			Identity model.PayloadIdentity `json:"identity"`
			SHA256   string                `json:"sha256"`
		}
		if json.Unmarshal(body, &record) != nil || record.Identity.Validate() != nil || record.SHA256 == "" {
			continue
		}
		dataPath := filepath.Join(root, record.Identity.Key()+".data")
		info, err := os.Stat(dataPath)
		if err == nil && info.Mode().IsRegular() && info.Size() == record.Identity.Size {
			retained.files[record.Identity] = download.CachedFile{Identity: record.Identity, Path: dataPath, SHA256: record.SHA256}
		}
	}
	t.Logf("retained cache has %d candidate files; source inspectors independently reverify original payload digests", len(retained.files))
	resolution, err := source.ResolveMedia(ctx, env.catalog, source.NewAppCatalog(cfg.Catalog.Endpoint), &retained, selection, settings, nil, func(ctx context.Context, inv *metadata.Inventory, files download.Materialized) error {
		env.source.retainDownloads = settings.Storage.KeepDownloads
		t.Logf("native completion: %s %s, %d verified source payloads", inv.Source.UpdateID, inv.Source.BuildLabel, len(inv.Manifest.Payloads))
		if err := env.acquireRuntime(ctx); err != nil {
			return err
		}
		completionErr := (&source.NativeInspector{WIMLib: env.runtime.WIMLib(), Workspace: env.native}).Complete(ctx, inv, files)
		// Preserve source-bound observations privately for focused diagnosis. This
		// diagnostic snapshot is never a native authorization or a ReadyPlan.
		snapshot := struct {
			Inventory       metadata.Inventory
			CompletionError string
		}{Inventory: *inv}
		if completionErr != nil {
			snapshot.CompletionError = completionErr.Error()
		}
		if body, err := json.Marshal(snapshot); err == nil {
			artifactRoot := filepath.Join("..", "..", ".superpowers")
			if err := os.MkdirAll(artifactRoot, 0700); err == nil {
				if err := os.WriteFile(filepath.Join(artifactRoot, "live-media-inventory.json"), body, 0600); err != nil {
					t.Logf("private diagnostic snapshot: %v", err)
				}
			}
		}
		return completionErr
	})
	if err != nil {
		t.Fatal(err)
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base, err := config.DefaultDirectory()
	if err != nil {
		t.Fatal(err)
	}
	p := planner.Planner{ManagedSelected: true, InspectStorage: inspectBuildStorage, DefaultWorkspace: base, DefaultCache: base}
	plan, err := p.Resolve(ctx, planner.Request{Selection: selection, Settings: settings, Resolution: resolution, Host: host, DraftRevision: 1, Intent: planner.BuildMedia})
	if err != nil {
		t.Fatal(err)
	}
	if err = plan.Validate(); err != nil {
		t.Fatal(err)
	}
	t.Logf("exact source ReadyPlan %s; %d operations; no native servicing or ISO build executed", plan.Digest(), len(plan.Operations()))
}

type retainedMediaFetcher struct {
	live  *sourcePreparation
	root  string
	files map[model.PayloadIdentity]download.CachedFile
}

func (f *retainedMediaFetcher) Fetch(ctx context.Context, m model.PayloadManifest, locators model.Locators, emit model.Emit) (download.Materialized, error) {
	out := download.Materialized{}
	for _, p := range m.Payloads {
		file, err := f.FetchOne(ctx, p, locators[p.Identity], emit)
		if err != nil {
			return nil, err
		}
		out[p.Identity] = file
	}
	return out, nil
}
func (f *retainedMediaFetcher) FetchOne(ctx context.Context, p model.Payload, locator download.Locator, emit model.Emit) (download.CachedFile, error) {
	if err := ctx.Err(); err != nil {
		return download.CachedFile{}, err
	}
	if file, ok := f.files[p.Identity]; ok {
		return file, nil
	}
	// A concurrently finishing retained download is reusable only after the
	// manager has atomically published both its identity record and data file.
	var record struct {
		Identity model.PayloadIdentity `json:"identity"`
		SHA256   string                `json:"sha256"`
	}
	if body, err := os.ReadFile(filepath.Join(f.root, p.Identity.Key()+".json")); err == nil && json.Unmarshal(body, &record) == nil && record.Identity == p.Identity && record.SHA256 != "" {
		dataPath := filepath.Join(f.root, p.Identity.Key()+".data")
		if info, err := os.Stat(dataPath); err == nil && info.Mode().IsRegular() && info.Size() == p.Identity.Size {
			file := download.CachedFile{Identity: p.Identity, Path: dataPath, SHA256: record.SHA256}
			f.files[p.Identity] = file
			return file, nil
		}
	}
	file, err := f.live.FetchOne(ctx, p, locator, emit)
	if err == nil {
		f.files[p.Identity] = file
	}
	return file, err
}
