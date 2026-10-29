package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
	"uupbuilder/internal/download"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
	"uupbuilder/internal/worker"
)

// Exercise the actual downloader, composed registry and transaction together.
// Closing the origin proves that a verified reusable cache does not need links.
func TestRegisteredPreparationUsesVerifiedCacheWithoutNetwork(t *testing.T) {
	ctx := context.Background()
	body := []byte("prepared through actual download manager")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	p := model.Payload{Destination: "payload.esd", Identity: model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: digest}, Size: int64(len(body)), Provenance: model.PackageProvenance{Source: "synthetic-source", Name: "payload.esd"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer srv.Close()
	cache, err := platform.CreateWorkspace(t.TempDir(), "prep-cache")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	job, err := platform.CreateWorkspace(t.TempDir(), "prep-download")
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()
	r := &source.Resolver{Catalog: catalog.New(srv.Client(), srv.URL)}
	m, err := NewSourceManager(download.Options{Cache: cache, Job: job, Proxy: model.ProxySettings{Mode: model.ProxyDirect}}, r)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.FetchOne(ctx, p, model.Locator{URL: srv.URL}, nil); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.Image.UpdateID = "prep-revision"
	cfg.Storage.Workspace = root
	cfg.Storage.Cache = root
	cfg.Output.Directory = root
	sel, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: sel.UpdateID, BuildLabel: "fixture", Architecture: sel.Architecture, Language: sel.Language}, []model.Payload{p})
	if err != nil {
		t.Fatal(err)
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := (&planner.Planner{InspectStorage: inspectBuildStorage}).Resolve(ctx, planner.Request{Selection: sel, Settings: settings, Resolution: source.Resolution{Selection: sel, Settings: settings, Manifest: manifest}, Host: host, Intent: planner.DownloadOnly})
	if err != nil {
		t.Fatal(err)
	}
	inspector := &shutdownMounts{}
	inspector.complete.Store(true)
	store, err := jobstore.Create(root, "composed-preparation", inspector)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registry := worker.NewRegistry()
	if err := RegisterSourcePreparation(registry, m, r, nil); err != nil {
		t.Fatal(err)
	}
	peer, err := platform.CurrentPeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	d := platform.WorkerDescriptor{Version: 1, JobID: store.Identity().JobID, PlanDigest: plan.Digest(), Workspace: store.Identity()}
	session, err := worker.NewSession(plan, d, peer, peer, store, registry)
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.Dispatch(ctx, peer, worker.RequestFor(d, plan.Intent(), string(planner.DownloadPayloads)))
	if err != nil || len(result.Outputs) != 2 {
		t.Fatalf("composed preparation did not produce real inputs: %+v %v", result, err)
	}
	live, err := store.InspectRecovery(ctx, d.JobID)
	if err != nil || len(live.Checkpoints) != 1 || !live.Checkpoints[0].Valid {
		t.Fatalf("composed checkpoint: %+v %v", live, err)
	}
}
