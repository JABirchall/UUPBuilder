package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/providers"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
)

// Explicit opt-in: one exact latest-source metadata projection, never the full
// selected payload or APP closure. This records observations, not authority.
func TestLiveLatestSemanticPreparation(t *testing.T) {
	root := os.Getenv("UUP_LIVE_LATEST_SEMANTIC_ROOT")
	if root == "" {
		t.Skip("latest-source semantic check not configured")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute private artifact root required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	selection := model.Selection{UpdateID: preflightSourceID, Architecture: "amd64", Language: "en-us", Editions: []string{"Professional"}}
	owner := &sourcePreparation{inspect: inspectBuildStorage}
	var err error
	owner.cache, err = platform.CreateWorkspace(root, "latest-semantic-cache")
	if err != nil {
		t.Fatal(err)
	}
	owner.cacheReady = true
	defer func() {
		if err := owner.Close(); err != nil {
			t.Errorf("latest-source cleanup: %v", err)
		}
	}()
	owner.job, err = platform.CreateWorkspace(root, "latest-semantic-download")
	if err != nil {
		t.Fatal(err)
	}
	owner.jobReady = true
	proxy := model.ProxySettings{Mode: model.ProxySystem}
	owner.transport, err = download.NewTransport(proxy)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &source.Resolver{Catalog: catalog.New(&http.Client{Transport: owner.transport}, "")}
	owner.manager, err = NewSourceManager(download.Options{Cache: owner.cache, Job: owner.job, Transport: owner.transport, ParallelFiles: 4, Retries: 5, Proxy: proxy}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := resolver.Discover(ctx, selection)
	if err != nil {
		t.Fatalf("live exact-source metadata discovery: %v", err)
	}
	if len(plan.Inputs) != 1 || len(plan.Sets) != 1 || len(plan.Sets[0].Query.Projection) != 1 {
		t.Fatal("live discovery broadened metadata projection")
	}
	manifest, locators, err := source.Union(plan.Source, []catalog.FileSet{plan.Sets[0].Files}, plan.Sets[0].Query)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Payloads) != 1 || manifest.Payloads[0].Identity.Size > metadata.MaxMetadataCABBytes {
		t.Fatal("live check requires existing bounded aggregated metadata input")
	}
	files, err := owner.Fetch(ctx, manifest, locators, nil)
	if err != nil {
		t.Fatalf("live projected publisher verification: %v", err)
	}
	input := plan.Inputs[0]
	file := files[input.Identity]
	inv, inspectErr := metadata.Inspect(ctx, metadata.InspectRequest{Source: plan.Source, Manifest: manifest, Inspections: []metadata.Inspection{{Resource: metadata.LocalResource{Identity: file.Identity, Path: file.Path}, Provider: input.Provider}}})
	receipt := struct {
		CheckedUTC      time.Time
		Selection       model.Selection
		Manifest        model.PayloadManifest
		File            download.CachedFile
		Inventory       metadata.Inventory
		InspectionError string
		Scope           string
	}{CheckedUTC: time.Now().UTC(), Selection: selection, Manifest: manifest, File: file, Inventory: inv, Scope: "One official catalogue/CDN semantic metadata input, fully publisher-verified; no media capability, native image operation or ReadyPlan. Owned materialization removed after inspection."}
	if inspectErr != nil {
		receipt.InspectionError = inspectErr.Error()
	}
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "latest-semantic-observation.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("live source=%s build=%s target=amd64/en-us/Professional input=%s size=%d publisher=%s:%s computed-sha256=%s manifest=%s documents=%d compositions=%d gaps=%d classification=%s inspection=%v", selection.UpdateID, plan.Source.BuildLabel, manifest.Payloads[0].Destination, file.Identity.Size, file.Identity.Digest.Algorithm, file.Identity.Digest.Value, file.SHA256, manifest.Digest, len(inv.Documents), len(inv.Compositions), len(inv.Gaps), inv.Classification, inspectErr)
	if inspectErr != nil && !errors.Is(inspectErr, providers.ErrUnsupported) && !errors.Is(inspectErr, metadata.ErrLimit) && !errors.Is(inspectErr, source.ErrImplementationGap) {
		t.Fatalf("live semantic inspection failed: %v", inspectErr)
	}
}
