package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
)

// This explicit opt-in performs real acquisition only, in an existing private
// worktree directory. It never services/mounts images or installs a provider.
func TestLiveCanonicalPreparation(t *testing.T) {
	root := os.Getenv("UUP_LIVE_PREPARE_ROOT")
	if root == "" {
		t.Skip("real source acquisition not configured")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute acquisition root required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	c := catalog.New(nil, "")
	d := &source.Discovery{Catalog: c}
	r := &source.Resolver{Catalog: c, Discover: d.Metadata, DiscoverApps: d.Apps}
	cache, err := platform.CreateWorkspace(root, "u06-source-cache")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	job, err := platform.CreateWorkspace(root, "u06-source-download")
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()
	m, err := NewSourceManager(download.Options{Cache: cache, Job: job, ParallelFiles: 4, Retries: 5, Proxy: model.ProxySettings{Mode: model.ProxySystem}}, r)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := model.Selection{UpdateID: "3b507ad4-99b0-4630-b979-7c220b37a002", Architecture: "x86", Language: "en-us", Editions: []string{"professional"}}
	if id := os.Getenv("UUP_LIVE_SOURCE_ID"); id != "" {
		s.UpdateID = id
	}
	plan, err := d.Metadata(ctx, s)
	if err != nil && !errors.Is(err, source.ErrImplementationGap) {
		t.Fatalf("exact census metadata discovery failed (%T): %v", err, err)
	}
	if err == nil {
		manifest, locators, e := source.Union(plan.Source, []catalog.FileSet{plan.Sets[0].Files}, plan.Sets[0].Query)
		if e != nil {
			t.Fatal(e)
		}
		got, e := m.Fetch(ctx, manifest, locators, nil)
		if e != nil {
			t.Fatalf("exact metadata acquisition failed (%T)", e)
		}
		input := plan.Inputs[0]
		inv, e := metadata.Inspect(ctx, metadata.InspectRequest{Source: plan.Source, Manifest: manifest, Inspections: []metadata.Inspection{{Resource: metadata.LocalResource{Identity: input.Identity, Path: got[input.Identity].Path}, Provider: input.Provider}}})
		if e != nil {
			t.Fatalf("actual semantic metadata inspection failed (%T): %v", e, e)
		}
		t.Logf("actual source=%s build=%s target=x86 metadata=%s compositions=%d classification=%s gaps=%d", s.UpdateID, plan.Source.BuildLabel, got[input.Identity].SHA256, len(inv.Compositions), inv.Classification, len(inv.Gaps))
	} else {
		t.Logf("metadata adapter remains blocked: %v; continuing exact catalog acquisition only", err)
	}
	selected, err := c.Files(ctx, s.UpdateID, s.Language, "professional")
	if err != nil {
		t.Fatalf("exact selected source response failed (%T): %v", err, err)
	}
	query := model.SourceQuery{UpdateID: s.UpdateID, Language: s.Language, Edition: "professional"}
	selectedManifest, selectedLocators, err := source.Union(selected.Source, []catalog.FileSet{selected}, query)
	if err != nil {
		t.Fatal(err)
	}
	var bytes int64
	for _, p := range selectedManifest.Payloads {
		bytes += p.Identity.Size
		t.Logf("catalog payload: name=%s algorithm=%s digest=%s size=%d", p.Destination, p.Identity.Digest.Algorithm, p.Identity.Digest.Value, p.Identity.Size)
	}
	t.Logf("selected canonical candidate closure: payloads=%d bytes=%d manifest=%s", len(selectedManifest.Payloads), bytes, selectedManifest.Digest)
	data, err := json.MarshalIndent(selectedManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "selected-manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UUP_LIVE_PREPARE_PAYLOADS") != "1" {
		t.Log("payload-body acquisition not requested; full prepared closure remains unverified")
		return
	}
	files, err := m.Fetch(ctx, selectedManifest, selectedLocators, func(e model.Event) {
		if e.Kind == model.EventError {
			t.Logf("source transfer event: %s", e.Message)
		}
	})
	if err != nil {
		t.Fatalf("full selected acquisition failed (%T)", err)
	}
	type receipt struct {
		Manifest model.PayloadManifest
		Files    []download.CachedFile
	}
	report := receipt{Manifest: selectedManifest}
	for _, p := range selectedManifest.Payloads {
		report.Files = append(report.Files, files[p.Identity])
	}
	data, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "prepared-source.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual prepared payloads=%d bytes=%d; semantic base/reference/media closure and native operation proof remain separate", len(files), bytes)
}

func TestPreparedCanonicalInputsInspection(t *testing.T) {
	root := os.Getenv("UUP_PREPARED_SOURCE_ROOT")
	if root == "" {
		t.Skip("actual prepared source receipt not configured")
	}
	body, err := os.ReadFile(filepath.Join(root, "prepared-source.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Manifest model.PayloadManifest
		Files    []download.CachedFile
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Manifest.Validate() != nil || receipt.Manifest.Source.UpdateID != "3d12aa3e-806a-46c9-900e-bf7613959273" || receipt.Manifest.Source.BuildLabel != "19045.7811" || len(receipt.Manifest.Payloads) != 40 || len(receipt.Files) != 40 {
		t.Fatal("prepared source identity differs")
	}
	files := map[model.PayloadIdentity]download.CachedFile{}
	var total int64
	for _, f := range receipt.Files {
		if files[f.Identity].Path != "" {
			t.Fatal("duplicate prepared input")
		}
		file, e := os.Open(f.Path)
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.New()
		n, e := io.Copy(h, file)
		closeErr := file.Close()
		if e != nil || closeErr != nil || n != f.Identity.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 || f.Identity.Digest.Algorithm != model.DigestSHA256 || f.SHA256 != f.Identity.Digest.Value {
			t.Fatal("prepared file no longer matches source digest/size and local SHA256")
		}
		files[f.Identity] = f
		total += n
	}
	if total != 3036466495 {
		t.Fatalf("prepared total=%d", total)
	}
	for _, p := range receipt.Manifest.Payloads {
		if files[p.Identity].Path == "" {
			t.Fatal("prepared closure missing frozen payload")
		}
	}
	c := preparedCatalog{set: catalog.FileSet{Source: receipt.Manifest.Source, Payloads: receipt.Manifest.Payloads}}
	d := source.Discovery{Catalog: c}
	s := model.Selection{UpdateID: receipt.Manifest.Source.UpdateID, Architecture: "x86", Language: "en-us", Editions: []string{"professional"}}
	plan, err := d.Metadata(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	p := plan.Inputs[0]
	if p.Identity.Digest.Value != "edf4967f0d9f8b8703d24489f727786cd314c43a26cfdc111e5d3b8e40d13dc0" || p.Identity.Size != 338670400 {
		t.Fatal("selected WIM differs from independent retained source oracle")
	}
	inv, err := metadata.Inspect(context.Background(), metadata.InspectRequest{Source: receipt.Manifest.Source, Manifest: receipt.Manifest, Inspections: []metadata.Inspection{{Resource: metadata.LocalResource{Identity: p.Identity, Path: files[p.Identity].Path}, Provider: p.Provider}}})
	if err != nil || len(inv.Images) != 3 {
		t.Fatalf("actual WIM inventory: images=%d %v", len(inv.Images), err)
	}
	t.Logf("actual prepared source=%s build=%s inputs=40 bytes=%d manifest=%s; selected WIM matches independent retained baseline SHA256", receipt.Manifest.Source.UpdateID, receipt.Manifest.Source.BuildLabel, total, receipt.Manifest.Digest)
	for _, image := range inv.Images {
		t.Logf("actual image index=%d architecture=%s edition=%s installation=%s build=%s", image.Index, image.Architecture, image.Edition, image.InstallationType, image.Build)
	}
	t.Logf("classification=%s gaps=%d; metadata/XML observations do not prove file reconstruction, full reference closure, app licensing or servicing", inv.Classification, len(inv.Gaps))
}

type preparedCatalog struct{ set catalog.FileSet }

func (c preparedCatalog) Files(context.Context, string, string, string) (catalog.FileSet, error) {
	return c.set, nil
}
func (preparedCatalog) Editions(context.Context, string, string) ([]catalog.Edition, error) {
	return []catalog.Edition{{ID: "professional"}}, nil
}
