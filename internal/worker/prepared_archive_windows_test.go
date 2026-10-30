package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"uupbuilder/internal/config"
	"uupbuilder/internal/download"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
)

func TestPreparedArchiveCrossesFilePinLimitAndSelectsExactInputs(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.Image.UpdateID = "archive-fixture"
	cfg.Storage.Workspace = root
	cfg.Storage.Cache = root
	cfg.Output.Directory = root
	selection, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("a"))
	sha := hex.EncodeToString(sum[:])
	src := filepath.Join(t.TempDir(), "source")
	if err = os.WriteFile(src, []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	var payloads []model.Payload
	files := download.Materialized{}
	for i := 0; i < 350; i++ {
		p := model.Payload{Destination: fmt.Sprintf("payload-%03d", i), Identity: model.PayloadIdentity{Size: 1, Digest: model.Digest{Algorithm: model.DigestSHA256, Value: sha}, Provenance: model.PackageProvenance{Source: "fixture", Name: fmt.Sprintf("payload-%03d", i)}}}
		payloads = append(payloads, p)
		files[p.Identity] = download.CachedFile{Identity: p.Identity, Path: src, SHA256: sha}
	}
	manifest, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: selection.UpdateID, BuildLabel: "fixture", Architecture: selection.Architecture, Language: selection.Language}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inspect := func(_ context.Context, path string) (planner.Volume, error) {
		v, e := platform.InspectStorage(path)
		return planner.Volume{Path: v.Path, ID: v.ID, FileSystem: v.Capabilities, AvailableBytes: v.AvailableBytes, MaxFileBytes: v.MaxFileBytes}, e
	}
	plan, err := (&planner.Planner{InspectStorage: inspect}).Resolve(ctx, planner.Request{Selection: selection, Settings: settings, Resolution: source.Resolution{Selection: selection, Settings: settings, Manifest: manifest}, Host: host, Intent: planner.DownloadOnly})
	if err != nil {
		t.Fatal(err)
	}
	store, err := jobstore.Create(root, "archive-test", clearMounts{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	intent := jobstore.MutationIntent{JobID: "archive-test", PlanDigest: plan.Digest(), ConfigDigest: plan.Digest(), StageID: string(planner.DownloadPayloads), OwnedPaths: []string{"result.json", "payloads.tar"}}
	tx, err := store.Begin(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	stage := Stage{Plan: plan, Operation: plan.Operations()[0], Transaction: tx}
	result, err := prepareArchive(ctx, stage, files)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx, result.Outputs); err != nil {
		t.Fatal(err)
	}
	live, err := store.InspectRecovery(ctx, "archive-test")
	if err != nil {
		t.Fatal(err)
	}
	cp := live.Checkpoints[0].Checkpoint
	if len(cp.Outputs) != 2 {
		t.Fatal("payloads were not archived")
	}
	intent.StageID = "consume"
	intent.OwnedPaths = []string{"result.json"}
	intent.Predecessors = []jobstore.PredecessorIdentity{{StageID: cp.Intent.StageID, Digest: cp.Digest}}
	tx, err = store.Begin(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	stage.Transaction = tx
	stage.Predecessors = []jobstore.Checkpoint{cp}
	var receipt PreparedInputs
	if err = readCheckpoint(ctx, stage, planner.DownloadPayloads, &receipt); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "selected")
	want := map[model.PayloadIdentity]string{payloads[349].Identity: dest}
	if err = materializePrepared(ctx, stage, receipt, want); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(dest)
	if err != nil || string(body) != "a" {
		t.Fatal(err)
	}
	// An absent requested identity cannot be silently dropped by streaming.
	missing := payloads[0].Identity
	missing.Provenance.Name = "absent"
	if err = materializePrepared(ctx, stage, receipt, map[model.PayloadIdentity]string{missing: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Fatal("missing requested payload accepted")
	}
}
