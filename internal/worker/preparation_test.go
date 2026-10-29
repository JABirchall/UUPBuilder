//go:build windows

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

type preparedFetcher struct{ files download.Materialized }

func (f preparedFetcher) Fetch(context.Context, model.PayloadManifest, model.Locators, model.Emit) (download.Materialized, error) {
	return f.files, nil
}

// The handler must checkpoint actual payload bytes, rather than a receipt that
// points at a mutable cache outside the committed stage.
func TestPreparationCheckpointsCopiedVerifiedPayloads(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.Image.UpdateID = "prepared-rev.1"
	cfg.Storage.Workspace = root
	cfg.Storage.Cache = root
	cfg.Output.Directory = root
	sel, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("real byte-verified prepared input")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	p := model.Payload{Destination: "opaque.esd", Identity: model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: digest}, Size: int64(len(body)), Provenance: model.PackageProvenance{Source: "synthetic-input", Name: "original.esd"}}}
	manifest, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: sel.UpdateID, BuildLabel: "fixture", Architecture: sel.Architecture, Language: sel.Language}, []model.Payload{p})
	if err != nil {
		t.Fatal(err)
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check := func(_ context.Context, path string) (planner.Volume, error) {
		v, e := platform.InspectStorage(path)
		return planner.Volume{Path: v.Path, ID: v.ID, FileSystem: v.Capabilities, AvailableBytes: v.AvailableBytes, MaxFileBytes: v.MaxFileBytes}, e
	}
	plan, err := (&planner.Planner{InspectStorage: check}).Resolve(ctx, planner.Request{Selection: sel, Settings: settings, Resolution: source.Resolution{Selection: sel, Settings: settings, Manifest: manifest}, Host: host, Intent: planner.DownloadOnly})
	if err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(t.TempDir(), "cache.data")
	if err := os.WriteFile(cachePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	fetcher := preparedFetcher{download.Materialized{p.Identity: {Identity: p.Identity, Path: cachePath, SHA256: digest}}}
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "modified-cache"}[corrupt], func(t *testing.T) {
			if corrupt {
				if err := os.WriteFile(cachePath, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			store, err := jobstore.Create(root, "prepared-job", clearMounts{})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			peer, err := platform.CurrentPeerIdentity()
			if err != nil {
				t.Fatal(err)
			}
			d := platform.WorkerDescriptor{Version: 1, JobID: "prepared-job", PlanDigest: plan.Digest(), Workspace: store.Identity()}
			registry := NewRegistry()
			if err := registry.Register(planner.DownloadPayloads, PreparationHandler(fetcher, nil)); err != nil {
				t.Fatal(err)
			}
			session, err := NewSession(plan, d, peer, peer, store, registry)
			if err != nil {
				t.Fatal(err)
			}
			result, err := session.Dispatch(ctx, peer, RequestFor(d, plan.Intent(), string(planner.DownloadPayloads)))
			if corrupt {
				if err == nil {
					t.Fatal("modified cache committed")
				}
				return
			}
			if err != nil || len(result.Outputs) != 2 {
				t.Fatalf("real inputs not checkpointed: %+v %v", result, err)
			}
			live, err := store.InspectRecovery(ctx, d.JobID)
			if err != nil || len(live.Checkpoints) != 1 || !live.Checkpoints[0].Valid {
				t.Fatalf("checkpoint: %+v %v", live, err)
			}
			for _, output := range live.Checkpoints[0].Checkpoint.Outputs {
				if output.Role == "prepared-inputs" {
					data, e := os.ReadFile(filepath.Join(store.Identity().Path, filepath.FromSlash(output.Path)))
					if e != nil {
						t.Fatal(e)
					}
					var receipt PreparedInputs
					if json.Unmarshal(data, &receipt) != nil || receipt.ManifestDigest != manifest.Digest || len(receipt.Files) != 1 || receipt.Files[0].Identity != p.Identity || receipt.Files[0].SHA256 != digest {
						t.Fatalf("receipt not source-bound: %s", data)
					}
				} else if output.SHA256 != digest || output.Size != int64(len(body)) {
					t.Fatalf("payload checkpoint mismatch: %+v", output)
				}
			}
		})
	}
}
