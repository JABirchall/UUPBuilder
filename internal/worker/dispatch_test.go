//go:build windows

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uupbuilder/internal/config"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
	"uupbuilder/internal/tools"
)

type clearMounts struct{}

func (clearMounts) Inspect(context.Context, string) (jobstore.MountSnapshot, error) {
	return jobstore.MountSnapshot{Complete: true}, nil
}
func workerFixture(t *testing.T) (planner.ReadyPlan, *jobstore.Store, platform.PeerIdentity, platform.WorkerDescriptor) {
	t.Helper()
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.Image.UpdateID = "revision-a"
	cfg.Output.Directory = root
	cfg.Storage.Workspace = root
	cfg.Storage.Cache = root
	sel, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: sel.UpdateID, BuildLabel: "build", Architecture: sel.Architecture, Language: sel.Language}, []model.Payload{{Destination: "payload", Identity: model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: strings.Repeat("a", 64)}, Size: 1, Provenance: model.PackageProvenance{Source: "uup", Name: "payload"}}}})
	if err != nil {
		t.Fatal(err)
	}
	host, err := platform.DetectHost(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := planner.Planner{InspectStorage: func(_ context.Context, path string) (planner.Volume, error) {
		v, e := platform.InspectStorage(path)
		return planner.Volume{Path: v.Path, ID: v.ID, FileSystem: v.Capabilities, AvailableBytes: v.AvailableBytes, MaxFileBytes: v.MaxFileBytes}, e
	}}
	plan, err := p.Resolve(context.Background(), planner.Request{Selection: sel, Settings: settings, Resolution: source.Resolution{Selection: sel, Settings: settings, Manifest: manifest}, Host: host, Intent: planner.DownloadOnly, DraftRevision: 2})
	if err != nil {
		t.Fatal(err)
	}
	store, err := jobstore.Create(root, "job-a", clearMounts{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	peer, err := platform.CurrentPeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	descriptor := platform.WorkerDescriptor{Version: 1, JobID: "job-a", PlanDigest: plan.Digest(), Workspace: store.Identity()}
	return plan, store, peer, descriptor
}
func resultHandler(ctx context.Context, stage Stage) (Result, error) {
	data := []byte("verified test result")
	file, err := stage.Transaction.OpenFile("result.json", os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return Result{}, err
	}
	if _, err = file.Write(data); err != nil {
		file.Close()
		return Result{}, err
	}
	if err = file.Close(); err != nil {
		return Result{}, err
	}
	sum := sha256.Sum256(data)
	return Result{Outputs: []jobstore.OutputIdentity{{Path: "result.json", Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Role: "test-observation"}}}, nil
}
func TestWorkerRejectsWrongPeerOrOperation(t *testing.T) {
	plan, store, peer, descriptor := workerFixture(t)
	registry := NewRegistry()
	if err := registry.Register(planner.DownloadPayloads, Handler{Run: resultHandler}); err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(plan, descriptor, peer, peer, store, registry)
	if err != nil {
		t.Fatal(err)
	}
	request := RequestFor(descriptor, plan.Intent(), plan.Operations()[0].ID)
	before, err := os.ReadDir(store.Identity().Path)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		change func(*platform.PeerIdentity, *OperationRequest)
	}{
		{"pid", func(p *platform.PeerIdentity, r *OperationRequest) { p.ProcessID++ }},
		{"creation", func(p *platform.PeerIdentity, r *OperationRequest) { p.CreationTime++ }},
		{"sid", func(p *platform.PeerIdentity, r *OperationRequest) { p.UserSID += "-other" }},
		{"session", func(p *platform.PeerIdentity, r *OperationRequest) { p.SessionID++ }},
		{"executable", func(p *platform.PeerIdentity, r *OperationRequest) {
			p.Executable = filepath.Join(t.TempDir(), "other.exe")
		}},
		{"elevation", func(p *platform.PeerIdentity, r *OperationRequest) { p.Elevated = !p.Elevated }},
		{"operation", func(p *platform.PeerIdentity, r *OperationRequest) { r.OperationID = "master-iso" }},
		{"intent", func(p *platform.PeerIdentity, r *OperationRequest) { r.Intent = planner.BuildMedia }},
		{"plan", func(p *platform.PeerIdentity, r *OperationRequest) { r.PlanDigest = strings.Repeat("b", 64) }},
		{"capability", func(p *platform.PeerIdentity, r *OperationRequest) { r.Capability = strings.Repeat("0", 32) }},
		{"workspace", func(p *platform.PeerIdentity, r *OperationRequest) { r.Workspace.Path = t.TempDir() }},
		{"workspace-job", func(p *platform.PeerIdentity, r *OperationRequest) { r.Workspace.JobID = "other" }},
		{"job", func(p *platform.PeerIdentity, r *OperationRequest) { r.JobID = "other" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual, req := peer, request
			tc.change(&actual, &req)
			if _, err := session.Dispatch(context.Background(), actual, req); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("wrong binding dispatched: %v", err)
			}
		})
	}
	after, err := os.ReadDir(store.Identity().Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatal("rejected request created stage resources")
	}
	if _, err := session.Dispatch(context.Background(), peer, request); err != nil {
		t.Fatal(err)
	}
	live, err := store.InspectRecovery(context.Background(), descriptor.JobID)
	if err != nil || len(live.Checkpoints) != 1 || !live.Checkpoints[0].Valid {
		t.Fatalf("authorized real checkpoint: %#v %v", live, err)
	}
	if _, err := session.Dispatch(context.Background(), peer, request); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replayed operation: %v", err)
	}
}

func TestWorkerRejectsMissingHandlerAndForeignStore(t *testing.T) {
	plan, store, peer, descriptor := workerFixture(t)
	if _, err := NewSession(plan, descriptor, peer, peer, store, NewRegistry()); !errors.Is(err, ErrMissingHandler) {
		t.Fatalf("missing handler: %v", err)
	}
	registry := NewRegistry()
	_ = registry.Register(planner.DownloadPayloads, Handler{Run: resultHandler})
	descriptor.Workspace.Token = strings.Repeat("0", 32)
	if _, err := NewSession(plan, descriptor, peer, peer, store, registry); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("foreign workspace capability: %v", err)
	}
}

func TestWorkerBindsWorkspaceToPlannedScratchParent(t *testing.T) {
	plan, _, peer, d := workerFixture(t)
	foreign, err := jobstore.Create(t.TempDir(), d.JobID, clearMounts{})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	d.Workspace = foreign.Identity()
	registry := NewRegistry()
	_ = registry.Register(planner.DownloadPayloads, Handler{Run: resultHandler})
	if _, err := NewSession(plan, d, peer, peer, foreign, registry); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("workspace escaped planned scratch parent: %v", err)
	}
}

func TestDeferredBarrierBindsActualAssemblySourceDraftAndPlan(t *testing.T) {
	for _, broken := range []string{"plan", "manifest", "revision", "assembly", "settings", "observation", "valid"} {
		t.Run(broken, func(t *testing.T) {
			download, store, peer, d := workerFixture(t)
			p := planner.Planner{InspectStorage: nativeStorage, SelectTools: func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }}
			manifest := download.Manifest()
			settings := download.RequestedSettings()
			selection := download.Selection()
			host, err := platform.DetectHost(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			plan, err := p.Resolve(context.Background(), planner.Request{Selection: selection, Settings: settings, Resolution: source.Resolution{Selection: selection, Settings: settings, Manifest: manifest, Inventory: metadata.Inventory{Source: manifest.Source, Manifest: manifest, Classification: metadata.ClassificationSemanticInventory}, Classification: metadata.ClassificationSemanticInventory, AppPhase: metadata.PhasePostAssembly}, Host: host, DraftRevision: 11, Intent: planner.BuildMedia})
			if err != nil {
				t.Fatal(err)
			}
			d.PlanDigest = plan.Digest()
			registry := NewRegistry()
			for _, op := range plan.Operations() {
				if err := registry.Register(op.Kind, Handler{Run: resultHandler}); err != nil {
					t.Fatal(err)
				}
			}
			// The inventory handler's authority is fixed before the session snapshot.
			registry.handlers[planner.InspectApps] = Handler{Run: func(ctx context.Context, stage Stage) (Result, error) {
				result, err := resultHandler(ctx, stage)
				if err != nil {
					return result, err
				}
				assembly := ""
				for _, cp := range stage.Predecessors {
					if cp.Intent.StageID == string(planner.AssembleImage) {
						assembly = cp.Digest
					}
				}
				e := &AppBarrierEvidence{PlanDigest: plan.Digest(), ManifestDigest: manifest.Digest, DraftRevision: 11, AssemblyCheckpointDigest: assembly, RequestedSettingsDigest: identityDigest(settings), ObservationDigest: result.Outputs[0].SHA256}
				switch broken {
				case "plan":
					e.PlanDigest = strings.Repeat("0", 64)
				case "manifest":
					e.ManifestDigest = strings.Repeat("0", 64)
				case "revision":
					e.DraftRevision++
				case "assembly":
					e.AssemblyCheckpointDigest = strings.Repeat("0", 64)
				case "settings":
					e.RequestedSettingsDigest = strings.Repeat("0", 64)
				case "observation":
					e.ObservationDigest = strings.Repeat("0", 64)
				}
				result.AppBarrier = e
				return result, nil
			}}
			session, err := NewSession(plan, d, peer, peer, store, registry)
			if err != nil {
				t.Fatal(err)
			}
			for _, kind := range []planner.OperationKind{planner.DownloadPayloads, planner.AssembleImage} {
				if _, err := session.Dispatch(context.Background(), peer, RequestFor(d, plan.Intent(), string(kind))); err != nil {
					t.Fatal(err)
				}
			}
			_, err = session.Dispatch(context.Background(), peer, RequestFor(d, plan.Intent(), string(planner.InspectApps)))
			if broken == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := session.Dispatch(context.Background(), peer, RequestFor(d, plan.Intent(), string(planner.ServiceImage))); err != nil {
					t.Fatalf("valid read-only barrier did not unlock next stage: %v", err)
				}
			} else {
				if !errors.Is(err, ErrAppBarrier) {
					t.Fatalf("wrong %s barrier: %v", broken, err)
				}
				if _, err := session.Dispatch(context.Background(), peer, RequestFor(d, plan.Intent(), string(planner.ServiceImage))); !errors.Is(err, ErrUnauthorized) {
					t.Fatalf("mutation bypassed rejected barrier: %v", err)
				}
			}
		})
	}
}

func TestActiveRegistrySnapshotCannotBeReplaced(t *testing.T) {
	plan, store, peer, d := workerFixture(t)
	registry := NewRegistry()
	_ = registry.Register(planner.DownloadPayloads, Handler{Run: resultHandler})
	session, err := NewSession(plan, d, peer, peer, store, registry)
	if err != nil {
		t.Fatal(err)
	}
	registry.mu.Lock()
	registry.handlers[planner.DownloadPayloads] = Handler{Run: func(context.Context, Stage) (Result, error) {
		t.Error("later registry authority entered active session")
		return Result{}, errors.New("changed")
	}}
	registry.mu.Unlock()
	if _, err := session.Dispatch(context.Background(), peer, RequestFor(d, plan.Intent(), string(planner.DownloadPayloads))); err != nil {
		t.Fatal(err)
	}
}
