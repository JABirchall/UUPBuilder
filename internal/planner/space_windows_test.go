package planner_test

import (
	"context"
	"strings"
	"testing"

	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
)

func TestNativeChosenVolumeAccountsForPayloadAboveFourGiB(t *testing.T) {
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.Image.UpdateID = "revision"
	cfg.Storage.Workspace = root
	cfg.Storage.Cache = root
	cfg.Output.Directory = root
	selection, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: selection.UpdateID, BuildLabel: "build", Architecture: selection.Architecture, Language: selection.Language}, []model.Payload{{Destination: "image.esd", Identity: model.PayloadIdentity{Size: 5 << 30, Digest: model.Digest{Algorithm: model.DigestSHA256, Value: strings.Repeat("a", 64)}, Provenance: model.PackageProvenance{Source: "uup", Name: "image.esd"}}}})
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
	plan, err := p.Resolve(context.Background(), planner.Request{Selection: selection, Settings: settings, Resolution: source.Resolution{Selection: selection, Settings: settings, Manifest: manifest}, Host: host, Intent: planner.DownloadOnly})
	if err != nil {
		t.Fatal(err)
	}
	estimate := plan.Estimates()
	if estimate.KnownPayloadBytes != 5368709120 || estimate.ScratchBytes != 5368709120 || !estimate.ScratchEstimated {
		t.Fatalf("64-bit accounting: %#v", estimate)
	}
	checks := plan.StorageChecks()
	if len(checks) != 3 || checks[0].Volume.ID != checks[1].Volume.ID || checks[0].RequiredBytes+checks[1].RequiredBytes != 10737418240 {
		t.Fatalf("shared physical volume accounting: %#v", checks)
	}
	t.Logf("Observed host: Windows build %d, native %s, process %s; chosen filesystem %s, volume %s, free %d bytes; known payload 5368709120 bytes, scratch estimate 5368709120 bytes; aggregate required 10737418240 bytes. No payload/image bytes were created.", host.WindowsBuild, host.NativeArchitecture, host.ProcessArchitecture, checks[0].Volume.FileSystem.Name, checks[0].Volume.ID, checks[0].Volume.AvailableBytes)
}
