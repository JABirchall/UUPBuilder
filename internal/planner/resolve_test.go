package planner

import (
	"bytes"
	"context"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"uupbuilder/internal/config"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/source"
	"uupbuilder/internal/tools"
)

func fixture(t *testing.T) (*Planner, Request) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Image.UpdateID = "revision-a"
	cfg.Storage.Workspace = filepath.Join(t.TempDir(), "scratch")
	cfg.Storage.Cache = filepath.Join(t.TempDir(), "cache")
	cfg.Output.Directory = filepath.Join(t.TempDir(), "out")
	sel, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	src := model.SourceIdentity{UpdateID: sel.UpdateID, BuildLabel: "build-a", Architecture: sel.Architecture, Language: sel.Language}
	payload := model.Payload{Destination: "image.esd", Identity: model.PayloadIdentity{Size: 5 << 30, Digest: model.Digest{Algorithm: model.DigestSHA256, Value: strings.Repeat("a", 64)}, Provenance: model.PackageProvenance{Source: "uup", Name: "image.esd"}}}
	manifest, err := model.NewPayloadManifest(src, []model.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	host := model.Host{WindowsBuild: 26100, NativeArchitecture: "amd64", ProcessArchitecture: "amd64", FileSystem: model.FileSystemCapabilities{Name: "FAT32"}}
	res := source.Resolution{Selection: sel, Settings: settings, Manifest: manifest, Classification: metadata.ClassificationSemanticInventory, Inventory: metadata.Inventory{Source: src, Manifest: manifest, Classification: metadata.ClassificationSemanticInventory}, AppPhase: metadata.PhaseOfflineProvisioning}
	p := &Planner{InspectStorage: func(_ context.Context, path string) (Volume, error) {
		return Volume{Path: path, ID: path, AvailableBytes: math.MaxInt64, MaxFileBytes: math.MaxInt64, FileSystem: model.FileSystemCapabilities{Name: "NTFS", Local: true, ACLs: true, AlternateStreams: true, HardLinks: true, ReparsePoints: true}}, nil
	}}
	return p, Request{Selection: sel, Settings: settings, Resolution: res, Host: host, DraftRevision: 7, Intent: DownloadOnly}
}

func TestPlannerBindsCapabilitiesToSourceAndPreparationRule(t *testing.T) {
	p, req := fixture(t)
	req.Intent = BuildMedia
	p.SelectTools = func(r tools.Requirement) (tools.Selection, error) {
		if r.Source != req.Resolution.Manifest.Source || r.SourceManifestDigest != req.Resolution.Manifest.Digest || (model.Digest{Algorithm: model.DigestSHA256, Value: r.RuleDigest}).Validate() != nil {
			t.Fatalf("capability request omits exact source/rule binding: %+v", r)
		}
		return tools.Selection{Requirement: r}, nil
	}
	if _, err := p.Resolve(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadPreparationReservesTransferScratchAndCheckpointCopies(t *testing.T) {
	p, req := fixture(t)
	prior := p.InspectStorage
	p.InspectStorage = func(ctx context.Context, path string) (Volume, error) {
		v, e := prior(ctx, path)
		v.AvailableBytes = 11 << 30
		return v, e
	}
	if _, err := p.Resolve(context.Background(), req); !errors.Is(err, ErrBlocked) {
		t.Fatalf("download checkpoint copies exceed available space but were permitted: %v", err)
	}
}

func TestDecoderIndependentlyValidatesResealedShape(t *testing.T) {
	p, req := fixture(t)
	req.Intent = BuildMedia
	p.SelectTools = func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }
	plan, err := p.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*frozen)
	}{
		{"host", func(f *frozen) { f.Host.WindowsBuild = 0; f.Tools[0].Host = f.Host }},
		{"app-phase", func(f *frozen) { f.AppPhase = "unknown" }},
		{"estimate", func(f *frozen) { f.Estimate.KnownPayloadBytes = 0 }},
		{"storage-role", func(f *frozen) { f.Storage[0].Role = "output" }},
		{"storage-requirement", func(f *frozen) { f.Storage[0].RequiredBytes = 0 }},
		{"incomplete-tools", func(f *frozen) { f.Tools[0].Operations = []tools.Operation{tools.Inspect} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := copyOf(*plan.data)
			tc.change(&f)
			f.Operations = graph(f)
			raw, err := toml.Marshal(struct {
				Digest string
				Plan   frozen
			}{hash(f), f})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeReadyPlan(raw); err == nil {
				t.Fatal("decoder accepted independently invalid plan with a matching checksum")
			}
		})
	}
}

func TestFrozenPlanRejectsChangedIdentity(t *testing.T) {
	p, req := fixture(t)
	req.Resolution.Locators = model.Locators{req.Resolution.Manifest.Payloads[0].Identity: model.Locator{URL: "https://signed.example/file?token=private"}}
	plan, err := p.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.Selection.Editions[0] = "other"
	req.Settings.Apps.Include = append(req.Settings.Apps.Include, "changed")
	sel := plan.Selection()
	sel.Editions[0] = "changed"
	settings := plan.RequestedSettings()
	settings.Conversion.Drivers.Targets = append(settings.Conversion.Drivers.Targets, model.DriverWinRE)
	manifest := plan.Manifest()
	manifest.Payloads[0].Destination = "changed"
	ops := plan.Operations()
	ops[0].Inputs[0].Digest = strings.Repeat("b", 64)
	if plan.Selection().Editions[0] != "professional" || plan.Manifest().Payloads[0].Destination != "image.esd" || plan.Operations()[0].Inputs[0].Digest != plan.Manifest().Digest {
		t.Fatal("accessor or request mutated frozen identity")
	}
	encoded, err := plan.MarshalTOML()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReadyPlan(encoded)
	if err != nil || decoded.Digest() != plan.Digest() {
		t.Fatalf("round trip: %v", err)
	}
	for _, mutation := range []struct{ old, new string }{{"revision-a", "revision-b"}, {"professional", "enterprise"}, {"download-only", "build-media"}, {"download-payloads", "master-iso"}, {"u05-graph-v1", "changed-rule"}} {
		changed := bytes.Replace(encoded, []byte(mutation.old), []byte(mutation.new), 1)
		if bytes.Equal(changed, encoded) {
			t.Fatalf("fixture missing %q", mutation.old)
		}
		if _, err := DecodeReadyPlan(changed); !errors.Is(err, ErrIdentityChanged) {
			t.Fatalf("accepted changed %s: %v", mutation.old, err)
		}
	}
	if bytes.Contains(encoded, []byte("signed.example")) {
		t.Fatal("persisted runtime locator")
	}
}

func TestBuildMediaAccountsForFinalISOSize(t *testing.T) {
	p, req := fixture(t)
	req.Intent = BuildMedia
	p.SelectTools = func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }
	base := p.InspectStorage
	p.InspectStorage = func(ctx context.Context, path string) (Volume, error) {
		v, e := base(ctx, path)
		if filepath.Base(path) == "out" {
			v.MaxFileBytes = 6 << 30
		}
		return v, e
	}
	if _, err := p.Resolve(context.Background(), req); err == nil || !strings.Contains(err.Error(), "large-file") {
		t.Fatalf("final ISO estimate ignored actual output limit: %v", err)
	}
}

func TestFrozenToolIdentityAndChosenVolumeRecheck(t *testing.T) {
	p, req := fixture(t)
	req.Intent = BuildMedia
	p.SelectTools = func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }
	plan, err := p.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	requirements := plan.Tools()
	original := requirements[0].ManifestDigest
	requirements[0].Operations[0] = tools.Service
	requirements[0].ManifestDigest = strings.Repeat("0", 64)
	rules := plan.Operations()
	rules[0].Rules[0].Digest = strings.Repeat("0", 64)
	if plan.Tools()[0].ManifestDigest != original || plan.Tools()[0].Operations[0] != tools.Extract || plan.Operations()[0].Rules[0].Digest == strings.Repeat("0", 64) {
		t.Fatal("caller changed frozen tool/rule authority")
	}
	encoded, err := plan.MarshalTOML()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReadyPlan(encoded); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(encoded, []byte(original), []byte(strings.Repeat("0", 64)), 1)
	if _, err := DecodeReadyPlan(changed); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("changed tool pin accepted: %v", err)
	}
	probe := p.InspectStorage
	if err := plan.RecheckStorage(context.Background(), func(ctx context.Context, path string) (Volume, error) {
		v, e := probe(ctx, path)
		v.ID = "substituted-volume"
		return v, e
	}); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("changed actual volume accepted: %v", err)
	}
}

func TestPreflightChecksChosenVolumes(t *testing.T) {
	for _, role := range []string{"scratch", "cache", "out"} {
		t.Run(role, func(t *testing.T) {
			p, req := fixture(t)
			base := p.InspectStorage
			p.InspectStorage = func(ctx context.Context, path string) (Volume, error) {
				v, e := base(ctx, path)
				if filepath.Base(path) == role {
					v.MaxFileBytes = (4 << 30) - 1
				}
				return v, e
			}
			_, err := p.Resolve(context.Background(), req)
			if err == nil || !strings.Contains(err.Error(), "large-file") {
				t.Fatalf("chosen %s volume was not checked: %v", role, err)
			}
		})
	}
	p, req := fixture(t)
	base := p.InspectStorage
	// All three destinations share this physical volume. Its free bytes cannot
	// independently be spent once per configured directory.
	p.InspectStorage = func(ctx context.Context, path string) (Volume, error) {
		v, e := base(ctx, path)
		v.ID = "same-volume"
		v.AvailableBytes = 9 << 30
		return v, e
	}
	if _, err := p.Resolve(context.Background(), req); err == nil || !strings.Contains(err.Error(), "space") {
		t.Fatalf("shared-volume accounting: %v", err)
	}
}

func TestInvalidAndStaleDraftsAndExcludedSettingsBlock(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Request)
		want   string
	}{
		{"invalid", func(r *Request) { r.Selection.Editions = nil }, "image.editions"},
		{"stale-settings", func(r *Request) { r.Settings.Downloads.Retries++ }, "identity"},
		{"stale-source", func(r *Request) { r.Resolution.Manifest.Source.UpdateID = "changed" }, "identity"},
		{"image-output", func(r *Request) { r.Settings.Output.Kind = model.OutputImage; r.Resolution.Settings = r.Settings }, "output.kind"},
		{"winre", func(r *Request) { r.Settings.Conversion.IncludeWinRE = true; r.Resolution.Settings = r.Settings }, "include_winre"},
		{"winre-auto", func(r *Request) {
			r.Settings.Conversion.WinREUpdates = model.InclusionAuto
			r.Resolution.Settings = r.Settings
		}, "winre_updates"},
		{"winre-driver", func(r *Request) {
			r.Settings.Conversion.Drivers.Targets = []model.DriverTarget{model.DriverWinRE}
			r.Resolution.Settings = r.Settings
		}, "drivers.targets"},
		{"discovery", func(r *Request) {
			r.Intent = BuildMedia
			r.Resolution.Diagnostics = []model.Diagnostic{{Code: "metadata-discovery-unavailable", Severity: model.SeverityError, Message: "semantic discovery producer is missing"}}
		}, "metadata-discovery-unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, req := fixture(t)
			tc.change(&req)
			_, err := p.Resolve(context.Background(), req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %s blocker, got %v", tc.want, err)
			}
		})
	}
}

func TestMissingProviderIsConcreteBlocker(t *testing.T) {
	p, req := fixture(t)
	req.Intent = BuildMedia
	_, err := p.Resolve(context.Background(), req)
	if !errors.Is(err, tools.ErrUnverified) || !strings.Contains(err.Error(), "capability-unverified") {
		t.Fatalf("provider blocker: %v", err)
	}
}

func TestDeferredAppBarrierPrecedesMutation(t *testing.T) {
	p, req := fixture(t)
	req.Intent = BuildMedia
	req.Resolution.AppPhase = metadata.PhasePostAssembly
	req.Resolution.Diagnostics = []model.Diagnostic{{Code: "apps-require-materialized-inspection", Severity: model.SeverityError, Message: "source-bound post-assembly inspection required"}, {Code: "app-selection-rules-unresolved", Severity: model.SeverityError, Message: "explicit app requests require post-assembly validation"}}
	p.SelectTools = func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }
	plan, err := p.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	barrier := -1
	for i, op := range plan.Operations() {
		if op.Kind == InspectApps {
			barrier = i
		}
		if op.Kind == CustomizeImage && (barrier < 0 || !contains(op.DependsOn, "inspect-apps")) {
			t.Fatal("app mutation bypassed deferred inspection barrier")
		}
	}
	if barrier < 0 {
		t.Fatal("missing deferred barrier")
	}
}
