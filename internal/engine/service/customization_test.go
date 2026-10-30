package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
)

func TestCustomizationObservationsRejectWrongVersionAndMissingFeature(t *testing.T) {
	app := metadata.AppPackage{Identity: metadata.AppIdentity{Name: "Microsoft.Example", Version: "2.0.0.0", Architecture: "neutral", Publisher: "CN=Publisher"}}
	p := planner.AppPlan{Provision: []planner.AppProvision{{Package: app}}}
	observed := CustomizationObservation{Apps: []ProvisionedApp{{Name: "Microsoft.Example", Version: "1.0.0.0", Architecture: "neutral", PublisherID: publisherID("CN=Publisher"), PackageName: "Microsoft.Example_1.0.0.0_neutral__test"}}}
	if verifyCustomization(p, []planner.FeatureOperation{{Name: "NetFx3", Enable: true}}, nil, observed) == nil {
		t.Fatal("wrong app version accepted")
	}
	observed.Apps[0].Version = "2.0.0.0"
	if verifyCustomization(p, []planner.FeatureOperation{{Name: "NetFx3", Enable: true}}, nil, observed) == nil {
		t.Fatal("missing feature accepted")
	}
	observed.Features = map[string]string{"NetFx3": "Enabled"}
	if e := verifyCustomization(p, []planner.FeatureOperation{{Name: "NetFx3", Enable: true}}, nil, observed); e != nil {
		t.Fatal(e)
	}
	observed.Features["NetFx3"] = "Enable Pending"
	if e := verifyCustomization(p, []planner.FeatureOperation{{Name: "NetFx3", Enable: true}}, nil, observed); e != nil {
		t.Fatal(e)
	}
}
func TestDISMCustomizationParsersAndFixedArguments(t *testing.T) {
	apps, e := parseProvisionedApps("DisplayName : Microsoft.Example\nVersion : 2.0.0.0\nArchitecture : neutral\nResourceId :\nPackageName : Microsoft.Example_2.0.0.0_neutral__8wekyb3d8bbwe\n")
	if e != nil || len(apps) != 1 || apps[0].PublisherID != "8wekyb3d8bbwe" {
		t.Fatalf("apps: %+v %v", apps, e)
	}
	if _, e = parseProvisionedApps("DisplayName : Example\n"); e == nil {
		t.Fatal("partial observation accepted")
	}
	if publisherID("CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") != "8wekyb3d8bbwe" {
		t.Fatal("incorrect Windows publisher ID")
	}
	op := planner.AppProvision{Package: metadata.AppPackage{Identity: metadata.AppIdentity{Name: "Example"}}, SkipLicense: true, Stub: model.AppStub}
	args, e := appArguments(op, "C:/main.msix", []string{"C:/framework.appx"}, "")
	if e != nil || len(args) != 5 || args[4] != "/StubPackageOption:installstub" {
		t.Fatalf("app args: %v %v", args, e)
	}
	op.SkipLicense = false
	if _, e = appArguments(op, "C:/main.msix", nil, ""); e == nil {
		t.Fatal("unlicensed mutation accepted")
	}
}

type customizationFixture struct {
	*fixtureBackend
	omitApp bool
	exports int
	cancel  context.CancelFunc
}

func (f *customizationFixture) Export(ctx context.Context, src ImageRef, path string, emit model.Emit) error {
	f.exports++
	return f.fixtureBackend.Export(ctx, src, path, emit)
}
func (f *customizationFixture) InspectCustomization(_ context.Context, m platform.OwnedMount, _ model.DriverTarget, _ []planner.FeatureOperation, _ model.Emit) (CustomizationObservation, error) {
	v, e := readFixture(f.mounted[m.RelativePath])
	return v.Customization, e
}
func (f *customizationFixture) AddApp(_ context.Context, m platform.OwnedMount, op planner.AppProvision, _ AppFiles, _ model.Emit) error {
	if f.omitApp {
		return nil
	}
	path := f.mounted[m.RelativePath]
	v, e := readFixture(path)
	if e != nil {
		return e
	}
	id := op.ObservedIdentity()
	v.Customization.Apps = append(v.Customization.Apps, ProvisionedApp{Name: id.Name, Version: id.Version, Architecture: id.Architecture, ResourceID: id.ResourceID, PublisherID: publisherID(id.Publisher)})
	e = writeFixture(path, v)
	if f.cancel != nil {
		f.cancel()
	}
	return e
}
func (f *customizationFixture) RemoveApp(context.Context, platform.OwnedMount, string, model.Emit) error {
	return nil
}
func (f *customizationFixture) EnableFeature(_ context.Context, m platform.OwnedMount, op planner.FeatureOperation, _ []UpdateInput, _ model.Emit) error {
	path := f.mounted[m.RelativePath]
	v, e := readFixture(path)
	if e != nil {
		return e
	}
	v.Customization.Features = map[string]string{op.Name: "Enabled"}
	return writeFixture(path, v)
}
func (f *customizationFixture) DriverInfo(context.Context, platform.OwnedMount, string, model.Emit) (DriverObservation, error) {
	return DriverObservation{OriginalName: "sample.inf", Provider: "Example", Class: "Net", Version: "1.0.0.0"}, nil
}
func (f *customizationFixture) AddDriver(_ context.Context, m platform.OwnedMount, _ string, _ model.Emit) error {
	path := f.mounted[m.RelativePath]
	v, e := readFixture(path)
	if e != nil {
		return e
	}
	driver, _ := f.DriverInfo(context.Background(), m, "", nil)
	v.Customization.Drivers = append(v.Customization.Drivers, driver)
	return writeFixture(path, v)
}
func customizationRequestFixture(t *testing.T, configure ...func(*metadata.Inventory, *model.ResolvedSettings)) (CustomizationRequest, *customizationFixture) {
	t.Helper()
	source := model.SourceIdentity{UpdateID: "customize-test", BuildLabel: "28000.3365", Architecture: "amd64", Language: "en-gb"}
	body := []byte("app payload fixture")
	sum := sha256.Sum256(body)
	payload := model.Payload{Destination: "app.msix", Identity: model.PayloadIdentity{Size: int64(len(body)), Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, Provenance: model.PackageProvenance{Source: "fixture", Name: "app.msix"}}}
	manifest, e := model.NewPayloadManifest(source, []model.Payload{payload})
	if e != nil {
		t.Fatal(e)
	}
	ref := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: payload.Identity}, SHA256: strings.Repeat("a", 64)}
	evidence := metadata.Evidence{Source: source, Document: ref, Selector: "/Package/Identity"}
	family := metadata.AppFamily{Name: "Example", Publisher: "CN=Example"}
	inv := metadata.Inventory{Source: source, Manifest: manifest, Images: []metadata.Image{{Edition: "Professional", Build: "10.0.28000.1"}}, Documents: []metadata.Document{{Reference: ref}}, Apps: metadata.AppInventory{Packages: []metadata.AppPackage{{Identity: metadata.AppIdentity{Name: family.Name, Publisher: family.Publisher, Version: "1.0.0.0", Architecture: "neutral"}, Family: family, Phase: metadata.PhaseOfflineProvisioning, Evidence: evidence}}, SelectionRules: []metadata.AppSelectionRule{{ID: "Exact.Request", Family: family, LicenseFree: true, StubSupported: true, Evidence: evidence}}}}
	cfg := config.Defaults()
	cfg.Image.UpdateID = source.UpdateID
	_, settings, requestErr := cfg.Request()
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	settings.Apps = model.AppSettings{Mode: model.AppsCustom, Include: []string{"Exact.Request"}, StubPolicy: model.AppStub, Edge: model.EdgeDefault}
	for _, fn := range configure {
		fn(&inv, &settings)
	}
	plan, e := planner.BuildCustomizationPlan(inv, settings, []string{"Professional", "Enterprise"})
	if e != nil {
		t.Fatal(e)
	}
	store, e := jobstore.Create(t.TempDir(), "customize-test", fixtureMountInventory{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := store.Close(); e != nil {
			t.Error(e)
		}
	})
	tx, e := store.Begin(context.Background(), jobstore.MutationIntent{JobID: "customize-test", PlanDigest: plan.Digest, ConfigDigest: plan.Digest, StageID: "customize-image", OwnedPaths: plan.OutputPaths()})
	if e != nil {
		t.Fatal(e)
	}
	parent := t.TempDir()
	path := filepath.Join(parent, "source.wim")
	images := []ImageIdentity{{Index: 1, Edition: "Professional", Architecture: "amd64", Language: "en-gb"}, {Index: 2, Edition: "Enterprise", Architecture: "amd64", Language: "en-gb"}}
	if e = writeFixture(path, imageFixture{Images: images}); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(path)
	imageSum := sha256.Sum256(raw)
	req := CustomizationRequest{Plan: plan, Transaction: tx}
	for _, image := range images {
		req.Images = append(req.Images, InspectedImage{ImageRef: ImageRef{WIMPath: path, Index: image.Index}, Identity: image, SHA256: hex.EncodeToString(imageSum[:])})
	}
	payloadPath := filepath.Join(parent, "app.msix")
	if e = os.WriteFile(payloadPath, body, 0600); e != nil {
		t.Fatal(e)
	}
	req.Payloads = []UpdateInput{{Resource: ref.Resource, Path: payloadPath}}
	return req, &customizationFixture{fixtureBackend: &fixtureBackend{mounted: map[string]string{}}}
}

func TestCustomizationCommitsAfterUnmountReplacesMountDirectory(t *testing.T) {
	req, backend := customizationRequestFixture(t)
	backend.replaceMountDirectory = true
	result, err := (&CustomizationExecutor{Backend: backend}).Execute(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Transaction.Commit(context.Background(), result.Outputs); err != nil {
		t.Fatalf("verified customized image could not be checkpointed after successful unmount: %v", err)
	}
}

func TestCustomizationFeaturesAndDriversReachSeparateOSAndWinPETargets(t *testing.T) {
	driverDir := t.TempDir()
	inf := filepath.Join(driverDir, "sample.inf")
	body := []byte("signed INF fixture")
	if e := os.WriteFile(inf, body, 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(body)
	req, b := customizationRequestFixture(t, func(inv *metadata.Inventory, s *model.ResolvedSettings) {
		s.Conversion.NetFX3 = true
		s.Conversion.Drivers = model.DriverSettings{Enabled: true, Source: driverDir, Targets: []model.DriverTarget{model.DriverShared}}
		inv.Packages = []metadata.Package{{Identity: metadata.PackageIdentity{Name: "Microsoft-Windows-NetFx3-OnDemand-Package", Architecture: inv.Source.Architecture}, Evidence: inv.Apps.Packages[0].Evidence}}
	})
	req.FeatureSources = req.Payloads
	for _, target := range []model.DriverTarget{model.DriverOS, model.DriverWinPE} {
		req.Drivers = append(req.Drivers, DriverInput{Target: target, INF: inf, Files: []DriverFile{{Path: inf, SHA256: hex.EncodeToString(sum[:])}}})
	}
	bootPath := filepath.Join(t.TempDir(), "boot.wim")
	bootImages := []ImageIdentity{{Index: 1, Edition: "WindowsPE", Architecture: "amd64", Language: "en-us"}, {Index: 2, Edition: "WindowsPE", Architecture: "amd64", Language: "en-us"}}
	if e := writeFixture(bootPath, imageFixture{Images: bootImages}); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(bootPath)
	bootSum := sha256.Sum256(raw)
	for _, image := range bootImages {
		req.BootImages = append(req.BootImages, InspectedImage{ImageRef: ImageRef{WIMPath: bootPath, Index: image.Index}, Identity: image, SHA256: hex.EncodeToString(bootSum[:])})
	}
	out, e := (&CustomizationExecutor{Backend: b}).Execute(context.Background(), req, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(out.BootImages) != 2 || out.BootWIMPath == "" {
		t.Fatalf("WinPE output missing: %+v", out)
	}
	for _, observation := range out.Observations {
		if observation.Features["NetFx3"] != "Enabled" || len(observation.Apps) != 1 || len(observation.Drivers) != 1 {
			t.Fatalf("OS customization missing: %+v", observation)
		}
	}
	for _, observation := range out.BootObservations {
		if len(observation.Features) != 0 || len(observation.Apps) != 0 || len(observation.Drivers) != 1 {
			t.Fatalf("OS policies leaked into WinPE: %+v", observation)
		}
	}
}
func TestCustomizationExecutorProducesOrderedImagesAndObservedApps(t *testing.T) {
	req, backend := customizationRequestFixture(t)
	before, e := os.ReadFile(req.Images[0].WIMPath)
	if e != nil {
		t.Fatal(e)
	}
	out, e := (&CustomizationExecutor{Backend: backend}).Execute(context.Background(), req, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Images) != 2 || out.Images[0].Edition != "Professional" || out.Images[1].Edition != "Enterprise" || len(out.Observations) != 2 || len(out.Observations[0].Apps) != 1 || out.WIMPath == "" {
		t.Fatalf("wrong customization output: %+v", out)
	}
	after, _ := os.ReadFile(req.Images[0].WIMPath)
	if string(before) != string(after) {
		t.Fatal("source image mutated")
	}
	if len(backend.mounted) != 0 {
		t.Fatal("mount leaked")
	}
}
func TestCustomizationExecutorMissingClosureAndFailedStateCannotPublish(t *testing.T) {
	for _, kind := range []string{"payload", "state", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			req, b := customizationRequestFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "payload":
				req.Payloads = nil
			case "state":
				b.omitApp = true
			case "cancel":
				b.cancel = cancel
			}
			out, e := (&CustomizationExecutor{Backend: b}).Execute(ctx, req, nil)
			if e == nil || len(out.Outputs) != 0 {
				t.Fatalf("failed customization produced outputs: %+v %v", out, e)
			}
			if kind == "payload" && b.exports != 0 {
				t.Fatal("app closure checked after mutation")
			}
			if len(b.mounted) != 0 {
				t.Fatal("failed customization mount leaked")
			}
		})
	}
}
