package output

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uupbuilder/internal/config"
	"uupbuilder/internal/engine/service"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
	"uupbuilder/internal/tools"
)

func outputPlan(t *testing.T) planner.ReadyPlan {
	t.Helper()
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Image.UpdateID = "output-fixture"
	cfg.Image.Language = "en-GB"
	root := t.TempDir()
	cfg.Storage.Workspace = root
	cfg.Storage.Cache = root
	cfg.Output.Directory = root
	cfg.Output.Label = "U10_SYNTHETIC"
	sel, s, _ := cfg.Request()
	m, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: sel.UpdateID, BuildLabel: "28000.1", Architecture: sel.Architecture, Language: sel.Language}, []model.Payload{{Destination: "fixture", Identity: model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: strings.Repeat("a", 64)}, Size: 1, Provenance: model.PackageProvenance{Source: "fixture", Name: "fixture"}}}})
	if err != nil {
		t.Fatal(err)
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := planner.Planner{InspectStorage: func(_ context.Context, path string) (planner.Volume, error) {
		v, e := platform.InspectStorage(path)
		return planner.Volume{Path: v.Path, ID: v.ID, FileSystem: v.Capabilities, AvailableBytes: v.AvailableBytes, MaxFileBytes: v.MaxFileBytes}, e
	}, SelectTools: func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }}
	inv := metadata.Inventory{Source: m.Source, Manifest: m, Images: []metadata.Image{{Index: 1, Edition: sel.Editions[0], Build: "10.0.28000.1", Architecture: sel.Architecture}}, Classification: metadata.ClassificationSemanticInventory}
	ref := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: m.Payloads[0].Identity}, SHA256: strings.Repeat("b", 64)}
	ev := metadata.Evidence{Source: m.Source, Document: ref, Selector: "/Package/Identity"}
	family := metadata.AppFamily{Name: "Optional.App", Publisher: "CN=Test"}
	inv.Documents = []metadata.Document{{Reference: ref}}
	inv.Apps = metadata.AppInventory{Packages: []metadata.AppPackage{{Identity: metadata.AppIdentity{Name: family.Name, Publisher: family.Publisher, Version: "1.0.0.0", Architecture: "amd64"}, Family: family, Phase: metadata.PhaseOfflineProvisioning, Evidence: ev}}, SelectionRules: []metadata.AppSelectionRule{{ID: "Optional.App", Family: family, LicenseFree: true, Evidence: ev}}}
	plan, err := p.Resolve(ctx, planner.Request{Selection: sel, Settings: s, Resolution: source.Resolution{Selection: sel, Settings: s, Manifest: m, Inventory: inv, Classification: metadata.ClassificationSemanticInventory, AppPhase: metadata.PhaseOfflineProvisioning}, Host: host, Intent: planner.BuildMedia})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

type fixtureExporter struct {
	missing bool
	edition string
}

func (f fixtureExporter) Export(_ context.Context, _, dst string, _ model.ImageFormat, _ int) error {
	if f.missing {
		return nil
	}
	return os.WriteFile(dst, testWIM(f.edition), 0600)
}
func (f fixtureExporter) VerifyImage(context.Context, string, model.ImageFormat) error { return nil }

func exportFixture(t *testing.T) (ExportRequest, fixtureExporter) {
	t.Helper()
	p := outputPlan(t)
	c := p.CustomizationPlan()
	wim := filepath.Join(t.TempDir(), "customized.wim")
	b := testWIM(c.Editions[0])
	b = []byte(strings.ReplaceAll(string(b), "en-GB", p.Manifest().Source.Language))
	if err := os.WriteFile(wim, b, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := fileIdentity(context.Background(), wim)
	if err != nil {
		t.Fatal(err)
	}
	custom := service.CustomizedImages{PlanDigest: c.Digest, WIMPath: wim, Images: []service.ImageIdentity{{Index: 1, Edition: c.Editions[0], Architecture: c.Source.Architecture, Language: c.Source.Language}}, Observations: []service.CustomizationObservation{{Edition: c.Editions[0]}}, Outputs: []jobstore.OutputIdentity{{Path: "customized.wim", Size: f.Size, SHA256: f.SHA256, Role: "customized-install-image"}}}
	return ExportRequest{Plan: p, Customized: custom, Directory: filepath.Join(t.TempDir(), "exported")}, fixtureExporter{edition: c.Editions[0]}
}
func TestExportRejectsHelperSuccessWithoutFilesAndWrongEdition(t *testing.T) {
	for _, kind := range []string{"missing", "wrong-edition", "changed-input", "wrong-plan"} {
		t.Run(kind, func(t *testing.T) {
			req, backend := exportFixture(t)
			switch kind {
			case "missing":
				backend.missing = true
			case "wrong-edition":
				backend.edition = "Enterprise"
			case "changed-input":
				if err := os.WriteFile(req.Customized.WIMPath, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-plan":
				req.Customized.PlanDigest = strings.Repeat("b", 64)
			}
			if _, err := Prepare(context.Background(), req, backend); err == nil {
				t.Fatal("unverified export accepted")
			}
		})
	}
}

func TestExportReadsBackConfiguredImage(t *testing.T) {
	req, backend := exportFixture(t)
	got, err := Prepare(context.Background(), req, backend)
	if err != nil {
		t.Fatal(err)
	}
	if got.PlanDigest != req.Plan.Digest() || len(got.Files) != 1 || got.Images[0].Edition != req.Customized.Images[0].Edition {
		t.Fatalf("wrong export %+v", got)
	}
}
func TestCustomizedSourceEditionAndAppMismatchFail(t *testing.T) {
	req, _ := exportFixture(t)
	p := *req.Plan.CustomizationPlan()
	if err := validateCustomized(p, req.Customized); err != nil {
		t.Fatal(err)
	}
	p.Source.Language = "fr-fr"
	if err := validateCustomized(p, req.Customized); err == nil {
		t.Fatal("source language mismatch accepted")
	}
	p = *req.Plan.CustomizationPlan()
	p.Apps.Provision = []planner.AppProvision{{Package: metadata.AppPackage{Identity: metadata.AppIdentity{Name: "Required.App", Version: "1.0.0.0", Architecture: "amd64", Publisher: "CN=Test"}}}}
	if err := validateCustomized(p, req.Customized); err == nil {
		t.Fatal("absent configured app accepted")
	}
}
func TestPublishedCapabilityRechecksDestinationAndPlan(t *testing.T) {
	v := publicationFixture(t)
	p, err := PublishVerified(context.Background(), v, t.TempDir(), "Windows.iso")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Artifact(context.Background(), strings.Repeat("b", 64), v.state.source); err == nil {
		t.Fatal("foreign plan accepted")
	}
	a, err := p.Artifact(context.Background(), v.state.planDigest, v.state.source)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(a.Path, []byte("changed destination"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Artifact(context.Background(), v.state.planDigest, v.state.source); err == nil {
		t.Fatal("changed destination completed")
	}
}

func TestFrozenExplicitVolumeLabelCannotChange(t *testing.T) {
	p := outputPlan(t)
	if err := validateVolume(p, "OTHER_LABEL"); err == nil {
		t.Fatal("explicit configured label replaced")
	}
	if err := validateVolume(p, "U10_SYNTHETIC"); err != nil {
		t.Fatal(err)
	}
}
