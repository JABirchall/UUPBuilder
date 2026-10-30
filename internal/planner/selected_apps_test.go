package planner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"uupbuilder/internal/config"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/providers"
	"uupbuilder/internal/model"
	"uupbuilder/internal/source"
)

// This verifies the actual saved requests against acquired Microsoft manifests
// and the catalog's retained CompDB digest. It does not service an image.
func TestSelectedAppPoliciesFromActualManifests(t *testing.T) {
	dir := os.Getenv("UUP_BUILDER_U09_PLAN_WORKSPACE")
	if dir == "" {
		t.Skip("set UUP_BUILDER_U09_PLAN_WORKSPACE to prepared selected-source data")
	}
	read := func(name string, target any) {
		t.Helper()
		data, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(data, target); e != nil {
			t.Fatal(e)
		}
	}
	var receipt struct {
		Manifest model.PayloadManifest
		Files    []struct {
			Path     string
			Identity model.PayloadIdentity
		}
	}
	read("prepared-selected-apps.json", &receipt)
	var catalog source.AppCatalogSnapshot
	read("selected-app-catalog.json", &catalog)
	payloads := append([]model.Payload(nil), receipt.Manifest.Payloads...)
	for _, p := range catalog.AppManifest.Payloads {
		if p.Identity == catalog.CAB {
			payloads = append(payloads, p)
		}
	}
	manifest, e := model.NewPayloadManifest(catalog.SelectedSource, payloads)
	if e != nil {
		t.Fatal(e)
	}
	request := metadata.InspectRequest{Source: manifest.Source, Manifest: manifest}
	for _, file := range receipt.Files {
		request.Inspections = append(request.Inspections, metadata.Inspection{Resource: metadata.LocalResource{Identity: file.Identity, Path: file.Path}, Provider: providers.Appx{}})
	}
	inv, e := metadata.Inspect(context.Background(), request)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "source-metadata/apps/desktoptargetcompdb_app_neutral.xml.cab"))
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	var sourceDoc metadata.DocumentReference
	for _, d := range catalog.Documents {
		if d.SHA256 == hex.EncodeToString(sum[:]) {
			sourceDoc = d
		}
	}
	if sourceDoc.SHA256 == "" {
		t.Fatal("actual app CompDB bytes do not match retained source document")
	}
	inv.Documents = append(inv.Documents, metadata.Document{Reference: sourceDoc, Format: metadata.FormatCompositionXML, Original: raw, Provenance: "retained verified source catalog CompDB"})
	inv, e = metadata.BindAppPolicies(context.Background(), inv, sourceDoc)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := config.Load(filepath.Join(dir, "iso-settings.toml"))
	if e != nil {
		t.Fatal(e)
	}
	_, settings, e := cfg.Request()
	if e != nil {
		t.Fatal(e)
	}
	plan, e := PlanApps(inv, settings.Apps)
	if e != nil {
		t.Fatal(e)
	}
	if plan.Deferred || !reflect.DeepEqual(plan.Requested, settings.Apps) || len(plan.Provision) < len(settings.Apps.Include) {
		t.Fatalf("selected requests not resolved unchanged: %+v", plan)
	}
	roots, frameworks, externals := 0, 0, 0
	for _, op := range plan.Provision {
		if op.Package.Framework {
			frameworks++
		} else {
			roots++
			if op.Stub != model.AppStub {
				t.Fatal("saved stub preference changed")
			}
		}
		externals += len(op.External)
		if !op.SkipLicense && len(op.LicenseXML) == 0 {
			t.Fatal("embedded source license was not materialized")
		}
	}
	t.Logf("saved requests unchanged: %d requested apps, %d framework operations, %d declared external bundle files; actual native provisioning/stub acceptance pending", roots, frameworks, externals)
}
