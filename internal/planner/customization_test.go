package planner

import (
	"reflect"
	"testing"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

func appPlanFixture(t *testing.T) (metadata.Inventory, model.AppSettings) {
	t.Helper()
	_, req := fixture(t)
	inv := req.Resolution.Inventory
	ref := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: inv.Manifest.Payloads[0].Identity}, SHA256: hash("manifest")}
	inv.Documents = []metadata.Document{{Reference: ref}}
	evidence := metadata.Evidence{Source: inv.Source, Document: ref, Selector: "/Package/Identity"}
	framework := metadata.AppPackage{Identity: metadata.AppIdentity{Name: "Framework", Publisher: "CN=Publisher", Version: "2.0.0.0", Architecture: "neutral"}, Family: metadata.AppFamily{Name: "Framework", Publisher: "CN=Publisher"}, Framework: true, Phase: metadata.PhaseOfflineProvisioning, Evidence: evidence}
	app := framework
	app.Identity.Name = "Actual.App"
	app.Family.Name = "Actual.App"
	app.Framework = false
	app.Dependencies = []metadata.AppDependency{{Family: framework.Family, MinVersion: "2.0.0.0"}}
	inv.Apps.Packages = []metadata.AppPackage{app, framework}
	inv.Apps.SelectionRules = []metadata.AppSelectionRule{{ID: "Source.Feature", Family: app.Family, Default: true, LicenseFree: true, StubSupported: true, Evidence: evidence}, {ID: "Framework", Family: framework.Family, LicenseFree: true, Evidence: evidence}}
	return inv, model.AppSettings{Mode: model.AppsCustom, Include: []string{"Source.Feature"}, StubPolicy: model.AppStub, Edge: model.EdgeDefault}
}
func TestAppPlanResolvesRequestedIDsAndDependencyOrder(t *testing.T) {
	inv, settings := appPlanFixture(t)
	plan, err := PlanApps(inv, settings)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Deferred || !reflect.DeepEqual(plan.Requested, settings) || len(plan.Provision) != 2 || plan.Provision[0].Package.Identity.Name != "Framework" || plan.Provision[1].Package.Identity.Name != "Actual.App" || plan.Provision[1].Stub != model.AppStub {
		t.Fatalf("wrong concrete app plan: %+v", plan)
	}
	settings.Include = []string{"Missing"}
	if _, err = PlanApps(inv, settings); err == nil {
		t.Fatal("missing requested ID accepted")
	}
	inv.Apps.Packages[1].Identity.Version = "1.0.0.0"
	settings.Include = []string{"Source.Feature"}
	if _, err = PlanApps(inv, settings); err == nil {
		t.Fatal("unsatisfied framework version accepted")
	}
}
func TestAppPoliciesAndDeferredBarrier(t *testing.T) {
	inv, settings := appPlanFixture(t)
	for _, mode := range []model.AppMode{model.AppsDefault, model.AppsCustom, model.AppsNone} {
		settings.Mode = mode
		p, e := PlanApps(inv, settings)
		if e != nil {
			t.Fatal(e)
		}
		if mode == model.AppsNone && (len(p.Provision) != 0 || len(p.Remove) != 1) {
			t.Fatalf("none policy: %+v", p)
		}
	}
	settings.Mode = model.AppsCustom
	settings.Preset = "all-offered"
	settings.StubPolicy = model.AppFull
	p, e := PlanApps(inv, settings)
	if e != nil || p.Provision[1].Stub != model.AppFull {
		t.Fatalf("materialized preset/full: %+v %v", p, e)
	}
	settings.Edge = model.EdgeExclude
	if _, e = PlanApps(inv, settings); e == nil {
		t.Fatal("unsupported Edge exclusion accepted")
	}
	settings.Edge = model.EdgeDefault
	inv.Apps.Packages = nil
	p, e = PlanApps(inv, settings)
	if e != nil || !p.Deferred || !reflect.DeepEqual(p.Requested, settings) {
		t.Fatalf("unknown apps not deferred unchanged: %+v %v", p, e)
	}
}
func TestAppLicenseMustBeOfflineAndLinked(t *testing.T) {
	inv, settings := appPlanFixture(t)
	inv.Apps.SelectionRules[0].LicenseFree = false
	if _, e := PlanApps(inv, settings); e == nil {
		t.Fatal("missing license accepted")
	}
	license := metadata.LicenseEvidence{Family: inv.Apps.Packages[0].Family, Resource: inv.Documents[0].Reference.Resource, Evidence: inv.Apps.Packages[0].Evidence}
	inv.Apps.Packages[0].Licenses = []metadata.LicenseEvidence{license}
	inv.Apps.LicenseDocuments = []metadata.AppLicense{{PackageFamilyName: metadata.AppFamilyName(license.Family), Resource: license.Resource, Usage: "Online", BindingType: "Machine"}}
	if _, e := PlanApps(inv, settings); e == nil {
		t.Fatal("online license accepted for offline provisioning")
	}
	inv.Apps.LicenseDocuments[0].Usage = "Offline"
	if _, e := PlanApps(inv, settings); e != nil {
		t.Fatal(e)
	}
}
func TestFeatureAndDriverTargets(t *testing.T) {
	inv, _ := appPlanFixture(t)
	inv.Packages = []metadata.Package{{Identity: metadata.PackageIdentity{Name: "Microsoft-Windows-NetFx3-OnDemand-Package", Architecture: inv.Source.Architecture}, Evidence: inv.Apps.Packages[0].Evidence}}
	features, e := PlanFeatures(inv, model.ConversionSettings{NetFX3: true})
	if e != nil || len(features) != 1 || features[0].Name != "NetFx3" {
		t.Fatalf("NetFx3: %+v %v", features, e)
	}
	drivers, e := PlanDrivers(inv, model.DriverSettings{Enabled: true, Source: "C:/drivers", Targets: []model.DriverTarget{model.DriverShared}})
	if e != nil || len(drivers) != 2 || drivers[0].Target != model.DriverOS || drivers[1].Target != model.DriverWinPE {
		t.Fatalf("driver separation: %+v %v", drivers, e)
	}
	if _, e = PlanDrivers(inv, model.DriverSettings{Targets: []model.DriverTarget{model.DriverWinRE}}); e == nil {
		t.Fatal("excluded recovery target accepted")
	}
}
