package rules

import (
	"strings"
	"testing"

	"uupbuilder/internal/config"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

func TestOrdinaryUpdatesOrderAfterCumulativeBeforeEnablement(t *testing.T) {
	source := model.SourceIdentity{UpdateID: "ordinary-update-fixture", BuildLabel: "12345.6", Architecture: "amd64", Language: "en-us"}
	payload := model.Payload{Destination: "opaque.cab", Identity: model.PayloadIdentity{Size: 1, Digest: model.Digest{Algorithm: model.DigestSHA256, Value: strings.Repeat("a", 64)}, Provenance: model.PackageProvenance{Source: "fixture", Name: "opaque.cab"}}}
	manifest, err := model.NewPayloadManifest(source, []model.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	inv := metadata.Inventory{Source: source, Manifest: manifest}
	for _, kind := range []metadata.UpdateKind{metadata.UpdateEnablement, metadata.UpdateKind("update"), metadata.UpdateCumulative, metadata.UpdateCheckpoint, metadata.UpdateServicingStack} {
		inv.Updates = append(inv.Updates, metadata.Update{ID: string(kind), Kind: kind, Format: metadata.UpdateCAB, Resource: metadata.ResourceReference{Payload: payload.Identity}, Packages: []metadata.PackageIdentity{{Name: "Package_for_" + string(kind), Version: "1.0.0.0", Architecture: "amd64", PublicKeyToken: "publisher"}}})
	}
	cfg := config.Defaults()
	cfg.Image.UpdateID = source.UpdateID
	_, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	generation := Generation{ID: "fixture", Checkpoint: true, OfflineMSU: true}
	got, err := OrderUpdates(inv, settings, generation)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, update := range got {
		kinds = append(kinds, string(update.Kind))
		if !update.Integrate {
			t.Fatal("ordinary integration policy lost")
		}
	}
	if strings.Join(kinds, ",") != "servicing-stack,checkpoint,cumulative,update,enablement" {
		t.Fatalf("ordinary update ordering:%v", kinds)
	}
	settings.Conversion.EnablementPackages = model.InclusionOmit
	settings.Conversion.Updates = model.UpdatesExternal
	got, err = OrderUpdates(inv, settings, generation)
	if err != nil {
		t.Fatal(err)
	}
	regular := false
	for _, update := range got {
		if update.Kind == metadata.UpdateKind("update") {
			regular = true
			if update.Integrate || !update.Retain {
				t.Fatal("ordinary external policy dropped")
			}
		}
		if update.Kind == metadata.UpdateEnablement {
			t.Fatal("omitted enablement retained")
		}
	}
	if !regular {
		t.Fatal("ordinary update incorrectly omitted with enablement")
	}
}

func TestUpdateScopeExcludesOnlyObservedWinREWithoutDroppingOSLookalikes(t *testing.T) {
	source := model.SourceIdentity{UpdateID: "scope-fixture", BuildLabel: "12345.1", Architecture: "amd64", Language: "en-us"}
	payload := model.Payload{Destination: "source.cab", Identity: model.PayloadIdentity{Size: 1, Digest: model.Digest{Algorithm: model.DigestSHA256, Value: strings.Repeat("b", 64)}, Provenance: model.PackageProvenance{Source: "fixture", Name: "source.cab"}}}
	m, err := model.NewPayloadManifest(source, []model.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	recovery := metadata.Update{ID: "recovery", Kind: metadata.UpdateRegular, Target: metadata.RoleWinRE, Format: metadata.UpdateCAB, Resource: metadata.ResourceReference{Payload: payload.Identity}, Packages: []metadata.PackageIdentity{{Name: "Package_for_SafeOSDU", Version: "1.0.0.0", Architecture: "amd64", PublicKeyToken: "publisher"}}, Predecessors: []string{"unexamined-recovery-base"}}
	osUpdate := recovery
	osUpdate.ID = "ordinary-lookalike"
	osUpdate.Target = metadata.RoleOS
	osUpdate.Packages = []metadata.PackageIdentity{{Name: "Package_for_SafeOSDU_Lookalike", Version: "1.0.0.0", Architecture: "amd64", PublicKeyToken: "publisher"}}
	osUpdate.Predecessors = nil
	inv := metadata.Inventory{Source: source, Manifest: m, Updates: []metadata.Update{recovery, osUpdate}}
	cfg := config.Defaults()
	cfg.Image.UpdateID = source.UpdateID
	_, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	settings.Conversion.IncludeWinRE = false
	settings.Conversion.WinREUpdates = model.InclusionOmit
	for _, policy := range []model.UpdatePolicy{model.UpdatesIntegrate, model.UpdatesExternal} {
		settings.Conversion.Updates = policy
		got, err := OrderUpdates(inv, settings, Generation{ID: "fixture", OfflineMSU: true})
		if err != nil || len(got) != 1 || got[0].ID != osUpdate.ID {
			t.Fatalf("scope filtering%q: %+v %v", policy, got, err)
		}
	}
	if len(inv.Updates) != 2 || inv.Updates[0].Target != metadata.RoleWinRE {
		t.Fatal("source fact removed")
	}
	if Applies(UpdatePlan{Update: recovery}, "Professional") {
		t.Fatal("WinRE update treated as OS edition applicable")
	}
	if !Applies(UpdatePlan{Update: osUpdate}, "Professional") {
		t.Fatal("ordinary OS lookalike silently dropped")
	}
	settings.Conversion.IncludeWinRE = true
	if _, err = OrderUpdates(inv, settings, Generation{ID: "fixture"}); err == nil {
		t.Fatal("requested excluded recovery servicing accepted")
	}
	settings.Conversion.IncludeWinRE = false
	settings.Conversion.WinREUpdates = model.InclusionAuto
	if _, err = OrderUpdates(inv, settings, Generation{ID: "fixture"}); err == nil {
		t.Fatal("ambiguous recovery policy silently omitted")
	}
	settings.Conversion.WinREUpdates = model.InclusionOmit
	inv.Updates[0].Target = "invalid"
	if _, err = OrderUpdates(inv, settings, Generation{ID: "fixture"}); err == nil {
		t.Fatal("malformed scope accepted")
	}
}
