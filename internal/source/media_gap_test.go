package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// App-inventory/license/phase gaps must still inspect the selected app closure;
// only the explicit non-app media gap set permits default preflight deferral.
func TestMediaGapDeferralStillInspectsAppsWhenMediaGapsAreAbsent(t *testing.T) {
	r, c := configuredResolver(t)
	prior := r.Discover
	r.Discover = func(ctx context.Context, selection model.Selection) (MetadataPlan, error) {
		plan, err := prior(ctx, selection)
		provider := plan.Inputs[0].Provider.(fixtureProvider)
		e := provider.result.Layouts[0].Evidence
		provider.result.Roles = []metadata.RoleEvidence{{Role: metadata.RoleSetup, Resource: e.Document.Resource, Evidence: e}}
		provider.result.Absences = []metadata.AbsenceEvidence{{Role: metadata.RoleWinRE, Reason: "Synthetic fixture has no recovery image", Evidence: e}}
		plan.Inputs[0].Provider = provider
		return plan, err
	}
	text := []byte(`<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Example.App" Publisher="CN=Example" Version="1.0.0.0" ProcessorArchitecture="arm64"/></Package>`)
	sum := sha256.Sum256(text)
	p := sourcePayload("unexamined.appx", "e")
	p.Identity.Size = int64(len(text))
	p.Identity.Digest.Value = hex.EncodeToString(sum[:])
	path := filepath.Join(t.TempDir(), "app-manifest.xml")
	if err := os.WriteFile(path, text, 0600); err != nil {
		t.Fatal(err)
	}
	r.Fetcher.(fixtureFetcher).paths[p.Identity] = path
	c.editions = append(c.editions, catalog.Edition{ID: "APP"})
	c.sets["APP"] = sourceSet(p)
	r.DiscoverApps = func(_ context.Context, _ model.Selection, _ metadata.Inventory, sets []SourceSet) (AppDiscovery, error) {
		if len(sets) != 1 || !reflect.DeepEqual(sets[0].Files.Payloads, []model.Payload{p}) {
			t.Fatal("selected app closure changed")
		}
		return AppDiscovery{Inputs: []MetadataInput{{Identity: p.Identity, Format: metadata.FormatAppxXML}}}, nil
	}
	r.DeferAppsOnMediaGaps = true
	s, settings := selectionAndSettings(t)
	got, err := r.Resolve(context.Background(), s, settings)
	if err != nil || len(got.Inventory.Apps.Packages) != 1 || got.Inventory.Apps.Packages[0].Family.Name != "Example.App" || len(got.Manifest.Payloads) != 3 || hasDiagnostic(got, "app-inspection-unexamined") {
		t.Fatalf("app closure skipped without fatal media gaps: packages=%d manifest=%d diagnostics=%v err=%v", len(got.Inventory.Apps.Packages), len(got.Manifest.Payloads), got.Diagnostics, err)
	}
}

func TestMediaGapDeferralRetainsBoundEvidenceAndUnexaminedRequests(t *testing.T) {
	for _, code := range []string{"unsupported-schema", "unsupported-format", "role-unresolved", "layout-unresolved"} {
		t.Run(code, func(t *testing.T) {
			text := `<WIM><IMAGE INDEX="8"><WINDOWS><ARCH>12</ARCH><EDITIONID>CORE</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`
			if code == "unsupported-schema" {
				text = `<FutureComposition/>`
			}
			plan, fetcher, e := bootstrap(t, text)
			if code == "unsupported-schema" {
				plan.Inputs[0].Format = metadata.FormatCompositionXML
			}
			if code == "unsupported-format" {
				plan.Inputs[0].Format = metadata.Format("future-format")
			}
			provider := fixtureProvider{result: metadata.ProviderResult{EditionBases: []metadata.EditionBase{{Edition: "DERIVED", Base: "CORE", Evidence: e}}}}
			if code != "layout-unresolved" {
				provider.result.Layouts = []metadata.LayoutEvidence{{Kind: metadata.LayoutFullMedia, Family: "synthetic-full", Evidence: e}}
			}
			if code != "role-unresolved" {
				provider.result.Roles = []metadata.RoleEvidence{{Role: metadata.RoleSetup, Resource: e.Document.Resource, Evidence: e}}
				provider.result.Absences = []metadata.AbsenceEvidence{{Role: metadata.RoleWinRE, Reason: "Synthetic fixture has no recovery image", Evidence: e}}
			}
			plan.Inputs[0].Provider = provider
			c := &fixtureCatalog{sets: map[string]catalog.FileSet{}, editions: []catalog.Edition{{ID: "CORE"}, {ID: "APP"}}}
			r := &Resolver{Catalog: c, Fetcher: fetcher, DeferAppsOnMediaGaps: true, Discover: func(context.Context, model.Selection) (MetadataPlan, error) { return plan, nil }}
			s, settings := selectionAndSettings(t)
			settings.Apps.Mode = model.AppsCustom
			settings.Apps.Include = []string{"Requested.Family_123"}
			got, err := r.Resolve(context.Background(), s, settings)
			if err != nil || !hasDiagnostic(got, "metadata-"+code) || !hasDiagnostic(got, "app-inspection-unexamined") || got.AppPhase != metadata.PhaseUnknown || !reflect.DeepEqual(got.Settings.Apps, settings.Apps) || got.Manifest.Validate() != nil || got.Inventory.Manifest.Digest != got.Manifest.Digest || len(got.Inventory.Documents) != 1 || got.Inventory.Documents[0].Reference != e.Document || len(c.calls) != 0 {
				t.Fatalf("blocked preflight lost exact evidence or examined app closure: %+v %v", got.Diagnostics, err)
			}
		})
	}
}
