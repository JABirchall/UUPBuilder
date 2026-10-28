//go:build windows

package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// Fixtures are synthetic orchestration evidence; the real static M1 Inspector
// verifies their bytes and assertions. They are not live conversion evidence.
type fixtureCatalog struct {
	sets     map[string]catalog.FileSet
	editions []catalog.Edition
	calls    []string
	err      error
}

func (c *fixtureCatalog) Files(_ context.Context, id, language, edition string) (catalog.FileSet, error) {
	c.calls = append(c.calls, edition)
	if id != sourceIdentity().UpdateID || language != "en-us" {
		return catalog.FileSet{}, errors.New("incorrect frozen query")
	}
	if c.err != nil {
		return catalog.FileSet{}, c.err
	}
	s, ok := c.sets[edition]
	if !ok {
		return catalog.FileSet{}, &catalog.APIError{Code: "UNSUPPORTED_COMBINATION"}
	}
	return s, nil
}
func (c *fixtureCatalog) Editions(context.Context, string, string) ([]catalog.Edition, error) {
	return c.editions, nil
}

type fixtureFetcher struct {
	paths map[model.PayloadIdentity]string
}

func (f fixtureFetcher) FetchOne(_ context.Context, p model.Payload, _ download.Locator, _ model.Emit) (download.CachedFile, error) {
	path, ok := f.paths[p.Identity]
	if !ok {
		return download.CachedFile{}, errors.New("attempt to materialize undesignated large payload")
	}
	return download.CachedFile{Path: path, Identity: p.Identity, SHA256: p.Identity.Digest.Value}, nil
}

type fixtureProvider struct{ result metadata.ProviderResult }

func (p fixtureProvider) Inspect(context.Context, metadata.LocalResource, metadata.Limits) (metadata.ProviderResult, error) {
	return p.result, nil
}
func selectionAndSettings(t *testing.T) (model.Selection, model.ResolvedSettings) {
	t.Helper()
	c := config.Defaults()
	c.Image = model.Selection{UpdateID: sourceIdentity().UpdateID, Architecture: "arm64", Language: "en-us", Editions: []string{"DERIVED"}}
	s, settings, err := c.Request()
	if err != nil {
		t.Fatal(err)
	}
	return s, settings
}
func bootstrap(t *testing.T, text string) (MetadataPlan, fixtureFetcher, metadata.Evidence) {
	t.Helper()
	sum := sha256.Sum256([]byte(text))
	p := sourcePayload("opaque.bin", "a")
	p.Identity.Digest.Value = hex.EncodeToString(sum[:])
	p.Identity.Size = int64(len(text))
	path := filepath.Join(t.TempDir(), "opaque.bin")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	e := metadata.Evidence{Source: sourceIdentity(), Document: metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: p.Identity}, SHA256: p.Identity.Digest.Value}, Selector: "/WIM"}
	return MetadataPlan{Source: sourceIdentity(), Sets: []SourceSet{{Query: query("METADATA"), Files: sourceSet(p)}}, Inputs: []MetadataInput{{Identity: p.Identity, Format: metadata.FormatWIMXML}}}, fixtureFetcher{map[model.PayloadIdentity]string{p.Identity: path}}, e
}
func configuredResolver(t *testing.T) (*Resolver, *fixtureCatalog) {
	t.Helper()
	plan, fetcher, e := bootstrap(t, `<WIM><IMAGE INDEX="8"><WINDOWS><ARCH>12</ARCH><EDITIONID>CORE</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`)
	plan.Inputs[0].Provider = fixtureProvider{metadata.ProviderResult{Layouts: []metadata.LayoutEvidence{{Kind: metadata.LayoutFullMedia, Family: "synthetic-full", Evidence: e}}, EditionBases: []metadata.EditionBase{{Edition: "DERIVED", Base: "CORE", Evidence: e}}}}
	c := &fixtureCatalog{sets: map[string]catalog.FileSet{"CORE": sourceSet(sourcePayload("large.esd", "d"))}, editions: []catalog.Edition{{ID: "CORE"}}}
	return &Resolver{Catalog: c, Fetcher: fetcher, Discover: func(context.Context, model.Selection) (MetadataPlan, error) { return plan, nil }}, c
}

// Fetching final derived editions instead of semantic bases fails here.
func TestResolveUsesSemanticBasesAndSmallMetadataFirst(t *testing.T) {
	r, c := configuredResolver(t)
	s, settings := selectionAndSettings(t)
	got, err := r.Resolve(context.Background(), s, settings)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.calls, []string{"CORE"}) || len(got.Manifest.Payloads) != 2 || len(got.Inventory.Images) != 1 || !reflect.DeepEqual(got.Selection.Editions, []string{"DERIVED"}) {
		t.Fatalf("resolution lost semantic bases: calls=%v inventory=%d", c.calls, len(got.Inventory.Images))
	}
	if got.Manifest.Source.UpdateID != sourceIdentity().UpdateID || got.Manifest.Validate() != nil {
		t.Fatal("exact revision or frozen manifest lost")
	}
}

func TestUnavailablePayloadKeepsSourceUnavailableClassification(t *testing.T) {
	r, c := configuredResolver(t)
	c.err = &catalog.APIError{Code: "MISSING_FILES"}
	s, settings := selectionAndSettings(t)
	got, err := r.Resolve(context.Background(), s, settings)
	if !errors.Is(err, ErrPayloadUnavailable) || got.Classification != metadata.ClassificationSourceUnavailable || !reflect.DeepEqual(got.Selection, s) || !reflect.DeepEqual(got.Settings, settings) {
		t.Fatalf("unavailability misclassified: %q %v", got.Classification, err)
	}
}

// An update removed upstream must retain the unavailable classification and its
// safe API diagnosis whether absence is found in discovery or payload lookup.
func TestUnknownUpdateResolutionIsSourceUnavailable(t *testing.T) {
	for _, stage := range []string{"discovery", "payloads"} {
		t.Run(stage, func(t *testing.T) {
			r, c := configuredResolver(t)
			upstream := &catalog.APIError{Endpoint: "get.php", StatusCode: 404, Code: "UNKNOWN_UPDATE"}
			if stage == "discovery" {
				r.Discover = func(context.Context, model.Selection) (MetadataPlan, error) { return MetadataPlan{}, upstream }
			} else {
				c.err = upstream
			}
			s, settings := selectionAndSettings(t)
			got, err := r.Resolve(context.Background(), s, settings)
			var api *catalog.APIError
			if !errors.Is(err, ErrPayloadUnavailable) || got.Classification != metadata.ClassificationSourceUnavailable || !hasDiagnostic(got, "payload-unavailable") {
				t.Fatalf("missing update not classified unavailable: classification=%q diagnostics=%v err=%v", got.Classification, got.Diagnostics, err)
			}
			if !errors.As(err, &api) || api.Code != "UNKNOWN_UPDATE" || api.StatusCode != 404 || api.Endpoint != "get.php" {
				t.Fatalf("safe missing-update diagnosis lost: %v", err)
			}
			if !reflect.DeepEqual(got.Selection, s) || !reflect.DeepEqual(got.Settings, settings) {
				t.Fatal("missing update discarded target choices or explicit settings")
			}
		})
	}
}

func TestUnknownUpdateRefreshIsPayloadUnavailable(t *testing.T) {
	p := sourcePayload("a.esd", "a")
	frozen := manifestFor(t, p)
	r := &Resolver{Catalog: &fixtureCatalog{err: &catalog.APIError{Endpoint: "get.php", StatusCode: 404, Code: "UNKNOWN_UPDATE"}}}
	locators, err := r.RefreshLinks(context.Background(), frozen)
	var api *catalog.APIError
	if !errors.Is(err, ErrPayloadUnavailable) || locators != nil {
		t.Fatalf("missing update refresh not unavailable: %v", err)
	}
	if !errors.As(err, &api) || api.Code != "UNKNOWN_UPDATE" || api.StatusCode != 404 || api.Endpoint != "get.php" {
		t.Fatalf("safe missing-update diagnosis lost: %v", err)
	}
	if frozen.Validate() != nil {
		t.Fatal("failed refresh mutated frozen source identity")
	}
}

func TestUnknownLayoutRetainsTargetChoice(t *testing.T) {
	s, settings := selectionAndSettings(t)
	s.Architecture = "future128"
	settings.Apps.Include = []string{"Explicit.Family_123"}
	settings.Apps.Mode = model.AppsCustom
	got, err := (&Resolver{}).Resolve(context.Background(), s, settings)
	if err != nil || got.Classification != metadata.ClassificationImplementationGap || !reflect.DeepEqual(got.Selection, s) || !reflect.DeepEqual(got.Settings, settings) || len(got.Diagnostics) == 0 || got.Diagnostics[0].Code != "metadata-discovery-unavailable" {
		t.Fatalf("target or explicit settings discarded: %q %v", got.Classification, err)
	}
	s.Editions[0] = "mutated"
	settings.Apps.Include[0] = "mutated"
	if got.Selection.Editions[0] != "DERIVED" || got.Settings.Apps.Include[0] != "Explicit.Family_123" {
		t.Fatal("resolution aliases mutable request")
	}
}

// Advertised app selectors cannot establish family names or customization phase.
func TestAppSourcesDoNotInventFamilies(t *testing.T) {
	r, c := configuredResolver(t)
	c.editions = append(c.editions, catalog.Edition{ID: "APP"}, catalog.Edition{ID: "APP_MOMENT"})
	c.sets["APP"] = sourceSet(sourcePayload("LooksLike.A.Family.appx", "e"))
	s, settings := selectionAndSettings(t)
	settings.Apps.Mode = model.AppsCustom
	settings.Apps.Include = []string{"Explicit.Family_123"}
	got, err := r.Resolve(context.Background(), s, settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Inventory.Apps.Packages) != 0 || got.AppPhase != metadata.PhaseUnknown || !reflect.DeepEqual(got.Settings.Apps.Include, settings.Apps.Include) || !reflect.DeepEqual(c.calls, []string{"CORE", "APP"}) {
		t.Fatalf("invented app inventory or queried unadvertised/duplicate sources: %v", c.calls)
	}
	if !hasDiagnostic(got, "app-metadata-discovery-unavailable") {
		t.Fatal("missing concrete app producer gap")
	}
}

func hasDiagnostic(res Resolution, code string) bool {
	for _, d := range res.Diagnostics {
		if d.Code == code {
			return true
		}
	}
	return false
}

func TestAppsUseActualM1InventoryAndLegacyPhaseEvidence(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "separate-apps", true: "legacy"}[legacy], func(t *testing.T) {
			r, _ := configuredResolver(t)
			s, settings := selectionAndSettings(t)
			appPlan, fetcher, e := bootstrap(t, `<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Actual.Name" Publisher="CN=Actual Publisher" Version="1.2.3.4" ProcessorArchitecture="arm64"/></Package>`)
			appPlan.Sets[0].Query = query("APPMETADATA")
			appPlan.Sets[0].Files.Payloads[0].Destination = "app-manifest.bin"
			appPlan.Inputs[0].Format = metadata.FormatAppxXML
			oldDiscover := r.Discover
			r.Discover = func(ctx context.Context, s model.Selection) (MetadataPlan, error) {
				p, err := oldDiscover(ctx, s)
				if err != nil {
					return p, err
				}
				p.Sets = append(p.Sets, appPlan.Sets...)
				return p, nil
			}
			baseFetcher := r.Fetcher.(fixtureFetcher)
			for k, v := range fetcher.paths {
				baseFetcher.paths[k] = v
			}
			r.Fetcher = baseFetcher
			r.DiscoverApps = func(_ context.Context, _ model.Selection, inv metadata.Inventory, _ []SourceSet) (AppDiscovery, error) {
				if legacy {
					return AppDiscovery{Phase: metadata.PhasePostAssembly, Evidence: &inv.Images[0].Evidence}, nil
				}
				input := appPlan.Inputs[0]
				input.Provider = fixtureProvider{metadata.ProviderResult{AppPhases: []metadata.AppPhaseEvidence{{Family: metadata.AppFamily{Name: "Actual.Name", Publisher: "CN=Actual Publisher"}, Phase: metadata.PhaseOfflineProvisioning, Evidence: e}}}}
				return AppDiscovery{Inputs: []MetadataInput{input}}, nil
			}
			got, err := r.Resolve(context.Background(), s, settings)
			if err != nil {
				t.Fatal(err)
			}
			if legacy {
				if got.AppPhase != metadata.PhasePostAssembly || !hasDiagnostic(got, "apps-require-materialized-inspection") {
					t.Fatal("legacy discovery requirement lost")
				}
				return
			}
			if len(got.Inventory.Apps.Packages) != 1 || got.Inventory.Apps.Packages[0].Family.Name != "Actual.Name" || got.AppPhase != metadata.PhaseOfflineProvisioning {
				t.Fatal("actual Appx semantics not retained")
			}
		})
	}
}

// Restart refresh replays only frozen queries, without discovery or edition enumeration.
func TestRefreshLinksReplaysFrozenQueriesAndRejectsDrift(t *testing.T) {
	p := sourcePayload("a.esd", "a")
	frozen := manifestFor(t, p)
	set := sourceSet(p)
	set.Locators[p.Identity] = model.Locator{URL: "https://example.invalid/runtime"}
	c := &fixtureCatalog{sets: map[string]catalog.FileSet{"CORE": set}}
	r := &Resolver{Catalog: c}
	locs, err := r.RefreshLinks(context.Background(), frozen)
	if err != nil || len(locs) != 1 || !reflect.DeepEqual(c.calls, []string{"CORE"}) {
		t.Fatalf("restart refresh failed: %v", err)
	}
	set.Payloads[0].Identity.Digest.Value = strings.Repeat("b", 64)
	set.Locators = model.Locators{set.Payloads[0].Identity: {URL: "https://example.invalid/runtime"}}
	c.sets["CORE"] = set
	if _, err := r.RefreshLinks(context.Background(), frozen); !errors.Is(err, ErrInputIdentityChanged) {
		t.Fatalf("refresh accepted changed bytes: %v", err)
	}
	c.err = &catalog.APIError{Code: "MISSING_FILES"}
	if _, err := r.RefreshLinks(context.Background(), frozen); !errors.Is(err, ErrPayloadUnavailable) {
		t.Fatalf("upstream missing payload classification: %v", err)
	}
}

func TestCatalogErrorsRetainSafeCodeWithoutLeakingURL(t *testing.T) {
	r, c := configuredResolver(t)
	s, settings := selectionAndSettings(t)
	c.err = &catalog.APIError{Endpoint: "get.php", StatusCode: 500, Code: "WU_REQUEST_FAILED"}
	_, err := r.Resolve(context.Background(), s, settings)
	var api *catalog.APIError
	if !errors.As(err, &api) || api.Code != "WU_REQUEST_FAILED" || api.StatusCode != 500 {
		t.Fatalf("safe upstream diagnosis lost: %v", err)
	}
	c.err = errors.New("https://example.invalid/?signature=secret")
	_, err = r.Resolve(context.Background(), s, settings)
	if err == nil || strings.Contains(err.Error(), "signature") || strings.Contains(err.Error(), "https:") {
		t.Fatal("provider URL leaked")
	}
	c.err = &catalog.APIError{Endpoint: "get.php", StatusCode: 400, Code: "UNSUPPORTED_COMBINATION"}
	_, err = r.Resolve(context.Background(), s, settings)
	if !errors.Is(err, ErrPayloadUnavailable) || !errors.As(err, &api) || api.Code != "UNSUPPORTED_COMBINATION" {
		t.Fatalf("upstream unavailable code lost: %v", err)
	}
}

// An installed discovery adapter may still lack the provider needed for this
// layout; that error must become an actionable implementation-gap diagnostic.
func TestUnavailableDiscoveryProviderHasConcreteDiagnostic(t *testing.T) {
	s, settings := selectionAndSettings(t)
	r := &Resolver{Discover: func(context.Context, model.Selection) (MetadataPlan, error) {
		return MetadataPlan{}, ErrImplementationGap
	}}
	got, err := r.Resolve(context.Background(), s, settings)
	if !errors.Is(err, ErrImplementationGap) || got.Classification != metadata.ClassificationImplementationGap || !hasDiagnostic(got, "producer-unavailable") || !reflect.DeepEqual(got.Selection, s) {
		t.Fatalf("missing producer diagnosis: %+v %v", got.Diagnostics, err)
	}
}

func TestSourceAbsenceEvidenceSurvivesImplementationGaps(t *testing.T) {
	r, _ := configuredResolver(t)
	old := r.Discover
	r.Discover = func(ctx context.Context, s model.Selection) (MetadataPlan, error) {
		plan, err := old(ctx, s)
		if err != nil {
			return plan, err
		}
		provider := plan.Inputs[0].Provider.(fixtureProvider)
		provider.result.Absences = []metadata.AbsenceEvidence{{Role: metadata.RoleSetup, Reason: "Synthetic inspected source has no setup content", Evidence: provider.result.Layouts[0].Evidence}}
		plan.Inputs[0].Provider = provider
		return plan, nil
	}
	s, settings := selectionAndSettings(t)
	got, err := r.Resolve(context.Background(), s, settings)
	if err != nil || got.Classification != metadata.ClassificationSourceUnavailable || got.Inventory.Classification != metadata.ClassificationSourceUnavailable || len(got.Manifest.Payloads) != 2 || !hasDiagnostic(got, "app-metadata-discovery-unavailable") {
		t.Fatalf("upstream absence was overwritten by a code gap: %q %v", got.Classification, err)
	}
}

func TestInspectionRejectsTamperedMaterializedMetadata(t *testing.T) {
	r, _ := configuredResolver(t)
	fetcher := r.Fetcher.(fixtureFetcher)
	for _, path := range fetcher.paths {
		if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, settings := selectionAndSettings(t)
	_, err := r.Resolve(context.Background(), s, settings)
	if !errors.Is(err, metadata.ErrIntegrity) {
		t.Fatalf("unverified metadata reached semantic planning: %v", err)
	}
}
