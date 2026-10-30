package source

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

func mediaFixture(t *testing.T) (metadata.Inventory, model.Selection) {
	t.Helper()
	p := sourcePayload("professional_en-us.esd", "a")
	s := sourceSet(p).Source
	s.UpdateID = "26300-source-without-an-allowlist"
	s.Language = "en-us"
	s.Architecture = "amd64"
	m, err := model.NewPayloadManifest(s, []model.Payload{p})
	if err != nil {
		t.Fatal(err)
	}
	r := metadata.ResourceReference{Payload: p.Identity, Member: "wim.xml"}
	return metadata.Inventory{Source: s, Manifest: m, Images: []metadata.Image{
		{Resource: r, Index: 17, Name: "Windows Setup Media"},
		{Resource: r, Index: 5, InstallationType: "WindowsPE", Architecture: "amd64", Languages: []string{"en-US"}},
		{Resource: r, Index: 12, Edition: "Professional", InstallationType: "Client", Architecture: "amd64", Languages: []string{"en-US"}},
	}}, model.Selection{UpdateID: s.UpdateID, Architecture: s.Architecture, Language: s.Language, Editions: []string{"Professional"}}
}

func TestDetectMediaUsesSelectedSourceAndSemanticIndices(t *testing.T) {
	inv, selection := mediaFixture(t)
	got, err := DetectMedia(inv, selection)
	if err != nil || got.Payload != inv.Manifest.Payloads[0].Identity || got.OSIndex != 12 || got.MediaIndex != 17 || got.PEIndex != 5 {
		t.Fatalf("layout=%+v err=%v", got, err)
	}
	// XML candidate detection must not promote names or indices into content facts.
	if len(inv.Roles) != 0 || len(inv.Layouts) != 0 {
		t.Fatal("candidate detection asserted verified media")
	}
}

func TestDetectMediaRejectsAmbiguityMissingAndWrongTarget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*metadata.Inventory)
	}{
		{"missing-media", func(inv *metadata.Inventory) { inv.Images = inv.Images[1:] }},
		{"ambiguous-media", func(inv *metadata.Inventory) { im := inv.Images[0]; im.Index = 22; inv.Images = append(inv.Images, im) }},
		{"ambiguous-pe", func(inv *metadata.Inventory) { im := inv.Images[1]; im.Index = 23; inv.Images = append(inv.Images, im) }},
		{"wrong-language", func(inv *metadata.Inventory) { inv.Images[2].Languages = []string{"fr-fr"} }},
		{"wrong-architecture", func(inv *metadata.Inventory) { inv.Images[2].Architecture = "arm64" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv, s := mediaFixture(t)
			tc.change(&inv)
			if _, err := DetectMedia(inv, s); err == nil {
				t.Fatal("incomplete/ambiguous metadata accepted")
			}
		})
	}
}

func TestMediaEditionMappingsRetainActualBytesAndSourceBinding(t *testing.T) {
	inv, _ := mediaFixture(t)
	body := []byte(`<WindowsEditions><Edition virtual="true"><Name>Enterprise</Name><ParentEdition>Professional</ParentEdition></Edition><Edition virtual="true"><Name>Education</Name><ParentEdition>Professional</ParentEdition></Edition></WindowsEditions>`)
	if err := addMediaEditionMappings(context.Background(), &inv, inv.Images[2], body); err != nil {
		t.Fatal(err)
	}
	if len(inv.EditionBases) != 2 || len(inv.Documents) != 1 || string(inv.Documents[0].Original) != string(body) {
		t.Fatalf("lost original mapping: %+v", inv.EditionBases)
	}
	for _, base := range inv.EditionBases {
		if base.Evidence.Source != inv.Source || base.Evidence.Document != inv.Documents[0].Reference || !strings.Contains(base.Evidence.Selector, base.Edition) {
			t.Fatal("unbound edition mapping")
		}
	}
}

func TestMediaAppRequestsRespectDefaultCustomAndNone(t *testing.T) {
	s := AppCatalogSnapshot{Entries: []AppCatalogEntry{
		{FeatureID: "Default.App", Type: "MSIX", Media: []metadata.AppMediaHint{{Type: "CleanInstall", State: "INSTALLED"}}},
		{FeatureID: "Optional.App", Type: "MSIX", Media: []metadata.AppMediaHint{{Type: "CleanInstall", State: "STAGED"}}},
		{FeatureID: "Framework", Type: "MSIXFramework", Media: []metadata.AppMediaHint{{Type: "CleanInstall", State: "INSTALLED"}}},
	}}
	for _, tc := range []struct {
		settings model.AppSettings
		want     string
	}{{model.AppSettings{Mode: model.AppsDefault}, "Default.App"}, {model.AppSettings{Mode: model.AppsCustom, Include: []string{"Optional.App"}}, "Optional.App"}, {model.AppSettings{Mode: model.AppsNone}, ""}} {
		got, err := mediaAppRequests(s, tc.settings)
		if err != nil || strings.Join(got, ",") != tc.want {
			t.Fatalf("mode=%s got=%v err=%v", tc.settings.Mode, got, err)
		}
	}
	if _, err := mediaAppRequests(s, model.AppSettings{Mode: model.AppsCustom, Include: []string{"Unknown.App"}}); err == nil {
		t.Fatal("unknown request silently dropped")
	}
}

func TestMediaCBSRetainsPackageParentsFromActualContainerBytes(t *testing.T) {
	inv, _ := mediaFixture(t)
	archive := []byte("verified source container fixture")
	p := inv.Manifest.Payloads[0]
	sum := sha256.Sum256(archive)
	p.Identity.Size = int64(len(archive))
	p.Identity.Digest.Value = hex.EncodeToString(sum[:])
	p.Destination = "actual-update.cab"
	p.Identity.Provenance.Name = p.Destination
	m, err := model.NewPayloadManifest(inv.Source, []model.Payload{p})
	if err != nil {
		t.Fatal(err)
	}
	inv.Manifest = m
	file := filepath.Join(t.TempDir(), "actual-update.cab")
	if err = os.WriteFile(file, archive, 0600); err != nil {
		t.Fatal(err)
	}
	body := []byte(`<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"><assemblyIdentity name="Package_for_RollupFix" version="26300.9818.1.1" processorArchitecture="amd64" language="neutral" publicKeyToken="31bf3856ad364e35"/><package identifier="KB9999000" releaseType="Update"><parent><assemblyIdentity name="Microsoft-Windows-ProfessionalEdition" version="10.0.26300.1" processorArchitecture="amd64" language="neutral" publicKeyToken="31bf3856ad364e35"/></parent></package></assembly>`)
	r := mediaNativeRun{}
	if err = r.addCBS(context.Background(), &inv, p.Identity, file, []metadata.MetadataDocument{{Resource: metadata.ResourceReference{Payload: p.Identity, Member: "update.mum"}, Format: metadata.FormatCBSXML, Original: body, Provenance: "verified test container extraction"}}, false); err != nil {
		t.Fatal(err)
	}
	if len(inv.Packages) != 1 || len(inv.Packages[0].Dependencies) != 1 || inv.Packages[0].Dependencies[0].Identity.Name != "Microsoft-Windows-ProfessionalEdition" {
		t.Fatalf("CBS dependency observation lost: %+v", inv.Packages)
	}
	if len(inv.Updates) != 1 || inv.Updates[0].ID != "KB9999000" || inv.Updates[0].Resource.Payload != p.Identity || inv.Updates[0].Evidence.Document != inv.Packages[0].Evidence.Document || !strings.EqualFold(inv.Updates[0].Evidence.Document.Resource.Member, "update.mum") {
		t.Fatalf("unbound update: %+v", inv.Updates)
	}
}

func TestMediaOrdinaryCBSUpdatesKeepTheirActualReleaseKind(t *testing.T) {
	for _, release := range []string{"Update", "Security Update", "Critical Update", "Hotfix", "Software Update", "Update Rollup", "Service Pack"} {
		pack := metadata.Package{Identity: metadata.PackageIdentity{Name: "Package_for_OrdinaryFix", Version: "12345.6.1.0", Architecture: "amd64"}, Identifier: "Synthetic.Update", ReleaseType: release}
		kind, err := mediaUpdateKind(pack)
		if err != nil || kind != metadata.UpdateKind("update") {
			t.Fatalf("release%q classified%q: %v", release, kind, err)
		}
	}
	for _, release := range []string{"Feature Pack", "Language Pack", "Foundation", "OnDemand Pack", "Other", "FutureRelease"} {
		if kind, err := mediaUpdateKind(metadata.Package{Identity: metadata.PackageIdentity{Name: "Package_for_Unknown", Version: "1.0.0.0"}, ReleaseType: release}); err == nil {
			t.Fatalf("non-update release%q promoted to%q", release, kind)
		}
	}
	if _, err := mediaUpdateKind(metadata.Package{Identity: metadata.PackageIdentity{Name: "Microsoft-Windows-Foundation-Package"}, ReleaseType: "Update"}); err == nil {
		t.Fatal("base source content classified as ordinary installable update")
	}
	for _, tc := range []struct {
		name, release string
		want          metadata.UpdateKind
	}{{"Package_for_ServicingStack_42", "Update", metadata.UpdateServicingStack}, {"Package_for_RollupFix", "Security Update", metadata.UpdateCumulative}, {"Package_for_DotNetRollup_481", "Update", metadata.UpdateCumulative}, {"Package_for_Enablement", "Feature Pack", metadata.UpdateEnablement}} {
		kind, err := mediaUpdateKind(metadata.Package{Identity: metadata.PackageIdentity{Name: tc.name}, ReleaseType: tc.release})
		if err != nil || kind != tc.want {
			t.Fatalf("specialized identity%s lost:%s %v", tc.name, kind, err)
		}
	}
}

func TestMediaUpdatesRetainUnselectedEditionRestriction(t *testing.T) {
	inv, _ := mediaFixture(t)
	id := metadata.PackageIdentity{Name: "Package_for_RollupFix", Version: "1.2.3.4", Architecture: "amd64"}
	inv.Packages = []metadata.Package{{Identity: id, Dependencies: []metadata.PackageDependency{{Type: "parent", Identity: metadata.PackageIdentity{Name: "Microsoft-Windows-EnterpriseEdition", Version: "10.0.26300.1", Architecture: "amd64"}}}}}
	inv.Updates = []metadata.Update{{ID: "KB999", Kind: metadata.UpdateCumulative, Packages: []metadata.PackageIdentity{id}}}
	if err := bindMediaUpdateRelationships(&inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Updates[0].Editions) != 1 || inv.Updates[0].Editions[0] != "Enterprise" {
		t.Fatalf("edition restriction broadened: %+v", inv.Updates[0])
	}
}

func TestMediaUpdatesRejectUnexaminedRequiredBaseDependency(t *testing.T) {
	inv, _ := mediaFixture(t)
	id := metadata.PackageIdentity{Name: "Package_for_RollupFix", Version: "1.2.3.4", Architecture: "amd64"}
	inv.Packages = []metadata.Package{{Identity: id, Dependencies: []metadata.PackageDependency{{Type: "install", Identity: metadata.PackageIdentity{Name: "Required.Package", Version: "1.0.0.0", Architecture: "amd64"}}}}}
	inv.Updates = []metadata.Update{{ID: "KB999", Kind: metadata.UpdateCumulative, Packages: []metadata.PackageIdentity{id}}}
	if err := bindMediaUpdateRelationships(&inv); err == nil {
		t.Fatal("unexamined base-image prerequisite treated as satisfied")
	}
}

func TestMediaUpdatesAcceptTransitiveCheckpointChain(t *testing.T) {
	inv, _ := mediaFixture(t)
	for n := 1; n <= 3; n++ {
		id := metadata.PackageIdentity{Name: "Package_for_RollupFix", Version: string(rune('0'+n)) + ".0.0.0", Architecture: "amd64"}
		pack := metadata.Package{Identity: id}
		if n > 1 {
			dep := id
			dep.Version = string(rune('0'+n-1)) + ".0.0.0"
			pack.Dependencies = append(pack.Dependencies, metadata.PackageDependency{Type: "install", Identity: dep})
		}
		inv.Packages = append(inv.Packages, pack)
		inv.Updates = append(inv.Updates, metadata.Update{ID: "KB" + string(rune('0'+n)), Kind: metadata.UpdateCumulative, Packages: []metadata.PackageIdentity{id}})
	}
	if err := bindMediaUpdateRelationships(&inv); err != nil {
		t.Fatalf("valid predecessor chain rejected: %v", err)
	}
}

func TestMediaNativeTextDecodesWindowsUTF16(t *testing.T) {
	want := "Full Path           = \"\\sources\\setup.exe\"\r\nUncompressed size = 123 bytes\r\n"
	units := utf16.Encode([]rune(want))
	body := make([]byte, 2+len(units)*2)
	body[0] = 0xff
	body[1] = 0xfe
	for i, u := range units {
		binary.LittleEndian.PutUint16(body[2+i*2:], u)
	}
	got, err := decodeMediaText(string(body))
	if err != nil || got != want {
		t.Fatalf("decoded=%q err=%v", got, err)
	}
}

func TestMediaEdgeSamplesRequireEveryObservedRoot(t *testing.T) {
	if _, err := mediaEdgeSamples("/Edge\n/Edge/Application/msedge.exe\n/EdgeUpdate\n"); err == nil {
		t.Fatal("unexamined EdgeUpdate root accepted")
	}
	got, err := mediaEdgeSamples("/Edge\n/Edge/Application/msedge.exe\n/EdgeCore/147.0.1234.5/msedge.exe\n/EdgeUpdate/MicrosoftEdgeUpdate.exe\n")
	if err != nil || len(got) != 3 {
		t.Fatalf("actual versioned Edge content rejected: %v %v", got, err)
	}
}

func TestDetectMediaIgnoresReferenceOnlyOSImagesAndSupportsSharedMultiEdition(t *testing.T) {
	inv, s := mediaFixture(t)
	ref := sourcePayload("reference.esd", "b")
	inv.Manifest.Payloads = append(inv.Manifest.Payloads, ref)
	m, err := model.NewPayloadManifest(inv.Source, inv.Manifest.Payloads)
	if err != nil {
		t.Fatal(err)
	}
	inv.Manifest = m
	other := inv.Images[2]
	other.Resource.Payload = ref.Identity
	other.Index = 1
	inv.Images = append(inv.Images, other)
	if _, err = DetectMedia(inv, s); err != nil {
		t.Fatalf("reference image introduced false ambiguity: %v", err)
	}
	other = inv.Images[2]
	other.Index = 25
	other.Edition = "Enterprise"
	inv.Images = append(inv.Images, other)
	s.Editions = append(s.Editions, "Enterprise")
	if got, err := DetectMedia(inv, s); err != nil || got.OSIndex != 12 {
		t.Fatalf("shared multi-edition metadata rejected: %+v %v", got, err)
	}
}

func TestMediaEditionMappingsAcceptUTF16DeclarationAndRetainOriginal(t *testing.T) {
	inv, _ := mediaFixture(t)
	text := `<?xml version="1.0" encoding="utf-16"?><WindowsEditions><Edition virtual="true"><Name>Enterprise</Name><ParentEdition>Professional</ParentEdition></Edition></WindowsEditions>`
	units := utf16.Encode([]rune(text))
	body := make([]byte, 2+len(units)*2)
	body[0] = 0xff
	body[1] = 0xfe
	for i, u := range units {
		binary.LittleEndian.PutUint16(body[2+i*2:], u)
	}
	if err := addMediaEditionMappings(context.Background(), &inv, inv.Images[2], body); err != nil {
		t.Fatal(err)
	}
	if len(inv.EditionBases) != 1 || string(inv.Documents[0].Original) != string(body) {
		t.Fatal("UTF16 declaration or original bytes lost")
	}
}

func TestMediaUpdatesRejectUnexaminedParentGroupButAcceptEditionAlternatives(t *testing.T) {
	inv, _ := mediaFixture(t)
	id := metadata.PackageIdentity{Name: "Package_for_RollupFix", Version: "1.0.0.0", Architecture: "amd64"}
	inv.Packages = []metadata.Package{{Identity: id, Dependencies: []metadata.PackageDependency{{Type: "parent", Identity: metadata.PackageIdentity{Name: "Required.Base.Package", Version: "1.0.0.0", Architecture: "amd64"}}}}}
	inv.Updates = []metadata.Update{{ID: "KB999", Kind: metadata.UpdateCumulative, Packages: []metadata.PackageIdentity{id}}}
	if err := bindMediaUpdateRelationships(&inv); err == nil {
		t.Fatal("unexamined parent prerequisite accepted")
	}
	inv.Packages[0].Dependencies = append(inv.Packages[0].Dependencies, metadata.PackageDependency{Type: "parent", Identity: metadata.PackageIdentity{Name: "Microsoft-Windows-ProfessionalEdition", Version: "10.0.26300.1", Architecture: "amd64"}})
	if err := bindMediaUpdateRelationships(&inv); err != nil {
		t.Fatalf("OR edition alternative incorrectly treated as mandatory base package: %v", err)
	}
}

func TestMediaMixedParentAlternativesDoNotBroadenApplicability(t *testing.T) {
	inv, _ := mediaFixture(t)
	id := metadata.PackageIdentity{Name: "Package_for_RollupFix", Version: "2.0.0.0", Architecture: "amd64"}
	prior := id
	prior.Version = "1.0.0.0"
	inv.Packages = []metadata.Package{{Identity: id, Dependencies: []metadata.PackageDependency{{Type: "parent", Identity: metadata.PackageIdentity{Name: "Microsoft-Windows-EnterpriseEdition", Version: "10.0.26300.1", Architecture: "amd64"}}, {Type: "parent", Identity: prior}}}}
	inv.Updates = []metadata.Update{{ID: "KB998", Kind: metadata.UpdateCumulative, Packages: []metadata.PackageIdentity{prior}, Editions: []string{"Enterprise"}}, {ID: "KB999", Kind: metadata.UpdateCumulative, Packages: []metadata.PackageIdentity{id}}}
	if err := bindMediaUpdateRelationships(&inv); err == nil {
		t.Fatal("mixed edition/predecessor alternatives broadened to every edition")
	}
}

type mediaRecordingFetcher struct {
	calls []model.PayloadManifest
	files download.Materialized
}

func (f *mediaRecordingFetcher) Fetch(_ context.Context, m model.PayloadManifest, _ model.Locators, _ model.Emit) (download.Materialized, error) {
	f.calls = append(f.calls, m)
	out := download.Materialized{}
	for _, p := range m.Payloads {
		out[p.Identity] = f.files[p.Identity]
	}
	return out, nil
}

func TestResolveMediaProbesExactSelectedWIMBeforeFullClosure(t *testing.T) {
	for _, completeLayout := range []bool{false, true} {
		t.Run(strconv.FormatBool(completeLayout), func(t *testing.T) {
			text := `<WIM><IMAGE INDEX="12"><WINDOWS><ARCH>9</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><LANGUAGES><LANGUAGE>en-US</LANGUAGE></LANGUAGES></WINDOWS></IMAGE>`
			if completeLayout {
				text += `<IMAGE INDEX="17"><NAME>Windows Setup Media</NAME></IMAGE><IMAGE INDEX="5"><WINDOWS><ARCH>9</ARCH><INSTALLATIONTYPE>WindowsPE</INSTALLATIONTYPE><LANGUAGES><LANGUAGE>en-US</LANGUAGE></LANGUAGES></WINDOWS></IMAGE>`
			}
			text += `</WIM>`
			body := make([]byte, 208+len(text))
			copy(body, "MSWIM\x00\x00\x00")
			binary.LittleEndian.PutUint32(body[8:], 208)
			binary.LittleEndian.PutUint32(body[12:], 0x10d00)
			binary.LittleEndian.PutUint16(body[40:], 1)
			binary.LittleEndian.PutUint16(body[42:], 1)
			binary.LittleEndian.PutUint64(body[72:], uint64(len(text)))
			binary.LittleEndian.PutUint64(body[80:], 208)
			binary.LittleEndian.PutUint64(body[88:], uint64(len(text)))
			copy(body[208:], text)
			sum := sha256.Sum256(body)
			file := filepath.Join(t.TempDir(), "base.esd")
			if err := os.WriteFile(file, body, 0600); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/get.php" {
					t.Errorf("unexpected route %s", r.URL.Path)
					http.Error(w, "bad", 400)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{"arch": "amd64", "build": "26300.9818", "files": map[string]any{"professional_en-us.esd": map[string]any{"sha256": hex.EncodeToString(sum[:]), "size": len(body), "expire": 0}, "reference.psf": map[string]any{"sha256": strings.Repeat("b", 64), "size": 5000000000, "expire": 0}}}})
			}))
			defer server.Close()
			_, settings := selectionAndSettings(t)
			settings.Apps.Mode = model.AppsNone
			selection := model.Selection{UpdateID: appTestID, Architecture: "amd64", Language: "en-us", Editions: []string{"Professional"}}
			cat := catalog.New(server.Client(), server.URL)
			set, err := cat.Files(context.Background(), selection.UpdateID, selection.Language, "Professional")
			if err != nil {
				t.Fatal(err)
			}
			fetch := &mediaRecordingFetcher{files: download.Materialized{}}
			for _, p := range set.Payloads {
				fetch.files[p.Identity] = download.CachedFile{Identity: p.Identity, Path: file}
			}
			called := false
			got, err := ResolveMedia(context.Background(), cat, nil, fetch, selection, settings, nil, func(_ context.Context, inv *metadata.Inventory, _ download.Materialized) error {
				called = true
				if len(inv.Manifest.Payloads) != 2 {
					t.Fatal("completion lacks exact base closure")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(fetch.calls) == 0 || len(fetch.calls[0].Payloads) != 1 || fetch.calls[0].Payloads[0].Destination != "professional_en-us.esd" {
				t.Fatalf("probe broadened: %+v", fetch.calls)
			}
			if completeLayout {
				if !called || len(fetch.calls) != 2 || len(got.Manifest.Payloads) != 2 {
					t.Fatal("valid candidate did not acquire full closure")
				}
			} else {
				if called || len(fetch.calls) != 1 || len(got.Diagnostics) == 0 {
					t.Fatal("inconclusive metadata downloaded unrelated large source")
				}
			}
		})
	}
}

func TestResolveMediaEmptyAppProjectionCannotAcquireWholeNeutralSet(t *testing.T) {
	f := newAppHTTPFixture() // Features deliberately have no payload membership.
	text := `<WIM><IMAGE INDEX="12"><WINDOWS><ARCH>9</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><LANGUAGES><LANGUAGE>en-gb</LANGUAGE></LANGUAGES></WINDOWS></IMAGE><IMAGE INDEX="17"><NAME>Windows Setup Media</NAME></IMAGE><IMAGE INDEX="5"><WINDOWS><ARCH>9</ARCH><INSTALLATIONTYPE>WindowsPE</INSTALLATIONTYPE><LANGUAGES><LANGUAGE>en-gb</LANGUAGE></LANGUAGES></WINDOWS></IMAGE></WIM>`
	body := make([]byte, 208+len(text))
	copy(body, "MSWIM\x00\x00\x00")
	binary.LittleEndian.PutUint32(body[8:], 208)
	binary.LittleEndian.PutUint32(body[12:], 0x10d00)
	binary.LittleEndian.PutUint16(body[40:], 1)
	binary.LittleEndian.PutUint16(body[42:], 1)
	binary.LittleEndian.PutUint64(body[72:], uint64(len(text)))
	binary.LittleEndian.PutUint64(body[80:], 208)
	binary.LittleEndian.PutUint64(body[88:], uint64(len(text)))
	copy(body[208:], text)
	sum := sha256.Sum256(body)
	file := filepath.Join(t.TempDir(), "professional_en-gb.esd")
	if err := os.WriteFile(file, body, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/get.php" || r.URL.Query().Get("lang") == "neutral" {
			f.serve(w, r)
			return
		}
		recorder := httptest.NewRecorder()
		f.serve(recorder, r)
		if recorder.Code != 200 {
			w.WriteHeader(recorder.Code)
			w.Write(recorder.Body.Bytes())
			return
		}
		var payload map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Error(err)
			return
		}
		files := payload["response"].(map[string]any)["files"].(map[string]any)
		files["professional_en-gb.esd"] = map[string]any{"sha256": hex.EncodeToString(sum[:]), "size": len(body), "expire": 0}
		json.NewEncoder(w).Encode(payload)
	}))
	defer server.Close()
	clock := newAppPacingClock()
	cat := catalog.New(server.Client(), server.URL)
	cat.Clock = clock
	cat.Pacer = catalog.NewGetPacer(clock)
	apps := NewAppCatalog(server.URL)
	setAppTestPacer(apps, clock)
	selection := appSelection()
	_, settings := selectionAndSettings(t)
	settings.Apps.Mode = model.AppsCustom
	settings.Apps.Include = []string{"Example.App_pub"}
	set, err := cat.Files(context.Background(), selection.UpdateID, selection.Language, selection.Editions[0])
	if err != nil {
		t.Fatal(err)
	}
	fetch := &mediaRecordingFetcher{files: download.Materialized{}}
	for _, p := range set.Payloads {
		if p.Destination == "professional_en-gb.esd" {
			fetch.files[p.Identity] = download.CachedFile{Identity: p.Identity, Path: file, SHA256: hex.EncodeToString(sum[:])}
		}
	}
	called := false
	_, err = ResolveMedia(context.Background(), cat, apps, fetch, selection, settings, nil, func(context.Context, *metadata.Inventory, download.Materialized) error { called = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "projection") || len(fetch.calls) != 1 || called {
		t.Fatalf("empty app projection broadened source requests: fetches=%d completion=%v err=%v", len(fetch.calls), called, err)
	}
}
