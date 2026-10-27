package metadata

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"uupbuilder/internal/model"
)

// All inline XML and provider reports in this file are synthetic behavioral
// fixtures. They are not evidence of a supported real UUP source family.
// Each test's comment names the production regression it is intended to catch.
func testSource() model.SourceIdentity {
	return model.SourceIdentity{UpdateID: "synthetic-source-revision-7", BuildLabel: "10.0.1.2", Architecture: "arm64", Language: "en-US"}
}

func inputFile(t *testing.T, name, text string, format Format) MetadataFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(text))
	id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, Size: int64(len(text)), Provenance: model.PackageProvenance{Source: "synthetic-test", Name: name}}
	return MetadataFile{Resource: LocalResource{Identity: id, Path: path}, Format: format}
}

func requestFor(t *testing.T, files ...MetadataFile) InspectRequest {
	t.Helper()
	payloads := make([]model.Payload, len(files))
	for i, file := range files {
		payloads[i] = model.Payload{Identity: file.Resource.Identity, Destination: file.Resource.Identity.Provenance.Name}
	}
	manifest, err := model.NewPayloadManifest(testSource(), payloads)
	if err != nil {
		t.Fatal(err)
	}
	return InspectRequest{Source: testSource(), Manifest: manifest, Files: files}
}

type syntheticProvider struct{ result ProviderResult }

func (p syntheticProvider) Inspect(context.Context, LocalResource, Limits) (ProviderResult, error) {
	return p.result, nil
}

func evidenceFor(file MetadataFile) Evidence {
	return Evidence{Source: testSource(), Document: DocumentReference{Resource: ResourceReference{Payload: file.Resource.Identity}, SHA256: file.Resource.Identity.Digest.Value}, Selector: "/WIM/IMAGE"}
}

// A role selector based on the path or a fixed image index must fail this test.
func TestRolesDoNotDependOnFilenameOrIndex(t *testing.T) {
	for _, tc := range []struct {
		name            string
		setup, recovery int
	}{{"install.xml", 7, 2}, {"random.data", 2, 7}} {
		t.Run(tc.name, func(t *testing.T) {
			text := `<WIM><IMAGE INDEX="` + stringIndex(tc.setup) + `"><WINDOWS><ARCH>12</ARCH><INSTALLATIONTYPE>WindowsPE</INSTALLATIONTYPE></WINDOWS></IMAGE><IMAGE INDEX="` + stringIndex(tc.recovery) + `"><WINDOWS><ARCH>12</ARCH><INSTALLATIONTYPE>WindowsPE</INSTALLATIONTYPE></WINDOWS></IMAGE><IMAGE INDEX="19"><WINDOWS><ARCH>12</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>1</BUILD><SPBUILD>2</SPBUILD></VERSION></WINDOWS></IMAGE></WIM>`
			file := inputFile(t, tc.name, text, FormatWIMXML)
			req := requestFor(t, file)
			evidence := evidenceFor(file)
			req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{Roles: []RoleEvidence{{Role: RoleSetup, Resource: ResourceReference{Payload: file.Resource.Identity}, ImageIndex: tc.setup, Evidence: evidence}, {Role: RoleWinRE, Resource: ResourceReference{Payload: file.Resource.Identity}, ImageIndex: tc.recovery, Evidence: evidence}}}}}}
			inv, err := Inspect(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			got := map[Role]int{}
			for _, role := range inv.Roles {
				got[role.Role] = role.ImageIndex
				if role.Resource.Payload != file.Resource.Identity {
					t.Fatal("role lost resource identity")
				}
			}
			if !reflect.DeepEqual(got, map[Role]int{RoleSetup: tc.setup, RoleWinRE: tc.recovery, RoleOS: 19}) {
				t.Fatalf("semantic roles: %#v", got)
			}
			if inv.Images[2].Edition != "Professional" || inv.Images[2].Build != "10.0.1.2" {
				t.Fatalf("image properties: %#v", inv.Images[2])
			}
		})
	}
}

func stringIndex(index int) string {
	if index == 7 {
		return "7"
	}
	return "2"
}

// Silently accepting an OS architecture contradicting the selected source is a bug.
func TestConflictingArchitectureMetadataFails(t *testing.T) {
	file := inputFile(t, "anything.xml", `<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>9</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`, FormatWIMXML)
	_, err := Inspect(context.Background(), requestFor(t, file))
	if !errors.Is(err, ErrConflictingMetadata) {
		t.Fatalf("want metadata conflict, got %v", err)
	}
}

// An update-only classification must retain all download identities unchanged.
func TestUpdateOnlyRetainsDownloadability(t *testing.T) {
	file := inputFile(t, "update.xml", `<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"><assemblyIdentity name="Synthetic.Update" version="10.0.1.2" processorArchitecture="arm64" publicKeyToken="0011223344556677" language="neutral"/><package identifier="Synthetic.Update" releaseType="Update"/></assembly>`, FormatCBSXML)
	req := requestFor(t, file)
	e := evidenceFor(file)
	req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{Layouts: []LayoutEvidence{{Kind: LayoutUpdateOnly, Family: "synthetic-update", Evidence: e}}}}}}
	inv, err := Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Classification != ClassificationUpdateOnly || !reflect.DeepEqual(inv.Manifest, req.Manifest) {
		t.Fatalf("classification %q or manifest changed", inv.Classification)
	}
}

// Missing setup is unavailable only when a trusted source-bound absence report says so.
func TestMissingSetupIsSourceUnavailable(t *testing.T) {
	file := inputFile(t, "proof.xml", `<WIM/>`, FormatWIMXML)
	req := requestFor(t, file)
	req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{Absences: []AbsenceEvidence{{Role: RoleSetup, Reason: "Synthetic upstream closure explicitly lacks setup material", Evidence: evidenceFor(file)}}}}}}
	inv, err := Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Classification != ClassificationSourceUnavailable || len(inv.Absences) != 1 {
		t.Fatalf("want unavailable with explicit evidence: %#v", inv)
	}
}

// Unknown schemas must stay implementation gaps, never imply absent upstream setup.
func TestUnknownLayoutIsImplementationGap(t *testing.T) {
	file := inputFile(t, "setup.esd", `<FutureComposition Architecture="arm64"/>`, FormatCompositionXML)
	inv, err := Inspect(context.Background(), requestFor(t, file))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Classification != ClassificationImplementationGap || len(inv.Absences) != 0 || len(inv.Gaps) == 0 {
		t.Fatalf("unknown schema misclassified: %#v", inv)
	}
}

// Identity, dependency criteria and evidence-bound licenses must survive inventory.
func TestAppInventoryUsesFamiliesDependenciesAndLicenses(t *testing.T) {
	file := inputFile(t, "arbitrary.xml", `<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Synthetic.App" Publisher="CN=Synthetic" Version="1.2.3.4" ProcessorArchitecture="arm64" ResourceId="main"/><Properties><DisplayName>ms-resource:Name</DisplayName><Framework>false</Framework></Properties><Dependencies><PackageDependency Name="Synthetic.Framework" Publisher="CN=Synthetic" MinVersion="2.0.0.0"/></Dependencies><Resources><Resource Language="en-US"/></Resources></Package>`, FormatAppxXML)
	framework := inputFile(t, "unrelated.xml", `<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Synthetic.Framework" Publisher="CN=Synthetic" Version="2.3.0.0" ProcessorArchitecture="neutral"/><Properties><Framework>true</Framework></Properties></Package>`, FormatAppxXML)
	req := requestFor(t, file, framework)
	family := AppFamily{Name: "Synthetic.App", Publisher: "CN=Synthetic"}
	e := evidenceFor(file)
	req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{Licenses: []LicenseEvidence{{Family: family, Resource: ResourceReference{Payload: file.Resource.Identity}, Evidence: e}}, AppPhases: []AppPhaseEvidence{{Family: family, Phase: PhaseOfflineProvisioning, Evidence: e}}}}}}
	inv, err := Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Apps.Packages) != 2 {
		t.Fatalf("apps: %#v", inv.Apps)
	}
	app := inv.Apps.Packages[0]
	if app.Family != family || app.Identity.ResourceID != "main" || app.Identity.Version != "1.2.3.4" || len(app.Dependencies) != 1 || app.Dependencies[0].Family.Name != "Synthetic.Framework" || app.Dependencies[0].MinVersion != "2.0.0.0" || len(app.Licenses) != 1 || app.Phase != PhaseOfflineProvisioning || app.DisplayName != "ms-resource:Name" {
		t.Fatalf("identity/dependency/license lost: %#v", app)
	}
	if !inv.Apps.Packages[1].Framework {
		t.Fatal("framework property lost")
	}
	if app.PhaseEvidence == nil || *app.PhaseEvidence != e {
		t.Fatal("phase lost original semantic evidence")
	}
	if len(inv.Apps.RequiredFamilies) != 0 {
		t.Fatalf("invented universally required apps: %#v", inv.Apps.RequiredFamilies)
	}
}

// A partial supported document must not fabricate upstream absence or image roles.
func TestPartialMetadataStaysIncomplete(t *testing.T) {
	file := inputFile(t, "install.esd", `<WIM><IMAGE INDEX="1"><NAME>Windows Setup</NAME><FLAGS>WindowsRE</FLAGS><WINDOWS><ARCH>12</ARCH><INSTALLATIONTYPE>WindowsPE</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`, FormatWIMXML)
	inv, err := Inspect(context.Background(), requestFor(t, file))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Classification != ClassificationMetadataIncomplete || len(inv.Roles) != 0 || len(inv.Absences) != 0 {
		t.Fatalf("partial metadata overclaimed: %#v", inv)
	}
}

// Rebinding an absence report to another source must be rejected, not classified unavailable.
func TestEvidenceMustBindSourceAndOriginalMetadata(t *testing.T) {
	for _, tc := range []string{"source", "digest", "selector"} {
		t.Run(tc, func(t *testing.T) {
			file := inputFile(t, "proof.xml", `<WIM/>`, FormatWIMXML)
			req := requestFor(t, file)
			e := evidenceFor(file)
			switch tc {
			case "source":
				e.Source.UpdateID = "other-revision"
			case "digest":
				e.Document.SHA256 = strings.Repeat("0", 64)
			case "selector":
				e.Selector = ""
			}
			req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{Absences: []AbsenceEvidence{{Role: RoleSetup, Reason: "synthetic", Evidence: e}}}}}}
			_, err := Inspect(context.Background(), req)
			if !errors.Is(err, ErrInvalidEvidence) {
				t.Fatalf("want invalid evidence: %v", err)
			}
		})
	}
}

// Replacing immutable metadata or exceeding expansion limits must refuse inspection.
func TestVerifiedMetadataAndBoundedDecompression(t *testing.T) {
	t.Run("tampered", func(t *testing.T) {
		file := inputFile(t, "input.xml", `<WIM/>`, FormatWIMXML)
		req := requestFor(t, file)
		if err := os.WriteFile(file.Resource.Path, []byte(`<WIM!>`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Inspect(context.Background(), req); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("want integrity error: %v", err)
		}
	})
	t.Run("gzip-limit", func(t *testing.T) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(`<WIM>` + strings.Repeat(" ", 2000) + `</WIM>`))
		_ = zw.Close()
		file := inputFile(t, "input.gz", buf.String(), FormatWIMXML)
		file.Gzip = true
		req := requestFor(t, file)
		req.Limits = Limits{MaxDocumentBytes: 1000}
		if _, err := Inspect(context.Background(), req); !errors.Is(err, ErrLimit) {
			t.Fatalf("want decompression limit: %v", err)
		}
	})
}

// Future architecture values and the exact original metadata must remain inspectable.
func TestUnknownArchitectureAndOriginalBytesSurvive(t *testing.T) {
	text := `<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>65000</ARCH><EDITIONID>FutureEdition</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`
	file := inputFile(t, "future.xml", text, FormatWIMXML)
	req := requestFor(t, file)
	req.Source.Architecture = "65000"
	var err error
	req.Manifest, err = model.NewPayloadManifest(req.Source, req.Manifest.Payloads)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Images) != 1 || len(inv.Documents) != 1 {
		t.Fatalf("missing image/documents: %#v", inv)
	}
	if inv.Images[0].Architecture != "65000" || string(inv.Documents[0].Original) != text || inv.Documents[0].Reference.Resource.Payload != file.Resource.Identity {
		t.Fatalf("original/unknown value lost: %#v", inv)
	}
}

// CBS assembly dependency identities must remain graph criteria rather than filenames.
func TestPackageDependencyIdentitiesSurvive(t *testing.T) {
	file := inputFile(t, "random.bin", `<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"><assemblyIdentity name="Synthetic.OS" version="10.0.1.2" processorArchitecture="arm64" publicKeyToken="0011223344556677" language="neutral"/><dependency><dependentAssembly dependencyType="prerequisite"><assemblyIdentity name="Synthetic.Base" version="10.0.1.1" processorArchitecture="arm64" publicKeyToken="8899aabbccddeeff" language="neutral"/></dependentAssembly></dependency><package identifier="Synthetic.OS" releaseType="Feature Pack"/></assembly>`, FormatCBSXML)
	inv, err := Inspect(context.Background(), requestFor(t, file))
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Packages) != 1 || inv.Packages[0].Identity.Name != "Synthetic.OS" || len(inv.Packages[0].Dependencies) != 1 || inv.Packages[0].Dependencies[0].Identity.Name != "Synthetic.Base" || inv.Packages[0].Dependencies[0].Identity.PublicKeyToken != "8899aabbccddeeff" {
		t.Fatalf("CBS identity graph: %#v", inv.Packages)
	}
}
