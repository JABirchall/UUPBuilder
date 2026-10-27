package metadata

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"uupbuilder/internal/model"
)

// This optional local test inspects original Microsoft XML already extracted by
// the corpus researcher. It never extracts a CAB or launches a helper. Original
// XML is deliberately uncommitted while redistribution rights remain unresolved.
// Counts and graph expectations below were checked independently using .NET XML.
// Passing is static parser evidence for this source only, not Gate S/P proof.
func TestLocalOriginalCompDBCorpus(t *testing.T) {
	root := os.Getenv("M1_COMPDB_CORPUS")
	if root == "" {
		t.Skip("original local-only Microsoft CompDB corpus not supplied")
	}
	source := model.SourceIdentity{UpdateID: "a1b78728-530f-443f-b672-d742e7c14bcb", BuildLabel: "22000.1", Architecture: "arm64", Language: "en-us"}
	// The resolver request defaults to revision 1; no independently echoed
	// Microsoft revision is claimed. Preserve the observed source ID verbatim.
	id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA1, Value: "fc9cd5aa6972bc862550ce1baa2f0a4a44b47e2b"}, Size: 1146246, Provenance: model.PackageProvenance{Source: "Microsoft metadata via UUP Dump a1b78728-530f-443f-b672-d742e7c14bcb; local research; catalog signature unchecked", Name: "a1b78728-530f-443f-b672-d742e7c14bcb.aggregatedmetadata.cab"}}
	manifest, err := model.NewPayloadManifest(source, []model.Payload{{Identity: id, Destination: "metadata.cab"}})
	if err != nil {
		t.Fatal(err)
	}
	var documents []MetadataDocument
	for _, name := range []string{"DesktopTargetCompDB_professional_en-us.xml", "DesktopTargetCompDB_Neutral.xml", "DesktopBaselessCompDB_en-us.CompDB.xml", "Desktop_neutral_Forward_19041.1.vb_release.191206-1406.CompDB.xml"} {
		data, err := os.ReadFile(filepath.Join(root, "22000-arm64-xml", name))
		if err != nil {
			t.Fatal(err)
		}
		documents = append(documents, MetadataDocument{Resource: ResourceReference{Payload: id, Member: name}, Format: FormatCompositionXML, Original: data, Provenance: "pre-extracted original Microsoft XML; nested member hashes in local corpus provenance; read-only parser test only"})
	}
	resource := LocalResource{Identity: id, Path: filepath.Join(root, "22000-arm64-aggregatedmetadata.cab")}
	inv, err := Inspect(context.Background(), InspectRequest{Source: source, Manifest: manifest, Inspections: []Inspection{{Resource: resource, Provider: syntheticProvider{ProviderResult{Documents: documents}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Compositions) != 4 {
		t.Fatalf("composition count: %d", len(inv.Compositions))
	}
	professional := inv.Compositions[0]
	if professional.Name != "Build~arm64~Desktop~professional~en-us" || professional.BuildID != "b5347a24-b65f-7c51-ac95-8bdd36d866a1" || professional.OSVersion != "10.0.22000.1" || len(professional.Packages) != 44 || len(professional.Features) != 1 || professional.Features[0].ID != "professional_en-us" || len(professional.Features[0].Dependencies) != 18 {
		t.Fatalf("professional semantic graph: name %q packages %d features %#v", professional.Name, len(professional.Packages), professional.Features)
	}
	if professional.Features[0].Dependencies[0] != "Windows.Client.ShellComponents~~1.0" || professional.Packages[0].ID != "Microsoft-Windows-Client-LanguagePack-Package_en-us~31bf3856ad364e35~arm64~en-us~" {
		t.Fatal("real feature/package identities changed or dropped")
	}
	forward := inv.Compositions[3]
	if forward.Type != "Update" || forward.OSVersion != "10.0.19041.1" || forward.TargetOSVersion != "10.0.22000.1" || forward.TargetBuildID != "b5347a24-b65f-7c51-ac95-8bdd36d866a1" {
		t.Fatalf("differential source/target identity lost: %#v", forward)
	}
	if len(inv.Roles) != 0 || len(inv.Absences) != 0 || inv.Classification != ClassificationMetadataIncomplete {
		t.Fatalf("real partial metadata overclaimed: %s, roles %d, absences %d", inv.Classification, len(inv.Roles), len(inv.Absences))
	}
	for _, comp := range inv.Compositions {
		t.Logf("original CompDB %s: packages=%d features=%d source=%s target=%s; unresolved resource/role evidence retained", comp.Name, len(comp.Packages), len(comp.Features), comp.OSVersion, comp.TargetOSVersion)
	}
}
