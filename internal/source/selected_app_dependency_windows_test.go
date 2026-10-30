package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

func TestAppPayloadClosureFollowsRequiredDependenciesOnly(t *testing.T) {
	main := sourcePayload("main.msix", "a")
	framework := sourcePayload("framework.msix", "b")
	manifest, err := model.NewPayloadManifest(sourceIdentity(), []model.Payload{main, framework})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" SchemaVersion="1.2" Type="Build" Product="Desktop" BuildID="arbitrary-source" BuildArch="amd64" OSVersion="10.0.26100.1"><Features/><Packages><Package ID="main"><Payload><PayloadItem Path="main.msix" PayloadSize="16"/></Payload></Package><Package ID="framework"><Payload><PayloadItem Path="framework.msix" PayloadSize="16"/></Payload></Package></Packages></CompDB>`)
	sum := sha256.Sum256(raw)
	doc := metadata.Document{Reference: metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: main.Identity, Member: "app_neutral.xml"}, SHA256: hex.EncodeToString(sum[:])}, Original: raw}
	snapshot := AppCatalogSnapshot{AppManifest: manifest, Entries: []AppCatalogEntry{
		{FeatureID: "Main", Dependencies: []metadata.AppFeatureDependency{{FeatureID: "Framework", Type: "Required"}, {FeatureID: "UnselectedOptionalApp", Type: "Optional"}}, Media: []metadata.AppMediaHint{{PackageID: "main"}}},
		{FeatureID: "Framework", Media: []metadata.AppMediaHint{{PackageID: "framework"}}},
	}}
	got, err := SelectedAppPayloads(context.Background(), snapshot, []metadata.Document{doc}, []string{"Main"})
	if err != nil || len(got) != 2 {
		t.Fatalf("required closure=%v err=%v", got, err)
	}
}

func TestAppPayloadClosureAcceptsDirectPackageMembership(t *testing.T) {
	main := sourcePayload("main.msix", "a")
	manifest, err := model.NewPayloadManifest(sourceIdentity(), []model.Payload{main})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" SchemaVersion="1.2" Type="Build" Product="Desktop" BuildID="arbitrary-source" BuildArch="amd64" OSVersion="10.0.26100.1"><Features/><Packages><Package ID="main"><Payload><PayloadItem Path="main.msix" PayloadSize="16"/></Payload></Package></Packages></CompDB>`)
	sum := sha256.Sum256(raw)
	doc := metadata.Document{Reference: metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: main.Identity, Member: "app_neutral.xml"}, SHA256: hex.EncodeToString(sum[:])}, Original: raw}
	snapshot := AppCatalogSnapshot{AppManifest: manifest, Entries: []AppCatalogEntry{{FeatureID: "Main", Packages: []metadata.CompositionPackageReference{{ID: "main"}}}}}
	got, err := SelectedAppPayloads(context.Background(), snapshot, []metadata.Document{doc}, []string{"Main"})
	if err != nil || len(got) != 1 || got[0] != main {
		t.Fatalf("direct membership was lost: got=%v err=%v", got, err)
	}
}
