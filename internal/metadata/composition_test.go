package metadata

import (
	"context"
	"errors"
	"testing"
)

// Synthetic shape based on observed Microsoft CompDB 1.2 records. It is not
// copied upstream metadata and does not prove a real family's role closure.
// Dropping package IDs/dependency edges or inferring an opaque hash algorithm
// from its length must fail this test. Exact resource bindings need evidence.
func TestCompositionRetainsGraphAndEvidenceBoundResources(t *testing.T) {
	payload := inputFile(t, "renamed.resource", "synthetic payload bytes", Format("payload"))
	text := `<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" SchemaVersion="1.2" Revision="1" Product="Desktop" BuildID="synthetic-build" BuildInfo="synthetic.1" OSVersion="10.0.1.2" BuildArch="arm64" Type="Build" Name="Synthetic"><Tags Type="Edition"><Tag Name="Edition" Value="Professional"/><Tag Name="Language" Value="en-US"/><Tag Name="UpdateType" Value="Canonical"/></Tags><Features><Feature Type="DesktopMedia" FeatureID="edition-feature" FMID="MSDE" Group="Microsoft" Family="Client"><Dependencies><Feature FeatureID="base-feature"/></Dependencies><Packages><Package ID="opaque-package-id" PackageType="FeaturePackage"/></Packages></Feature></Features><Packages><Package ID="opaque-package-id" Version="10.0.1.2" InstalledSize="6000000000"><Payload><PayloadItem PayloadHash="opaque-upstream-hash" PayloadSize="23" Path="not-the-downloaded-name.esd" PayloadType="Canonical"/></Payload></Package></Packages></CompDB>`
	file := inputFile(t, "metadata.xml", text, FormatCompositionXML)
	req := requestFor(t, file, payload)
	req.Files = []MetadataFile{file}
	inv, err := Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Compositions) != 1 {
		t.Fatalf("composition records missing: %#v", inv)
	}
	comp := inv.Compositions[0]
	if comp.Architecture != "arm64" || comp.OSVersion != "10.0.1.2" || len(comp.Packages) != 1 || comp.Packages[0].ID != "opaque-package-id" {
		t.Fatalf("composition identity lost: %#v", comp)
	}
	if len(comp.Features) != 1 || len(comp.Features[0].Dependencies) != 1 || comp.Features[0].Dependencies[0] != "base-feature" || comp.Features[0].Packages[0].ID != "opaque-package-id" {
		t.Fatalf("feature graph lost: %#v", comp.Features)
	}
	item := comp.Packages[0].Payloads[0]
	if item.Path != "not-the-downloaded-name.esd" || item.Resource != nil || item.Hash != "opaque-upstream-hash" || item.HashAlgorithm != "" || comp.Packages[0].InstalledSize != 6000000000 {
		t.Fatalf("payload identity/size guessed or lost: %#v", comp.Packages[0])
	}
	if len(inv.Roles) != 0 || inv.Classification == ClassificationSemanticInventory {
		t.Fatal("composition filenames fabricated image roles/readiness")
	}
	req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{PayloadBindings: []PayloadBinding{{PackageID: "opaque-package-id", PayloadHash: "opaque-upstream-hash", Resource: ResourceReference{Payload: payload.Resource.Identity}, Evidence: evidenceFor(file)}}}}}}
	inv, err = Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	item = inv.Compositions[0].Packages[0].Payloads[0]
	if item.Resource == nil || item.Resource.Payload != payload.Resource.Identity {
		t.Fatalf("explicit resource provenance lost: %#v", item)
	}
	if item.Binding == nil || item.Binding.Evidence != evidenceFor(file) {
		t.Fatal("resource binding lost original semantic evidence")
	}
}

// Treating an unrecognized schema version or missing feature closure as complete
// must fail; contradictory target metadata must be rejected.
func TestCompositionSchemaConflictAndClosure(t *testing.T) {
	for _, tc := range []struct {
		name, version, arch string
		want                error
		unsupported         bool
	}{{"future", "99", "arm64", nil, true}, {"architecture", "1.2", "x86", ErrConflictingMetadata, false}} {
		t.Run(tc.name, func(t *testing.T) {
			file := inputFile(t, "metadata.xml", `<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" SchemaVersion="`+tc.version+`" BuildArch="`+tc.arch+`"/>`, FormatCompositionXML)
			inv, err := Inspect(context.Background(), requestFor(t, file))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error: %v", err)
			}
			if tc.unsupported && inv.Classification != ClassificationImplementationGap {
				t.Fatalf("future schema classification: %s", inv.Classification)
			}
		})
	}
}

// A binding for a different package/raw hash, wrong size or invalid full resource
// identity must fail rather than attaching a convenient local payload.
func TestCompositionPayloadBindingsRejectMismatches(t *testing.T) {
	for _, name := range []string{"package", "hash", "size", "identity", "member"} {
		t.Run(name, func(t *testing.T) {
			file := inputFile(t, "metadata.xml", `<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" SchemaVersion="1.2" BuildArch="arm64"><Packages><Package ID="id"><Payload><PayloadItem PayloadHash="opaque" PayloadSize="7" Path="irrelevant"/></Payload></Package></Packages></CompDB>`, FormatCompositionXML)
			payload := inputFile(t, "resource.bin", "payload", Format("payload"))
			req := requestFor(t, file, payload)
			req.Files = []MetadataFile{file}
			binding := PayloadBinding{PackageID: "id", PayloadHash: "opaque", Resource: ResourceReference{Payload: payload.Resource.Identity}, Evidence: evidenceFor(file)}
			switch name {
			case "package":
				binding.PackageID = "other"
			case "hash":
				binding.PayloadHash = "other"
			case "size":
				binding.Resource.Payload = file.Resource.Identity
			case "identity":
				binding.Resource.Payload.Provenance.Source = "other"
			case "member":
				binding.Resource.Member = "../escape"
			}
			req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{PayloadBindings: []PayloadBinding{binding}}}}}
			if _, err := Inspect(context.Background(), req); !errors.Is(err, ErrInvalidEvidence) {
				t.Fatalf("want invalid binding, got %v", err)
			}
		})
	}
}
