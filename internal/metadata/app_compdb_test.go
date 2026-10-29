package metadata

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const appCompDBFixture = `<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" SchemaVersion="1.2" Type="Build" Product="Desktop" BuildID="build-id" BuildArch="amd64" OSVersion="10.0.1.1"><Features><Feature FeatureID="Example.App_pub" Type="MSIXBundle" Group="PreinstalledApps"><Dependencies><Feature FeatureID="Example.Framework_pub" Type="Required"/></Dependencies><InitialIntents><InitialIntent Value="PREFERSTUB"/></InitialIntents><CustomInformation><CustomInfo Key="licensedata"><![CDATA[<License xmlns="urn:schemas-microsoft-com:windows:store:licensing:ls" Version="3"><Binding><PFM>different.app_pub</PFM></Binding><LicenseInfo LicenseUsage="Offline" LicenseCategory="OEM"/></License>]]></CustomInfo></CustomInformation><Packages><Package ID="source-package"><Media Type="CleanInstall" State="INSTALLED"/></Package></Packages></Feature><Feature FeatureID="Example.Framework_pub" Type="MSIXFramework"/></Features></CompDB>`

func TestObserveAppCompDBRetainsRawRequestsAndHints(t *testing.T) {
	doc, err := ObserveAppCompDB(context.Background(), []byte(appCompDBFixture))
	if err != nil {
		t.Fatal(err)
	}
	if doc.BuildID != "build-id" || doc.Architecture != "amd64" || len(doc.Features) != 2 {
		t.Fatalf("bad document: %+v", doc)
	}
	f := doc.Features[0]
	if f.FeatureID != "Example.App_pub" || f.Type != "MSIXBundle" || f.Dependencies[0].Type != "Required" || f.InitialIntents[0] != "PREFERSTUB" || f.Media[0].PackageID != "source-package" || f.Media[0].State != "INSTALLED" {
		t.Fatalf("lost source declarations: %+v", f)
	}
	if len(f.Licenses) != 1 || f.Licenses[0].PFM != "different.app_pub" || f.Licenses[0].FamilyMatchesIgnoringCase {
		t.Fatalf("license mismatch guessed away: %+v", f.Licenses)
	}
}

func TestObserveAppCompDBRejectsUnsafeXMLAndWrongSchemas(t *testing.T) {
	for _, data := range []string{`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///x">]>` + appCompDBFixture, strings.Replace(appCompDBFixture, "SchemaVersion=\"1.2\"", "SchemaVersion=\"9\"", 1), strings.Replace(appCompDBFixture, "http://schemas.microsoft.com/embedded/2004/10/ImageUpdate", "foreign", 1), strings.Replace(appCompDBFixture, "</Features>", `<Feature FeatureID="Example.App_pub" Type="MSIX"/></Features>`, 1)} {
		if _, err := ObserveAppCompDB(context.Background(), []byte(data)); err == nil {
			t.Fatal("unsafe/conflicting document accepted")
		}
	}
	if _, err := ObserveAppCompDB(context.Background(), make([]byte, (16<<20)+1)); !errors.Is(err, ErrLimit) {
		t.Fatalf("unbounded XML: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ObserveAppCompDB(ctx, []byte(appCompDBFixture)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestObserveEditionCompDBKeepsOnlyExplicitDesktopMediaReferences(t *testing.T) {
	raw := `<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" SchemaVersion="1.2" Type="Build" Product="Desktop" BuildID="build-id" BuildArch="amd64" OSVersion="10.0.1.1"><Tags Type="Edition"><Tag Name="Edition" Value="professional"/><Tag Name="Language" Value="en-gb"/></Tags><Features><Feature Type="DesktopMedia" FeatureID="professional_en-gb"><Dependencies><Feature FeatureID="Example.App_pub" Group="PreinstalledApps" Type="MediaCreationRequired"/><Feature FeatureID="EdgeBrowser" Group="Edge" Type="Optional"/></Dependencies></Feature></Features></CompDB>`
	doc, err := ObserveAppCompDB(context.Background(), []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Edition != "professional" || doc.Language != "en-gb" || doc.Features[0].Dependencies[0].Type != "MediaCreationRequired" || doc.Features[0].Dependencies[1].Group != "Edge" {
		t.Fatalf("lost source scope: %+v", doc)
	}
}
