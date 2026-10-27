package metadata

import (
	"context"
	"os"
	"testing"
)

// Losing the documented five-part package identity, application IDs, or framework
// dependency criteria must fail on Microsoft-authored examples, not only made-up XML.
func TestMicrosoftSourceAppxExamples(t *testing.T) {
	for _, tc := range []struct {
		file, name, version string
		framework           bool
		dependency          string
	}{{"msix-Sample_AppxManifest.xml", "SampleAppManifest", "3.6.25071.0", false, "Microsoft.VCLibs.140.00"}, {"windowsappsdk-framework-arm64-AppxManifest.xml", "WindowsAppRuntime.Test.InstallerFramework", "1.0.0.0", true, ""}, {"windowsappsdk-ddlm-arm64-AppxManifest.xml", "WindowsAppRuntime.Test.DDLM.4.1.1967.333-arm64", "4.1.1967.333", false, "Microsoft.WindowsAppRuntime.4"}} {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + tc.file)
			if err != nil {
				t.Fatal(err)
			}
			file := inputFile(t, "opaque.xml", string(data), FormatAppxXML)
			file.Resource.Identity.Provenance.Source = "Microsoft-authored source example; pinned commit and original path in testdata provenance"
			file.Resource.Identity.Provenance.Name = tc.file
			inv, err := Inspect(context.Background(), requestFor(t, file))
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.Apps.Packages) != 1 {
				t.Fatalf("app count: %d", len(inv.Apps.Packages))
			}
			app := inv.Apps.Packages[0]
			if app.Identity.Name != tc.name || app.Identity.Version != tc.version || app.Framework != tc.framework {
				t.Fatalf("identity/framework: %#v", app)
			}
			if tc.dependency != "" && (len(app.Dependencies) != 1 || app.Dependencies[0].Family.Name != tc.dependency) {
				t.Fatalf("dependency: %#v", app.Dependencies)
			}
			if tc.file == "msix-Sample_AppxManifest.xml" && (app.Identity.ResourceID != "NorthAmerica" || len(app.TargetDeviceFamilies) != 1 || len(app.Applications) != 1 || app.Applications[0].ID != "Mca.App") {
				t.Fatalf("package/application identity: %#v", app)
			}
			if app.Phase != PhaseUnknown || len(app.Licenses) != 0 {
				t.Fatal("source examples invented provisioning rules or license links")
			}
		})
	}
}

// A license's explicit PFM binding, not its filename, identifies its family;
// parsing public test data must not assert license validity or application linkage.
func TestStoreLicenseRetainsDeclaredFamilyWithoutGuessingLinkage(t *testing.T) {
	data, err := os.ReadFile("testdata/windowsappsdk-main-test-license.xml")
	if err != nil {
		t.Fatal(err)
	}
	file := inputFile(t, "Synthetic.App-license.xml", string(data), FormatStoreLicenseXML)
	file.Resource.Identity.Provenance.Source = "Microsoft WindowsAppSDK 186154b3df20207c6f3398a6dec5de12a4cecd44 installer/test/CreateTestPackages/TestPackage_Framework/main_license.xml; public test license"
	inv, err := Inspect(context.Background(), requestFor(t, file))
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Apps.LicenseDocuments) != 1 {
		t.Fatalf("license records: %d", len(inv.Apps.LicenseDocuments))
	}
	license := inv.Apps.LicenseDocuments[0]
	if license.PackageFamilyName != "microsoftcorporationii.appnametestpackage_8wekyb3d8bbwe" || license.BindingType != "Machine" || license.Usage != "Offline" || license.Category != "OEM" || license.Type != "Full" {
		t.Fatalf("license identity lost: %#v", license)
	}
	if len(inv.Apps.Packages) != 0 || inv.Classification == ClassificationSemanticInventory {
		t.Fatal("license filename invented an app/validity")
	}
}
