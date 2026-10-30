package metadata

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func appPolicyInventory(t *testing.T, version string) (Inventory, DocumentReference) {
	t.Helper()
	raw := fmt.Sprintf(`<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" SchemaVersion="1.2" Type="Build" Product="Desktop" BuildID="arbitrary-build" BuildArch="arm64" OSVersion="%s"><Features/><Packages/></CompDB>`, version)
	file := inputFile(t, "apps.xml", raw, FormatCompositionXML)
	inv, err := Inspect(context.Background(), requestFor(t, file))
	if err != nil {
		t.Fatal(err)
	}
	return inv, inv.Documents[0].Reference
}

func TestBindAppPoliciesUsesSourceBaselineInsteadOfReleasePin(t *testing.T) {
	for _, version := range []string{"10.0.19041.1", "10.0.26100.1", "10.0.28000.1", "10.0.40000.1"} {
		t.Run(version, func(t *testing.T) {
			inv, doc := appPolicyInventory(t, version)
			inv.Images = []Image{{Edition: "Professional", InstallationType: "Client", Build: version, Architecture: inv.Source.Architecture}}
			if _, err := BindAppPolicies(context.Background(), inv, doc); err != nil {
				t.Fatalf("same-schema source rejected by release: %v", err)
			}
		})
	}
}

func TestBindAppPoliciesRejectsMismatchedAndMalformedBaseline(t *testing.T) {
	inv, doc := appPolicyInventory(t, "10.0.26100.1")
	inv.Images = []Image{{Edition: "Professional", InstallationType: "Client", Build: "10.0.28000.1", Architecture: inv.Source.Architecture}}
	if _, err := BindAppPolicies(context.Background(), inv, doc); err == nil || !strings.Contains(err.Error(), "baseline") {
		t.Fatalf("foreign app baseline accepted or misdiagnosed: %v", err)
	}
	for _, version := range []string{"10.0.garbage.1", "10.0.26100", "-1.0.26100.1"} {
		inv, doc := appPolicyInventory(t, version)
		if _, err := BindAppPolicies(context.Background(), inv, doc); err == nil {
			t.Fatalf("malformed baseline %q accepted", version)
		}
	}
}
