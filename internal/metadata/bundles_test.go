package metadata

import (
	"context"
	"testing"
)

func TestFlatBundleRetainsDeclaredExternalPackageIdentities(t *testing.T) {
	file := inputFile(t, "bundle.xml", `<Bundle xmlns="http://schemas.microsoft.com/appx/2016/bundle" SchemaVersion="5.0"><Identity Name="Example" Publisher="CN=Publisher" Version="2025.1.0.0"/><Packages><Package Type="application" Version="2.0.0.0" Architecture="x64" FileName="app.msix"/><Package Type="resource" Version="2.0.0.0" ResourceId="split.language-en" FileName="en.msix"><Resources><Resource Language="en-gb"/></Resources></Package></Packages></Bundle>`, FormatAppxBundleXML)
	inv, e := Inspect(context.Background(), requestFor(t, file))
	if e != nil {
		t.Fatal(e)
	}
	if len(inv.Apps.Bundles) != 1 || inv.Apps.Bundles[0].Identity.Name != "Example" || len(inv.Apps.Bundles[0].Packages) != 2 || inv.Apps.Bundles[0].Packages[1].FileName != "en.msix" {
		t.Fatalf("bundle declarations lost: %+v", inv.Apps)
	}
}
