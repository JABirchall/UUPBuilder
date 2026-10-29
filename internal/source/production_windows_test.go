package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/providers"
	"uupbuilder/internal/model"
)

// Explicit private fixture configuration keeps Microsoft payloads out of the
// repository. This is actual metadata evidence, never conversion acceptance.
func TestRetainedCanonicalContainerDiscovery(t *testing.T) {
	root := os.Getenv("UUP_RETAINED_SOURCE_ROOT")
	if root == "" {
		t.Skip("actual retained source fixture not configured")
	}
	ctx := context.Background()
	data, err := os.ReadFile(filepath.Join(root, "22000-arm64-aggregatedmetadata.cab"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if len(data) != 1146246 || hex.EncodeToString(sum[:]) != "245c6f6e69081a504b20a16da4566b330dc8011bd89a2747cca9dbe083a1aa21" {
		t.Fatal("retained CAB identity changed")
	}
	s := model.Selection{UpdateID: "a1b78728-530f-443f-b672-d742e7c14bcb", Architecture: "arm64", Language: "en-us", Editions: []string{"professional"}}
	src := model.SourceIdentity{UpdateID: s.UpdateID, BuildLabel: "22000.1", Architecture: s.Architecture, Language: s.Language}
	p := model.Payload{Destination: "a1b78728-530f-443f-b672-d742e7c14bcb.aggregatedmetadata.cab", Identity: model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA1, Value: "fc9cd5aa6972bc862550ce1baa2f0a4a44b47e2b"}, Size: 1146246, Provenance: model.PackageProvenance{Source: "uupdump:get.php:" + s.UpdateID, Name: "a1b78728-530f-443f-b672-d742e7c14bcb.aggregatedmetadata.cab"}}}
	d := Discovery{Catalog: retainedCatalog{set: catalog.FileSet{Source: src, Payloads: []model.Payload{p}}}}
	plan, err := d.Metadata(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _, err := unionSets(plan.Source, plan.Sets)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := metadata.Inspect(ctx, metadata.InspectRequest{Source: src, Manifest: manifest, Inspections: []metadata.Inspection{{Resource: metadata.LocalResource{Identity: p.Identity, Path: filepath.Join(root, "22000-arm64-aggregatedmetadata.cab")}, Provider: plan.Inputs[0].Provider}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Compositions) != 1 || inv.Compositions[0].BuildID != "b5347a24-b65f-7c51-ac95-8bdd36d866a1" || inv.Compositions[0].OSVersion != "10.0.22000.1" || len(inv.Compositions[0].Packages) != 44 || len(inv.Documents) != 1 || inv.Documents[0].Reference.SHA256 != "3f1705c8ed1b8a2ff5b52899929536acebe760810561de4a16877ba41343cb90" {
		t.Fatalf("actual CompDB diverged: %+v", inv.Compositions)
	}
	t.Logf("actual CAB: source=%s arch=arm64 build=22000.1 canonical-packages=44 XML-SHA256=%s classification=%s gaps=%d", s.UpdateID, inv.Documents[0].Reference.SHA256, inv.Classification, len(inv.Gaps))
	path := filepath.Join(root, "microsoft-windows-foundation-package.esd")
	r := metadata.LocalResource{Path: path, Identity: model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA1, Value: "4004898a7fd7f2521fb2a8069a599ecf1fa6bbe3"}, Size: 21506, Provenance: model.PackageProvenance{Source: "uupdump:get.php:" + s.UpdateID, Name: "microsoft-windows-foundation-package.esd"}}}
	observed, err := (providers.WIM{}).Inspect(ctx, r, metadata.Limits{})
	if err != nil || len(observed.Documents) != 1 {
		t.Fatalf("actual canonical WIM XML: %+v %v", observed, err)
	}
	xsum := sha256.Sum256(observed.Documents[0].Original)
	t.Logf("actual WIM XML: input-SHA1=%s bytes=%d XML-SHA256=%x; file reconstruction/servicing not performed", r.Identity.Digest.Value, len(observed.Documents[0].Original), xsum)
}

type retainedCatalog struct{ set catalog.FileSet }

func (c retainedCatalog) Files(context.Context, string, string, string) (catalog.FileSet, error) {
	return c.set, nil
}
func (retainedCatalog) Editions(context.Context, string, string) ([]catalog.Edition, error) {
	return []catalog.Edition{{ID: "professional"}}, nil
}
