package source

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"uupbuilder/internal/engine/rules"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// Factual projection of original retained nested CBS manifests, read natively
// on 2026-10-30. Original document SHA256 values:
// KB5043080 2c047cb271b66c931bc2c015a79b87737041c9136ff201419c2fc79aca0e3ff0
// KB5127936 069c0d6adf88ef901470afea57046a5faef2d8eb074d04e44d3de4bcbc7c882d
// Only installation identity, package attributes and Professional parent are
// projected; the retained originals also include alternative editions/WinPE.
func checkpointFixture(t *testing.T, base string) metadata.Inventory {
	t.Helper()
	inv, _ := mediaFixture(t)
	inv.Images[2].Build = base
	return inv
}

func checkpointPackage(inv *metadata.Inventory, id, version, baseline, arch, token, comparison string, extraParent string) {
	identity := metadata.PackageIdentity{Name: "Package_for_RollupFix", Version: version, Architecture: model.Architecture(arch), Language: "neutral", PublicKeyToken: token}
	body := []byte(fmt.Sprintf(`<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"><assemblyIdentity name="Package_for_RollupFix" version="%s" processorArchitecture="%s" language="neutral" publicKeyToken="%s"/><package identifier="%s" releaseType="Update"><parent revisionCompare="%s" integrate="standalone" disposition="detect"><assemblyIdentity name="Microsoft-Windows-ProfessionalEdition" version="%s" processorArchitecture="%s" language="neutral" publicKeyToken="%s"/>%s</parent></package></assembly>`, version, arch, token, id, comparison, baseline, arch, token, extraParent))
	sum := sha256.Sum256(body)
	ref := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: inv.Manifest.Payloads[0].Identity, Member: id + "/update.mum"}, SHA256: hex.EncodeToString(sum[:])}
	evidence := metadata.Evidence{Source: inv.Source, Document: ref, Selector: "/assembly/assemblyIdentity"}
	inv.Documents = append(inv.Documents, metadata.Document{Reference: ref, Format: metadata.FormatCBSXML, Original: body})
	inv.Packages = append(inv.Packages, metadata.Package{Identity: identity, Identifier: id, ReleaseType: "Update", Evidence: evidence})
	inv.Updates = append(inv.Updates, metadata.Update{ID: id, Kind: metadata.UpdateCumulative, Format: metadata.UpdateMSU, Resource: metadata.ResourceReference{Payload: ref.Resource.Payload}, Packages: []metadata.PackageIdentity{identity}, Evidence: evidence})
}

func actualCheckpointPair(t *testing.T, base string) metadata.Inventory {
	inv := checkpointFixture(t, base)
	checkpointPackage(&inv, "KB5127936", "26100.9818.1.42", "10.0.26100.1742", "amd64", "31bf3856ad364e35", "GE", "")
	checkpointPackage(&inv, "KB5043080", "26100.1742.1.10", "10.0.26100.1", "amd64", "31bf3856ad364e35", "GE", "")
	return inv
}

func TestMediaCheckpointActualCBSBaselineDerivesRequiredPredecessor(t *testing.T) {
	inv := actualCheckpointPair(t, "10.0.26100.1")
	if err := bindMediaUpdateRelationships(&inv); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(inv.Updates[0].Predecessors, []string{"KB5043080"}) || len(inv.Updates[1].Predecessors) != 0 {
		t.Fatalf("source baseline chain lost: %+v", inv.Updates)
	}
	if !slices.Equal(inv.Updates[0].Editions, []string{"Professional"}) {
		t.Fatalf("edition scope changed: %+v", inv.Updates[0])
	}
	settings := model.ResolvedSettings{Conversion: model.ConversionSettings{Updates: model.UpdatesIntegrate, CumulativeMSU: model.MSUAuto}}
	ordered, err := rules.OrderUpdates(inv, settings, rules.Generation{ID: "inspected-source", OfflineMSU: true, Checkpoint: true})
	if err != nil || len(ordered) != 2 || ordered[0].ID != "KB5043080" || ordered[1].ID != "KB5127936" || ordered[0].Expand || ordered[1].Expand {
		t.Fatalf("source checkpoint plan = %+v, error %v", ordered, err)
	}
}

func TestMediaCheckpointParentComparisonKeepsOriginalEvidence(t *testing.T) {
	inv := actualCheckpointPair(t, "10.0.26100.1")
	groups, err := mediaCBSParentGroups(&inv)
	if err != nil {
		t.Fatal(err)
	}
	parent := groups[inv.Packages[0].Evidence.Document][0]
	if parent.RevisionCompare != "GE" || parent.Integrate != "standalone" || parent.Disposition != "detect" || parent.Evidence.Source != inv.Source || parent.Evidence.Document != inv.Documents[0].Reference || parent.Evidence.Selector != "/assembly/package/parent[1]" {
		t.Fatalf("CBS comparison/evidence lost: %+v", parent)
	}
}

func TestMediaCheckpointRecursivelyRequiresProvidersOwnBaseline(t *testing.T) {
	inv := checkpointFixture(t, "10.0.44555.1")
	checkpointPackage(&inv, "latest", "44555.9000.1.0", "10.0.44555.5000", "amd64", "publisher", "GE", "")
	checkpointPackage(&inv, "middle", "44555.5000.1.0", "10.0.44555.1000", "amd64", "publisher", "GE", "")
	if err := bindMediaUpdateRelationships(&inv); err == nil {
		t.Fatal("provider's own missing baseline ignored")
	}
	checkpointPackage(&inv, "first", "44555.1000.1.0", "10.0.44555.1", "amd64", "publisher", "GE", "")
	if err := bindMediaUpdateRelationships(&inv); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(inv.Updates[0].Predecessors, []string{"middle"}) || !slices.Equal(inv.Updates[1].Predecessors, []string{"first"}) {
		t.Fatalf("transitive supplied baseline chain lost: %+v", inv.Updates)
	}
}

func TestMediaCheckpointSourceAlreadySatisfiesMinimum(t *testing.T) {
	inv := checkpointFixture(t, "10.0.26100.5000")
	checkpointPackage(&inv, "target", "26100.9818.1.42", "10.0.26100.1742", "amd64", "31bf3856ad364e35", "GE", "")
	if err := bindMediaUpdateRelationships(&inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Updates[0].Predecessors) != 0 {
		t.Fatal("installed baseline invented predecessor")
	}
}

func TestMediaCheckpointRejectsMissingBaselineProvider(t *testing.T) {
	inv := checkpointFixture(t, "10.0.26100.1")
	checkpointPackage(&inv, "target", "26100.9818.1.42", "10.0.26100.1742", "amd64", "31bf3856ad364e35", "GE", "")
	if err := bindMediaUpdateRelationships(&inv); err == nil {
		t.Fatal("required checkpoint baseline was treated as edition-only applicability")
	}
}

func TestMediaCheckpointRejectsWrongProviderOrComparison(t *testing.T) {
	for _, tc := range []struct{ name, arch, token, version, compare string }{
		{"cross-architecture", "arm64", "31bf3856ad364e35", "26100.1742.1.10", "GE"},
		{"cross-token", "amd64", "0123456789abcdef", "26100.1742.1.10", "GE"},
		{"cross-build", "amd64", "31bf3856ad364e35", "26000.1742.1.10", "GE"},
		{"bad-comparison", "amd64", "31bf3856ad364e35", "26100.1742.1.10", "LT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inv := checkpointFixture(t, "10.0.26100.1")
			checkpointPackage(&inv, "target", "26100.9818.1.42", "10.0.26100.1742", "amd64", "31bf3856ad364e35", tc.compare, "")
			checkpointPackage(&inv, "prior", tc.version, "10.0.26100.1", tc.arch, tc.token, "GE", "")
			if err := bindMediaUpdateRelationships(&inv); err == nil {
				t.Fatal("unsupported baseline relationship accepted")
			}
		})
	}
}

func TestMediaCheckpointRejectsAmbiguousBaselineProvider(t *testing.T) {
	inv := actualCheckpointPair(t, "10.0.26100.1")
	checkpointPackage(&inv, "duplicate-provider", "26100.1742.1.10", "10.0.26100.1", "amd64", "31bf3856ad364e35", "GE", "")
	if err := bindMediaUpdateRelationships(&inv); err == nil {
		t.Fatal("ambiguous same-baseline sources accepted")
	}
}

func TestMediaCheckpointRejectsUnknownBuildComparison(t *testing.T) {
	inv := actualCheckpointPair(t, "10.0.26100.1")
	inv.Documents[0].Original = []byte(strings.Replace(string(inv.Documents[0].Original), `revisionCompare="GE"`, `buildCompare="LT" revisionCompare="GE"`, 1))
	if err := bindMediaUpdateRelationships(&inv); err == nil || !strings.Contains(err.Error(), `buildCompare="LT"`) || !strings.Contains(err.Error(), "KB5127936/update.mum") {
		t.Fatalf("unknown build comparison was accepted or lost its original source context: %v", err)
	}
}

func TestMediaCheckpointRetainsEditionAlternativesAndOtherRequiredGroups(t *testing.T) {
	inv := actualCheckpointPair(t, "10.0.26100.1")
	doc := &inv.Documents[0]
	text := strings.Replace(string(doc.Original), "</parent>", `<assemblyIdentity name="Microsoft-Windows-EnterpriseEdition" version="10.0.26100.1742" processorArchitecture="amd64" language="neutral" publicKeyToken="31bf3856ad364e35"/></parent>`, 1)
	doc.Original = []byte(text)
	if err := bindMediaUpdateRelationships(&inv); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(inv.Updates[0].Editions, []string{"Professional", "Enterprise"}) {
		t.Fatal("unselected OR edition lost")
	}
	doc.Original = []byte(strings.Replace(text, "</package>", `<parent><assemblyIdentity name="Unexamined.Required.Package" version="1.0.0.0" processorArchitecture="amd64"/></parent></package>`, 1))
	if err := bindMediaUpdateRelationships(&inv); err == nil {
		t.Fatal("checkpoint relationship erased separate required parent group")
	}
}
