package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

func scopeCBSFixture(t *testing.T, name, parents string) (metadata.Inventory, error) {
	t.Helper()
	archive := []byte("verified container for CBS scope fixture")
	sum := sha256.Sum256(archive)
	p := sourcePayload("scope.cab", "a")
	p.Identity.Size = int64(len(archive))
	p.Identity.Digest.Value = hex.EncodeToString(sum[:])
	m, err := model.NewPayloadManifest(sourceIdentity(), []model.Payload{p})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "scope.data")
	if err = os.WriteFile(file, archive, 0600); err != nil {
		t.Fatal(err)
	}
	body := []byte(fmt.Sprintf(`<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"><assemblyIdentity name="%s" version="12345.6.1.0" processorArchitecture="amd64" language="neutral" publicKeyToken="publisher"/><package identifier="Synthetic.Scope" releaseType="Update">%s</package></assembly>`, name, parents))
	inv := metadata.Inventory{Source: m.Source, Manifest: m}
	r := mediaNativeRun{}
	err = r.addCBS(context.Background(), &inv, p.Identity, file, []metadata.MetadataDocument{{Resource: metadata.ResourceReference{Payload: p.Identity, Member: "update.mum"}, Format: metadata.FormatCBSXML, Original: body, Provenance: "verified test container extraction"}}, false)
	return inv, err
}

func TestMediaSafeOSScopeRequiresOriginalExclusiveRejuvParents(t *testing.T) {
	parent := `<parent buildCompare="EQ" integrate="separate" disposition="detect"><assemblyIdentity name="WinPE-Rejuv-Package" version="10.0.12345.1" processorArchitecture="amd64" language="neutral" publicKeyToken="publisher"/></parent>`
	inv, err := scopeCBSFixture(t, "Package_for_SafeOSDU", parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Updates) != 1 || inv.Updates[0].Target != metadata.RoleWinRE {
		t.Fatalf("verified recovery scope lost:%+v", inv.Updates)
	}
	beforeDocs, beforePackages, beforeUpdates := len(inv.Documents), len(inv.Packages), len(inv.Updates)
	if err = bindMediaUpdateRelationships(&inv); err != nil {
		t.Fatalf("excluded recovery prerequisites applied to OS:%v", err)
	}
	if len(inv.Documents) != beforeDocs || len(inv.Packages) != beforePackages || len(inv.Updates) != beforeUpdates || inv.Updates[0].Target != metadata.RoleWinRE {
		t.Fatal("excluded recovery source facts removed")
	}
	inv.Documents[0].Original = append(inv.Documents[0].Original, []byte("<!-- altered -->")...)
	if err = bindMediaUpdateRelationships(&inv); err == nil {
		t.Fatal("WinRE scope trusted after its original document changed")
	}
	for _, tc := range []struct{ name, parents string }{{"missing-parent", ""}, {"mixed-parent", parent + `<parent><assemblyIdentity name="Microsoft-Windows-ProfessionalEdition" version="10.0.12345.1" processorArchitecture="amd64" language="neutral" publicKeyToken="publisher"/></parent>`}, {"lookalike-parent", `<parent><assemblyIdentity name="WinPE-Rejuv-Package-Lookalike" version="10.0.12345.1" processorArchitecture="amd64" language="neutral" publicKeyToken="publisher"/></parent>`}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := scopeCBSFixture(t, "Package_for_SafeOSDU", tc.parents); err == nil {
				t.Fatal("ambiguous recovery scope accepted")
			}
		})
	}
	ordinary, err := scopeCBSFixture(t, "Package_for_SafeOSDU_Lookalike", parent)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.Updates[0].Target == metadata.RoleWinRE {
		t.Fatal("ordinary lookalike update silently moved out of OS")
	}
	if err = bindMediaUpdateRelationships(&ordinary); err == nil {
		t.Fatal("ordinary OS prerequisite was silently skipped")
	}
}
