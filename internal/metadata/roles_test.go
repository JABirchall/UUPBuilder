package metadata

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Accepting a role for an uninspected image, conflicting roles/absence, or a
// layout that disagrees with inspected OS properties must fail these cases.
func TestSemanticEvidenceRejectsContradictions(t *testing.T) {
	for _, name := range []string{"index", "roles", "absence", "layout", "fact-limit"} {
		t.Run(name, func(t *testing.T) {
			file := inputFile(t, "metadata.xml", `<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>12</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`, FormatWIMXML)
			req := requestFor(t, file)
			e := evidenceFor(file)
			result := ProviderResult{}
			want := ErrConflictingMetadata
			switch name {
			case "index":
				result.Roles = []RoleEvidence{{Role: RoleSetup, Resource: e.Document.Resource, ImageIndex: 99, Evidence: e}}
				want = ErrInvalidEvidence
			case "roles":
				result.Roles = []RoleEvidence{{Role: RoleSetup, Resource: e.Document.Resource, ImageIndex: 1, Evidence: e}}
			case "absence":
				result.Absences = []AbsenceEvidence{{Role: RoleOS, Reason: "synthetic", Evidence: e}}
			case "layout":
				result.Layouts = []LayoutEvidence{{Kind: LayoutUpdateOnly, Family: "synthetic", Evidence: e}}
			case "fact-limit":
				req.Limits.MaxXMLTokens = 100
				result.Absences = make([]AbsenceEvidence, 101)
				for i := range result.Absences {
					result.Absences[i] = AbsenceEvidence{Role: RoleSetup, Reason: "synthetic", Evidence: e}
				}
				want = ErrLimit
			}
			req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{result}}}
			if _, err := Inspect(context.Background(), req); !errors.Is(err, want) {
				t.Fatalf("want %v, got %v", want, err)
			}
		})
	}
}

// Duplicate singleton/attribute values must not silently select a convenient
// architecture or property; DTDs and nesting must be bounded or rejected.
func TestXMLRejectsAmbiguousOrUnboundedMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		limits     Limits
		want       error
	}{
		{"duplicate-arch", `<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>12</ARCH><ARCH>9</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`, Limits{}, ErrConflictingMetadata},
		{"duplicate-attribute", `<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" SchemaVersion="1.2" BuildArch="arm64" BuildArch="x86"/>`, Limits{}, ErrMalformedMetadata},
		{"duplicate-properties", `<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Synthetic" Publisher="CN=Synthetic" Version="1.0.0.0"/><Properties><Framework>true</Framework><Framework>false</Framework></Properties></Package>`, Limits{}, ErrConflictingMetadata},
		{"doctype", `<!DOCTYPE WIM [<!ENTITY x "invalid">]><WIM/>`, Limits{}, ErrMalformedMetadata},
		{"depth", `<WIM><A><B><C/></B></A></WIM>`, Limits{MaxXMLDepth: 3}, ErrLimit},
		{"tokens", `<WIM>` + strings.Repeat(`<A/>`, 20) + `</WIM>`, Limits{MaxXMLTokens: 10}, ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			format := FormatWIMXML
			if tc.name == "duplicate-attribute" {
				format = FormatCompositionXML
			}
			if tc.name == "duplicate-properties" {
				format = FormatAppxXML
			}
			file := inputFile(t, "metadata.xml", tc.text, format)
			req := requestFor(t, file)
			req.Limits = tc.limits
			if _, err := Inspect(context.Background(), req); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

// A framework of the wrong architecture must not satisfy dependency closure.
func TestAppDependencyClosureRequiresCompatibleArchitecture(t *testing.T) {
	app := inputFile(t, "app.xml", `<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Synthetic.App" Publisher="CN=Synthetic" Version="1.0.0.0" ProcessorArchitecture="arm64"/><Dependencies><PackageDependency Name="Synthetic.Framework" Publisher="CN=Synthetic" MinVersion="1.0.0.0"/></Dependencies></Package>`, FormatAppxXML)
	framework := inputFile(t, "framework.xml", `<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Synthetic.Framework" Publisher="CN=Synthetic" Version="1.0.0.0" ProcessorArchitecture="x64"/><Properties><Framework>true</Framework></Properties></Package>`, FormatAppxXML)
	inv, err := Inspect(context.Background(), requestFor(t, app, framework))
	if err != nil {
		t.Fatal(err)
	}
	for _, gap := range inv.Gaps {
		if gap.Code == "app-dependency-unresolved" {
			return
		}
	}
	t.Fatal("wrong-architecture framework satisfied app dependency")
}

// Optional recovery material's explicit absence does not make standard setup/OS
// media unavailable. Its applicability belongs to the later settings resolver.
func TestExplicitWinREAbsenceDoesNotBlanketClassifySourceUnavailable(t *testing.T) {
	file := inputFile(t, "proof.xml", `<WIM/>`, FormatWIMXML)
	req := requestFor(t, file)
	req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{Absences: []AbsenceEvidence{{Role: RoleWinRE, Reason: "Synthetic explicit absence of optional recovery", Evidence: evidenceFor(file)}}}}}}
	inv, err := Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Classification == ClassificationSourceUnavailable || len(inv.Absences) != 1 {
		t.Fatalf("optional WinRE absence overclaimed: %s", inv.Classification)
	}
}

// A semantic setup/recovery role must not bypass the same target-architecture
// checks as an OS image. Missing architecture remains an explicit, source-bound
// gap; a matching architecture must not receive that gap.
func TestExplicitImageRoleValidatesArchitecture(t *testing.T) {
	for _, role := range []Role{RoleSetup, RoleWinRE} {
		for _, tc := range []struct {
			name, architectureXML string
			wantConflict, wantGap bool
		}{
			{"mismatch", "<ARCH>0</ARCH>", true, false},
			{"missing", "", false, true},
			{"matching", "<ARCH>12</ARCH>", false, false},
		} {
			t.Run(string(role)+"/"+tc.name, func(t *testing.T) {
				file := inputFile(t, "opaque.xml", `<WIM><IMAGE INDEX="8"><WINDOWS>`+tc.architectureXML+`<INSTALLATIONTYPE>WindowsPE</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`, FormatWIMXML)
				req := requestFor(t, file)
				evidence := evidenceFor(file)
				req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{Roles: []RoleEvidence{{Role: role, Resource: evidence.Document.Resource, ImageIndex: 8, Evidence: evidence}}}}}}
				inv, err := Inspect(context.Background(), req)
				if tc.wantConflict {
					if !errors.Is(err, ErrConflictingMetadata) {
						t.Fatalf("want architecture conflict for %s, got %v", role, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(inv.Roles) != 1 || inv.Roles[0].Role != role {
					t.Fatalf("semantic role lost: %#v", inv.Roles)
				}
				gotGap := false
				for _, gap := range inv.Gaps {
					if gap.Code == "image-architecture-unresolved" {
						gotGap = true
						if gap.Document == nil || *gap.Document != evidence.Document {
							t.Fatal("architecture gap lost original image metadata reference")
						}
					}
				}
				if gotGap != tc.wantGap {
					t.Fatalf("architecture gap: got %v, want %v", gotGap, tc.wantGap)
				}
			})
		}
	}
}
