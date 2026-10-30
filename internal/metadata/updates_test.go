package metadata

import (
	"context"
	"errors"
	"testing"
	"uupbuilder/internal/model"
)

func TestUpdateFactsRequireBoundEvidenceAndOwnCollections(t *testing.T) {
	file := inputFile(t, "update.xml", `<WIM/>`, FormatWIMXML)
	req := requestFor(t, file)
	evidence := evidenceFor(file)
	update := Update{ID: "checkpoint", Kind: UpdateCheckpoint, Format: UpdateMSU, Resource: evidence.Document.Resource, Packages: []PackageIdentity{{Name: "Package_for_RollupFix", Version: "28000.1.1.1", Architecture: model.ArchitectureARM64}}, Predecessors: []string{"ssu"}, Editions: []string{"Professional"}, Members: []string{"update.cab"}, Evidence: evidence}
	req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{Updates: []Update{update}}}}}
	inv, err := Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Updates) != 1 {
		t.Fatal("bound update fact dropped")
	}
	update.Packages[0].Name = "mutated"
	update.Predecessors[0] = "mutated"
	update.Editions[0] = "mutated"
	update.Members[0] = "mutated"
	if inv.Updates[0].Packages[0].Name != "Package_for_RollupFix" || inv.Updates[0].Predecessors[0] != "ssu" || inv.Updates[0].Editions[0] != "Professional" || inv.Updates[0].Members[0] != "update.cab" {
		t.Fatal("provider mutated returned update facts")
	}
	update.Evidence.Source.UpdateID = "another-source"
	req.Inspections[0].Provider = syntheticProvider{ProviderResult{Updates: []Update{update}}}
	if _, err = Inspect(context.Background(), req); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("unbound servicing fact accepted: %v", err)
	}
}

func TestRegularUpdateFactsRequireOriginalBoundEvidence(t *testing.T) {
	file := inputFile(t, "ordinary.xml", `<WIM/>`, FormatWIMXML)
	req := requestFor(t, file)
	evidence := evidenceFor(file)
	update := Update{ID: "ordinary-update", Kind: UpdateKind("update"), Format: UpdateCAB, Resource: evidence.Document.Resource, Packages: []PackageIdentity{{Name: "Package_for_OrdinaryFix", Version: "12345.6.1.0", Architecture: model.ArchitectureARM64}}, Evidence: evidence}
	req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{Updates: []Update{update}}}}}
	inv, err := Inspect(context.Background(), req)
	if err != nil || len(inv.Updates) != 1 || inv.Updates[0].Kind != UpdateKind("update") {
		t.Fatalf("bound regular update rejected: %+v %v", inv.Updates, err)
	}
	update.Evidence.Source.UpdateID = "foreign-source"
	req.Inspections[0].Provider = syntheticProvider{ProviderResult{Updates: []Update{update}}}
	if _, err = Inspect(context.Background(), req); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("unbound regular update accepted:%v", err)
	}
}

func TestUpdateTargetsValidateKnownRolesAndPreserveWinREFact(t *testing.T) {
	file := inputFile(t, "scope.xml", `<WIM/>`, FormatWIMXML)
	e := evidenceFor(file)
	for _, target := range []Role{"", RoleOS, RoleWinRE, RoleSetup, "future-invalid-role"} {
		req := requestFor(t, file)
		update := Update{ID: "scope", Kind: UpdateRegular, Target: target, Format: UpdateCAB, Resource: e.Document.Resource, Packages: []PackageIdentity{{Name: "Package_for_Scope", Version: "1.0.0.0", Architecture: "arm64"}}, Evidence: e}
		req.Inspections = []Inspection{{Resource: file.Resource, Provider: syntheticProvider{ProviderResult{Updates: []Update{update}}}}}
		inv, err := Inspect(context.Background(), req)
		if target == "future-invalid-role" || target == RoleSetup {
			if !errors.Is(err, ErrInvalidEvidence) {
				t.Fatalf("unknown target accepted:%v", err)
			}
		} else if err != nil || len(inv.Updates) != 1 || inv.Updates[0].Target != target {
			t.Fatalf("target%q fact lost:%+v %v", target, inv.Updates, err)
		}
	}
}
