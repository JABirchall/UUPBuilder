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
