package rules

import (
	"encoding/json"
	"os"
	"testing"
	"uupbuilder/internal/metadata"
)

func TestSelectedGenerationUsesInspectedBaseVersion(t *testing.T) {
	data, err := os.ReadFile("testdata/windows-client-28000.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv metadata.Inventory
	if err = json.Unmarshal(data, &inv); err != nil {
		t.Fatal(err)
	}
	generation, err := Select(inv)
	if err != nil {
		t.Fatal(err)
	}
	if generation.Build != 28000 || !generation.Checkpoint || !generation.OfflineMSU {
		t.Fatalf("wrong servicing applicability: %+v", generation)
	}
	editions, _, err := Editions(inv, []string{"professional"}, nil)
	if err != nil || len(editions) != 1 || editions[0].Edition != "Professional" || editions[0].Derive {
		t.Fatalf("CompDB edition not usable before assembly: %+v, %v", editions, err)
	}
	inv.Images = []metadata.Image{{Edition: "Professional", Build: "10.0.26100.1"}}
	if _, err := Select(inv); err == nil {
		t.Fatal("conflicting base generations accepted")
	}
}
