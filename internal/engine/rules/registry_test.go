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

func TestGenerationCapabilitiesFollowInspectedVersionsNotSourceLabels(t *testing.T) {
	for _, build := range []string{"10.0.10240.1", "10.0.19045.4291", "10.0.22000.1", "10.0.26100.1", "10.0.26300.9818", "10.0.29000.5"} {
		t.Run(build, func(t *testing.T) {
			inv := metadata.Inventory{Images: []metadata.Image{{Edition: "Professional", Build: build}}}
			inv.Source.BuildLabel = "untrusted release label"
			generation, err := Select(inv)
			if err != nil {
				t.Fatal(err)
			}
			if !generation.OfflineMSU || !generation.Cleanup || !generation.ResetBase {
				t.Fatalf("offline Windows 10.0 servicing capabilities missing: %+v", generation)
			}
			if generation.Checkpoint != (generation.Build >= 26100) {
				t.Fatalf("checkpoint feature boundary: %+v", generation)
			}
		})
	}
	for _, version := range []string{"", "10.0.bad.1", "10.0", "11.0.30000.1", "10.0.26100.1.7", "6.3.9600.1"} {
		if _, err := Select(metadata.Inventory{Images: []metadata.Image{{Edition: "Professional", Build: version}}}); err == nil {
			t.Fatalf("unsupported or incomplete inspected version %q accepted", version)
		}
	}
}

func TestGenerationSupportsServerAndOlderOfflineMSUWithoutCheckpoint(t *testing.T) {
	generation, err := Select(metadata.Inventory{Images: []metadata.Image{{Edition: "ServerStandard", InstallationType: "Server", Build: "10.0.20348.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if generation.Build != 20348 || generation.Checkpoint || !generation.OfflineMSU {
		t.Fatalf("server offline capability mismatch: %+v", generation)
	}
}
