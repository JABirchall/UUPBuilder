package probes

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"uupbuilder/internal/model"
)

func requiredMatrix() []Case {
	var cases []Case
	for _, host := range []model.Architecture{"x86", "amd64", "arm64"} {
		for _, target := range []model.Architecture{"x86", "amd64", "arm64"} {
			cases = append(cases, Case{
				ID: string(host) + "-" + string(target), Gate: "P",
				Host: HostRequirement{"windows", 10240, host, host}, Target: target,
				SourceFamily: "canonical", Operations: []Operation{Extract, Service, Reconstruct, MasterISO},
				Pending: []Blocker{{"fixture-missing", "No independently verified image fixture is available."}},
			})
		}
	}
	return cases
}

// Removing a pair check must fail, while adding future targets must stay possible.
func TestRequiredHostTargetCases(t *testing.T) {
	cases := requiredMatrix()
	if err := ValidateRequiredCases(cases); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequiredCases(cases[:8]); err == nil {
		t.Fatal("missing ARM64/ARM64 pair accepted")
	}
	cases[8] = cases[7]
	if err := ValidateRequiredCases(cases); err == nil {
		t.Fatal("duplicate pair accepted")
	}
	cases = requiredMatrix()
	for _, host := range []model.Architecture{"x86", "amd64", "arm64"} {
		c := cases[0]
		c.ID = string(host) + "-future"
		c.Host.NativeArchitecture = host
		c.Host.ProcessArchitecture = host
		c.Target = "future-target"
		cases = append(cases, c)
	}
	if err := ValidateRequiredCases(cases); err != nil {
		t.Fatalf("future target hidden: %v", err)
	}
}

func TestRequiredDescriptorsRejectMalformedCases(t *testing.T) {
	for name, mutate := range map[string]func(*Case){
		"native mismatch":     func(c *Case) { c.Host.ProcessArchitecture = "x86" },
		"unknown operation":   func(c *Case) { c.Operations = []Operation{"export-only"} },
		"empty blocker":       func(c *Case) { c.Pending = []Blocker{{}} },
		"duplicate operation": func(c *Case) { c.Operations = append(c.Operations, Extract) },
		"bad metadata digest": func(c *Case) {
			c.Inputs = []Artifact{{ID: "metadata", Role: "metadata", Size: 1, Provenance: "record", Digest: model.Digest{Algorithm: "sha256", Value: "1234"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := requiredMatrix()[3]
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("malformed descriptor accepted")
			}
		})
	}
}

func TestRequiredLedgerRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	for _, document := range []string{`{"schema_version":1,"cases":[],"source_census":{},"pretend_pass":true}`, `{"schema_version":1} {}`, `{"schema_version":2}`} {
		if _, err := LoadCases(strings.NewReader(document)); err == nil {
			t.Fatalf("invalid ledger accepted: %s", document)
		}
	}
}

func TestRequiredLedgerRejectsOversizeData(t *testing.T) {
	valid := CaseLedger{SchemaVersion: 1, Cases: requiredMatrix(), Census: SourceCensus{Limitations: []string{"unit-only census"}, Families: []SourceFamily{{ID: "future", Observation: "unknown", Availability: "unknown", Implementation: "unknown", MediaCapability: "unknown", Proof: Unverified, Gaps: []string{"not surveyed"}}}}}
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCases(strings.NewReader(string(encoded))); err != nil {
		t.Fatalf("valid control ledger rejected: %v", err)
	}
	if _, err := LoadCases(strings.NewReader(string(encoded) + strings.Repeat(" ", 4<<20))); err == nil {
		t.Fatal("oversize ledger accepted")
	}
}

func TestRequiredCheckedInCasesRemainPending(t *testing.T) {
	f, err := os.Open("../../testdata/compatibility/required-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ledger, err := LoadCases(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Cases) < 9 || ledger.Census.Complete {
		t.Fatal("required cases or census incompleteness lost")
	}
	for _, c := range ledger.Cases {
		if c.ValidateReady() == nil {
			t.Fatalf("research-only case %s became proof-ready", c.ID)
		}
	}
	for _, family := range ledger.Census.Families {
		if family.Proof == Passed || family.Availability == "unavailable" {
			t.Fatalf("unsupported research claim for %s", family.ID)
		}
	}
}
