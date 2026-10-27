//go:build windows && providerproof

package probes

import (
	"context"
	"os"
	"strings"
	"testing"
)

// The required gate matrix remains nonpassing until concrete cases supply full
// native provider/source/image evidence. The separate bounded observation tests
// never substitute for these requirements or use synthetic validator records.
func TestProviderPerformsCrossArchitectureServicing(t *testing.T) {
	f, err := os.Open("../../testdata/compatibility/required-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ledger, err := LoadCases(f)
	if err != nil {
		t.Fatal(err)
	}
	var required []Case
	for _, c := range ledger.Cases {
		if c.Gate == "P" {
			required = append(required, c)
		}
	}
	host, err := observeHost()
	if err != nil {
		t.Fatal(err)
	}
	selected, err := currentHostCases(required, host)
	if err != nil {
		t.Fatal(err)
	}
	var observed []Evidence
	for _, c := range selected {
		t.Run(c.ID, func(t *testing.T) {
			e, err := RunCase(context.Background(), c, nil)
			observed = append(observed, e)
			t.Logf("requested native/process=%s/%s target=%s; observed OS=%s build=%d native/process=%s/%s; invocations=%d", c.Host.NativeArchitecture, c.Host.ProcessArchitecture, c.Target, e.Host.OS, e.Host.Host.WindowsBuild, e.Host.Host.NativeArchitecture, e.Host.Host.ProcessArchitecture, len(e.Invocations))
			if err != nil {
				codes := make([]string, 0, len(e.Blockers))
				for _, b := range e.Blockers {
					codes = append(codes, b.Code)
				}
				t.Fatalf("UNVERIFIED: %s; blockers=%s", e.Status, strings.Join(codes, ","))
			}
			if err := ValidateEvidence([]Case{c}, []Evidence{e}); err != nil {
				t.Fatal(err)
			}
		})
	}
	coverage, err := ValidateArchitectureCoverage(required, observed)
	if err != nil {
		t.Fatalf("UNVERIFIED architecture coverage: %v", err)
	}
	for _, entry := range coverage {
		t.Logf("required=%s host=%s target=%s basis=%s actual-witness=%s native/process=%s/%s", entry.RequiredCaseID, entry.RequiredHost.NativeArchitecture, entry.Target, entry.Basis, entry.WitnessCaseID, entry.WitnessHost.Host.NativeArchitecture, entry.WitnessHost.Host.ProcessArchitecture)
	}
}
