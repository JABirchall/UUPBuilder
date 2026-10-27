package probes

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"uupbuilder/internal/model"
)

// All records in this file are synthetic validator fixtures, never runtime
// proof, build evidence, or a claim that any provider/source family works.
func unitCoverageRecord(host, target model.Architecture) (Case, Evidence) {
	c, e := unitRecord()
	c.ID = fmt.Sprintf("unit-%s-%s", host, target)
	c.Host.NativeArchitecture, c.Host.ProcessArchitecture = host, host
	c.Target, c.Source.Architecture = target, target
	for i := range c.Components {
		c.Components[i].NativeArchitecture = host
	}
	// Native component bytes differ across hosts; they are not portable output
	// expectations and must not be alleged to have executed elsewhere.
	if host != "amd64" {
		c.Components[0].Artifact.Digest.Value = strings.Repeat("2", 64)
	}
	e.CaseID, e.CaseDigest = c.ID, c.Digest()
	e.Host.Host.NativeArchitecture, e.Host.Host.ProcessArchitecture = host, host
	e.Host.Report.ID = "host-report-" + string(host)
	for i := range e.Verifications {
		e.Verifications[i].ObservedTarget = target
	}
	return c, e
}

func unitArchitectureSuite() ([]Case, []Evidence) {
	var required []Case
	var observed []Evidence
	for _, host := range []model.Architecture{"x86", "amd64", "arm64"} {
		for _, target := range []model.Architecture{"x86", "amd64", "arm64"} {
			c, e := unitCoverageRecord(host, target)
			required = append(required, c)
			if host == "amd64" {
				observed = append(observed, e)
			}
		}
	}
	return required, observed
}

func TestArchitectureCoverageAcceptsCompleteSingleHostSuite(t *testing.T) {
	required, observed := unitArchitectureSuite()
	before, _ := json.Marshal(observed)
	coverage, err := ValidateArchitectureCoverage(required, observed)
	if err != nil {
		t.Fatal(err)
	}
	if len(coverage) != 9 {
		t.Fatalf("coverage has %d entries, want all nine logical pairs", len(coverage))
	}
	for i, entry := range coverage {
		c := required[i]
		wantBasis := "portability-accepted"
		if c.Host.NativeArchitecture == "amd64" {
			wantBasis = "observed"
		}
		if entry.RequiredCaseID != c.ID || entry.RequiredHost != c.Host || entry.Target != c.Target || entry.Basis != wantBasis || entry.WitnessCaseID != "unit-amd64-"+string(c.Target) || entry.WitnessHost.Host.NativeArchitecture != "amd64" || entry.WitnessHost.Host.ProcessArchitecture != "amd64" || entry.WitnessHost.Report.ID != "host-report-amd64" {
			t.Fatalf("untruthful required/witness coverage: %+v", entry)
		}
	}
	after, _ := json.Marshal(observed)
	if string(before) != string(after) {
		t.Fatal("coverage evaluation relabeled or mutated actual evidence")
	}
	if ValidateEvidence(required, observed) == nil {
		t.Fatal("strict observed-record validator accepted unobserved hosts")
	}
}

func TestArchitectureCoverageAcceptsSeparateRunsAndPortableNativeClosure(t *testing.T) {
	required, observed := unitArchitectureSuite()
	for i := range observed {
		observed[i].Host.Report.ID = fmt.Sprintf("separate-run-host-report-%d", i)
	}
	for i := range required {
		if required[i].Host.NativeArchitecture != "amd64" {
			required[i].Components = nil
			required[i].DependencyClosureComplete = false
			required[i].Pending = []Blocker{{"native-host-not-established", "No physical machine for this native architecture."}}
		}
	}
	if _, err := ValidateArchitectureCoverage(required, observed); err != nil {
		t.Fatalf("incidental per-run reports or unexecuted host closure blocked portability acceptance: %v", err)
	}
}

func TestArchitectureCoverageRejectsIncompleteObservedProof(t *testing.T) {
	for name, mutate := range map[string]func(*[]Case, *[]Evidence){
		"missing target":         func(_ *[]Case, e *[]Evidence) { *e = (*e)[:2] },
		"missing operation":      func(_ *[]Case, e *[]Evidence) { (*e)[0].Invocations = (*e)[0].Invocations[2:] },
		"missing output":         func(_ *[]Case, e *[]Evidence) { (*e)[0].Outputs = nil },
		"missing inspection":     func(_ *[]Case, e *[]Evidence) { (*e)[0].Verifications = nil },
		"wrong output digest":    func(_ *[]Case, e *[]Evidence) { (*e)[0].Outputs[0].Artifact.Digest.Value = unitBeforeHash },
		"missing source":         func(c *[]Case, _ *[]Evidence) { (*c)[3].Source.UpdateID = "" },
		"component runtime":      func(_ *[]Case, e *[]Evidence) { (*e)[0].ExecutionKind = "component-runtime" },
		"unverified":             func(_ *[]Case, e *[]Evidence) { (*e)[0].Status = Unverified },
		"failed":                 func(_ *[]Case, e *[]Evidence) { (*e)[0].Status = Failed },
		"cross compile only":     func(_ *[]Case, e *[]Evidence) { (*e)[0].ExecutionKind = "cross-compile" },
		"synthetic execution":    func(_ *[]Case, e *[]Evidence) { (*e)[0].ExecutionKind = "synthetic" },
		"skipped":                func(_ *[]Case, e *[]Evidence) { (*e)[0].Status = "skipped" },
		"missing host report":    func(_ *[]Case, e *[]Evidence) { (*e)[0].Host.Report = Artifact{} },
		"host lie":               func(_ *[]Case, e *[]Evidence) { (*e)[0].Host.Host.NativeArchitecture = "x86" },
		"misbound descriptor":    func(_ *[]Case, e *[]Evidence) { (*e)[0].CaseDigest = unitBeforeHash },
		"missing dependencies":   func(_ *[]Case, e *[]Evidence) { (*e)[0].Components = nil },
		"unvalidated native API": func(_ *[]Case, e *[]Evidence) { (*e)[0].NativeInvocations = []NativeInvocation{{ID: "unit-only"}} },
		"unexpected evidence":    func(_ *[]Case, e *[]Evidence) { (*e)[0].CaseID = "unrelated" },
		"duplicate evidence":     func(_ *[]Case, e *[]Evidence) { *e = append(*e, (*e)[0]) },
		"duplicate required":     func(c *[]Case, _ *[]Evidence) { *c = append(*c, (*c)[0]) },
		"no requirements":        func(c *[]Case, _ *[]Evidence) { *c = nil },
		"no observations":        func(_ *[]Case, e *[]Evidence) { *e = nil },
	} {
		t.Run(name, func(t *testing.T) {
			required, observed := unitArchitectureSuite()
			mutate(&required, &observed)
			if _, err := ValidateArchitectureCoverage(required, observed); err == nil {
				t.Fatal("incomplete or misbound proof accepted as architecture coverage")
			}
		})
	}
}

func TestArchitectureCoverageRejectsUnrelatedFunctionalCounterparts(t *testing.T) {
	for name, mutate := range map[string]func(*Case){
		"source revision":   func(c *Case) { c.Source.UpdateID = "another_rev.2" },
		"source provenance": func(c *Case) { c.RevisionProvenance = "another revision oracle" },
		"source family":     func(c *Case) { c.SourceFamily = "another-family" },
		"target":            func(c *Case) { c.Target, c.Source.Architecture = "another-target", "another-target" },
		"gate":              func(c *Case) { c.Gate = "S" },
		"input bytes":       func(c *Case) { c.Inputs[0].Size = 1 },
		"algorithm": func(c *Case) {
			c.Algorithms = append(c.Algorithms, "another-algorithm")
			c.Expected[0].Algorithms = []string{"another-algorithm"}
		},
		"expected output":    func(c *Case) { c.Expected[0].SHA256 = unitBeforeHash },
		"expected content":   func(c *Case) { c.Expected[0].Assertions = append(c.Expected[0].Assertions, "another-check") },
		"minimum OS build":   func(c *Case) { c.Host.MinimumBuild = 22000 },
		"functional pending": func(c *Case) { c.Pending = []Blocker{{"fixture-missing", "Required functional proof is absent."}} },
	} {
		t.Run(name, func(t *testing.T) {
			required, observed := unitArchitectureSuite()
			mutate(&required[0]) // Unobserved x86 counterpart, not the amd64 witness.
			if _, err := ValidateArchitectureCoverage(required, observed); err == nil {
				t.Fatal("unrelated target/source/operation/output requirement borrowed a witness")
			}
		})
	}
}

func TestArchitectureCoverageRejectsMixedIncompleteHosts(t *testing.T) {
	required, observed := unitArchitectureSuite()
	_, otherHost := unitCoverageRecord("arm64", "arm64")
	observed[2] = otherHost
	if _, err := ValidateArchitectureCoverage(required, observed); err == nil {
		t.Fatal("partial suites from two architectures became one complete host suite")
	}
	_, observed = unitArchitectureSuite()
	observed[2].Host.Host.WindowsBuild++
	if _, err := ValidateArchitectureCoverage(required, observed); err == nil {
		t.Fatal("partial suites with different actual host facts were pooled")
	}
}

func TestArchitectureCoverageSelectsCurrentNativeHostCases(t *testing.T) {
	required, observed := unitArchitectureSuite()
	selected, err := currentHostCases(required, observed[0].Host)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 3 || selected[0].ID != "unit-amd64-x86" || selected[1].ID != "unit-amd64-amd64" || selected[2].ID != "unit-amd64-arm64" {
		t.Fatalf("selected unavailable hosts or lost current-host targets: %+v", selected)
	}
	for _, host := range []ObservedHost{
		{OS: "windows", Host: model.Host{WindowsBuild: 19045, NativeArchitecture: "amd64", ProcessArchitecture: "x86"}},
		{OS: "windows", Host: model.Host{WindowsBuild: 19045, ProcessArchitecture: "amd64"}},
		{OS: "linux", Host: observed[0].Host.Host},
		{OS: "windows", Host: model.Host{WindowsBuild: 10239, NativeArchitecture: "amd64", ProcessArchitecture: "amd64"}},
	} {
		if _, err := currentHostCases(required, host); err == nil {
			t.Fatalf("unknown/emulated/inapplicable host accepted: %+v", host)
		}
	}
}
