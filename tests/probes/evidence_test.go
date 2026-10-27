package probes

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"uupbuilder/internal/model"
)

// These are synthetic validator records, never actual provider evidence.
const unitHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
const unitBeforeHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func unitArtifact(id, role string) Artifact {
	return Artifact{id, role, model.Digest{Algorithm: "sha256", Value: unitHash}, 3, "synthetic validator record; not provider proof"}
}

func unitRecord() (Case, Evidence) {
	c := Case{
		ID: "unit-amd64-arm64", Gate: "P", Host: HostRequirement{"windows", 10240, "amd64", "amd64"}, Target: "arm64", SourceFamily: "canonical",
		Source: model.SourceIdentity{UpdateID: "unit_rev.1", BuildLabel: "unit", Architecture: "arm64", Language: "en-us"}, RevisionProvenance: "unit fixture",
		Inputs: []Artifact{unitArtifact("source-image", "payload")}, DependencyClosureComplete: true,
		Components: []Component{{unitArtifact("writer", "executable"), "amd64", []string{"runtime"}}, {unitArtifact("runtime", "dll"), "amd64", nil}, {unitArtifact("inspector", "executable"), "amd64", nil}},
		Operations: []Operation{Extract, Service, Reconstruct, MasterISO}, Algorithms: []string{"unit-algorithm"},
	}
	e := Evidence{CaseID: c.ID, Status: Passed, ExecutionKind: "native-runtime", Host: ObservedHost{OS: "windows", Host: model.Host{WindowsBuild: 19045, ProcessArchitecture: "amd64", NativeArchitecture: "amd64", FileSystem: model.FileSystemCapabilities{Name: "NTFS", Local: true}}, Report: unitArtifact("host-report", "host-report")}, Inputs: c.Inputs, Components: c.Components}
	// Distinct synthetic component digest, not an acquired executable identity.
	c.Components[2].Artifact.Digest.Value = strings.Repeat("1", 64)
	c.Inputs[0].Digest.Value = unitBeforeHash
	c.Inputs[0].Size = 0
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	zero := 0
	for i, op := range c.Operations {
		id := string(op)
		inspectID := "inspect-" + id
		outputID := "output-" + id
		assertions := []string{"content-inspected"}
		switch op {
		case Extract:
			assertions = append(assertions, "files-and-metadata-inspected")
		case Service:
			assertions = append(assertions, "modification-observed")
		case Reconstruct:
			assertions = append(assertions, "reconstructed-content-inspected")
		case MasterISO:
			assertions = append(assertions, "filesystem-inspected", "boot-catalog-inspected", "target-boot-resources-inspected")
		}
		expected := Expectation{ID: id, Operation: op, OutputID: outputID, SHA256: unitHash, Provenance: "independently prepared synthetic expected bytes", Assertions: assertions}
		if op == Reconstruct {
			expected.Algorithms = []string{"unit-algorithm"}
		}
		if op == Service {
			expected.BeforeSHA256 = unitBeforeHash
			expected.BeforeInputID = "source-image"
		}
		c.Expected = append(c.Expected, expected)
		e.Invocations = append(e.Invocations, Invocation{ID: id, Operation: op, ComponentID: "writer", Algorithms: []string{"unit-algorithm"}, Arguments: []string{"unit-only"}, StartedAt: now.Add(time.Duration(i*2) * time.Second), FinishedAt: now.Add(time.Duration(i*2+1) * time.Second), ExitCode: &zero, Log: unitArtifact("log-"+id, "log")}, Invocation{ID: inspectID, Operation: Inspect, ComponentID: "inspector", Arguments: []string{"unit-only"}, StartedAt: now.Add(time.Duration(i*2+1) * time.Second), FinishedAt: now.Add(time.Duration(i*2+2) * time.Second), ExitCode: &zero, Log: unitArtifact("log-"+inspectID, "log")})
		e.Outputs = append(e.Outputs, Output{unitArtifact(outputID, "output"), id})
		v := Verification{ExpectationID: id, OutputID: outputID, InvocationID: inspectID, SHA256: unitHash, Assertions: assertions, ObservedTarget: "arm64", Report: unitArtifact("report-"+id, "verification-report")}
		if op == Service {
			v.BeforeSHA256 = unitBeforeHash
		}
		e.Verifications = append(e.Verifications, v)
	}
	e.CaseDigest = c.Digest()
	return c, e
}

func TestEvidenceAcceptsCompleteRecordShape(t *testing.T) {
	c, e := unitRecord()
	if err := ValidateEvidence([]Case{c}, []Evidence{e}); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceRejectsCrossCompileOnly(t *testing.T) {
	c, e := unitRecord()
	e.ExecutionKind = "cross-compile"
	if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
		t.Fatal("cross-compilation counted as runtime proof")
	}
}

func TestEvidenceRejectsWOW64AsNativeX86Host(t *testing.T) {
	c, e := unitRecord()
	c.Host.NativeArchitecture = "x86"
	c.Host.ProcessArchitecture = "x86"
	for i := range c.Components {
		c.Components[i].NativeArchitecture = "x86"
	}
	e.Components = c.Components
	e.Host.Host.ProcessArchitecture = "x86"
	e.CaseDigest = c.Digest()
	if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
		t.Fatal("WOW64 counted as native x86 host")
	}
}

func TestEvidenceRejectsMissingDependencies(t *testing.T) {
	c, e := unitRecord()
	e.Components = append([]Component{e.Components[0]}, e.Components[2:]...)
	if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
		t.Fatal("missing runtime DLL accepted")
	}
}

func TestEvidenceRejectsIncompleteOrMisboundProof(t *testing.T) {
	for name, mutate := range map[string]func(*Case, *Evidence){
		"missing case":             func(c *Case, e *Evidence) { e.CaseID = "different" },
		"changed case":             func(c *Case, e *Evidence) { c.Algorithms = []string{"changed"} },
		"unverified":               func(c *Case, e *Evidence) { e.Status = Unverified },
		"failed":                   func(c *Case, e *Evidence) { e.Status = Failed },
		"unknown status":           func(c *Case, e *Evidence) { e.Status = "unknown" },
		"missing exit":             func(c *Case, e *Evidence) { e.Invocations[0].ExitCode = nil },
		"nonzero exit":             func(c *Case, e *Evidence) { v := 1; e.Invocations[0].ExitCode = &v },
		"no execution":             func(c *Case, e *Evidence) { e.Invocations = nil },
		"no independent inspector": func(c *Case, e *Evidence) { e.Invocations[1].ComponentID = "writer" },
		"missing verification":     func(c *Case, e *Evidence) { e.Verifications = e.Verifications[:3] },
		"metadata as output":       func(c *Case, e *Evidence) { e.Outputs[0].Artifact.Role = "metadata" },
		"wrong output hash":        func(c *Case, e *Evidence) { e.Outputs[0].Artifact.Digest.Value = strings.Repeat("0", 64) },
		"wrong target":             func(c *Case, e *Evidence) { e.Verifications[0].ObservedTarget = "x86" },
		"missing assertion":        func(c *Case, e *Evidence) { e.Verifications[0].Assertions = nil },
		"unknown closure":          func(c *Case, e *Evidence) { c.DependencyClosureComplete = false; e.CaseDigest = c.Digest() },
		"pending fixture": func(c *Case, e *Evidence) {
			c.Pending = []Blocker{{"fixture-missing", "no fixture"}}
			e.CaseDigest = c.Digest()
		},
		"metadata as payload":      func(c *Case, e *Evidence) { c.Inputs[0].Role = "metadata"; e.CaseDigest = c.Digest() },
		"missing host observation": func(c *Case, e *Evidence) { e.Host.Report = Artifact{} },
	} {
		t.Run(name, func(t *testing.T) {
			c, e := unitRecord()
			mutate(&c, &e)
			if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
				t.Fatal("incomplete/misbound proof accepted")
			}
		})
	}
	c, e := unitRecord()
	if ValidateEvidence(nil, nil) == nil {
		t.Error("empty requirements passed")
	}
	if ValidateEvidence([]Case{c}, nil) == nil {
		t.Error("missing evidence passed")
	}
	if ValidateEvidence([]Case{c}, []Evidence{e, e}) == nil {
		t.Error("duplicate evidence passed")
	}
	if ValidateEvidence([]Case{c, c}, []Evidence{e}) == nil {
		t.Error("duplicate requirements passed")
	}
}

func TestEvidenceRunCaseRefusesWithoutExecuting(t *testing.T) {
	c, _ := unitRecord()
	var events []model.Event
	e, err := RunCase(context.Background(), c, func(e model.Event) { events = append(events, e) })
	if err == nil || e.Status != Unverified || len(e.Invocations) != 0 {
		t.Fatalf("unfinished adapter must refuse, got %+v / %v", e, err)
	}
	if !strings.Contains(err.Error(), "adapter-unimplemented") {
		t.Fatalf("unfinished implementation not identified: %v", err)
	}
	if len(events) == 0 || events[len(events)-1].Kind != model.EventError {
		t.Fatal("refusal did not emit an error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e, err = RunCase(ctx, c, nil)
	if !errors.Is(err, context.Canceled) || e.Status != Unverified {
		t.Fatalf("canceled case: %+v %v", e, err)
	}
}

func TestEvidenceRequiresAppliedAlgorithms(t *testing.T) {
	c, e := unitRecord()
	c.Algorithms = append(c.Algorithms, "not-executed-algorithm")
	e.CaseDigest = c.Digest()
	if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
		t.Fatal("declared algorithm without execution accepted")
	}
}

// moveUnitAlgorithmsToDetachedInvocation reproduces Q1 using only synthetic
// records. The added invocation has valid execution/log fields but no output.
func moveUnitAlgorithmsToDetachedInvocation(e *Evidence) {
	var detached Invocation
	for i := range e.Invocations {
		if e.Invocations[i].ID == "reconstruct" {
			detached = e.Invocations[i]
		}
		e.Invocations[i].Algorithms = nil
	}
	detached.ID = "detached-reconstruct"
	detached.Algorithms = []string{"unit-algorithm"}
	detached.Log = unitArtifact("detached-log", "log")
	e.Invocations = append(e.Invocations, detached)
}

func TestEvidenceAlgorithmsBindVerifiedExpectedOutput(t *testing.T) {
	for _, binding := range []string{"expected reconstruct producer", "detached invocation", "different verified operation"} {
		t.Run(binding, func(t *testing.T) {
			c, e := unitRecord()
			for i := range e.Invocations {
				e.Invocations[i].Algorithms = nil
			}
			switch binding {
			case "expected reconstruct producer":
				e.Invocations[4].Algorithms = []string{"unit-algorithm"}
			case "detached invocation":
				moveUnitAlgorithmsToDetachedInvocation(&e)
			case "different verified operation":
				e.Invocations[0].Algorithms = []string{"unit-algorithm"}
			}
			err := ValidateEvidence([]Case{c}, []Evidence{e})
			if binding == "expected reconstruct producer" {
				if err != nil {
					t.Fatalf("algorithm on independently verified expected reconstruct producer rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("required reconstruction algorithm credited without its expected reconstructed result")
			}
		})
	}
}

func TestEvidenceRejectsUnboundAlgorithmRequirements(t *testing.T) {
	for _, declaration := range []string{"unassigned", "undeclared", "duplicate"} {
		t.Run(declaration, func(t *testing.T) {
			c, e := unitRecord()
			switch declaration {
			case "unassigned":
				c.Expected[2].Algorithms = nil
			case "undeclared":
				c.Expected[2].Algorithms = []string{"different-algorithm"}
			case "duplicate":
				c.Expected[2].Algorithms = []string{"unit-algorithm", "unit-algorithm"}
			}
			e.CaseDigest = c.Digest()
			if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
				t.Fatal("invalid expected-output algorithm binding accepted")
			}
		})
	}
}

func TestEvidenceRunCaseMeasuresHostWithoutHelpers(t *testing.T) {
	c, _ := unitRecord()
	e, err := RunCase(context.Background(), c, nil)
	if err == nil {
		t.Fatal("unfinished adapter passed")
	}
	if e.Host.OS != runtime.GOOS || e.Host.Host.ProcessArchitecture != model.ArchitectureFromGo(runtime.GOARCH) {
		t.Fatalf("actual host not observed: %+v", e.Host)
	}
	if runtime.GOOS == "windows" && (e.Host.Host.WindowsBuild < 10240 || e.Host.Host.NativeArchitecture == "") {
		t.Fatalf("native OS/build not measured: %+v", e.Host)
	}
}

func TestEvidenceRequiresRealModificationAndBootInspection(t *testing.T) {
	for name, mutate := range map[string]func(*Case, *Evidence){
		"unchanged service result":         func(c *Case, e *Evidence) { c.Expected[1].BeforeSHA256 = unitHash },
		"no before identity":               func(c *Case, e *Evidence) { c.Expected[1].BeforeSHA256 = "" },
		"hash alone is not servicing":      func(c *Case, e *Evidence) { c.Expected[1].Assertions = []string{"content-inspected"} },
		"hash alone is not ISO boot proof": func(c *Case, e *Evidence) { c.Expected[3].Assertions = []string{"content-inspected"} },
	} {
		t.Run(name, func(t *testing.T) {
			c, e := unitRecord()
			mutate(&c, &e)
			e.CaseDigest = c.Digest()
			if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
				t.Fatal("weakened operation proof accepted")
			}
		})
	}
}

func TestEvidenceIndependentInspectorMustUseDifferentBytes(t *testing.T) {
	c, e := unitRecord()
	c.Components[2].Artifact.Digest = c.Components[0].Artifact.Digest
	e.Components = c.Components
	e.CaseDigest = c.Digest()
	if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
		t.Fatal("renaming producer bytes counted as an independent inspector")
	}
}

func TestEvidenceRunCaseKeepsDistinctBlockers(t *testing.T) {
	c, _ := unitRecord()
	c.Pending = []Blocker{{"adapter-unimplemented", "Known unfinished adapter."}, {"policy-execution-stopped", "Known stopped execution path."}}
	e, err := RunCase(context.Background(), c, nil)
	if err == nil {
		t.Fatal("missing refusal")
	}
	seen := map[string]bool{}
	for _, b := range e.Blockers {
		if seen[b.Code] {
			t.Fatalf("duplicate blocker %s", b.Code)
		}
		seen[b.Code] = true
	}
}

func TestEvidenceBindsActualServicingBaseline(t *testing.T) {
	for name, mutate := range map[string]func(*Case, *Evidence){
		"wrong measured baseline":   func(c *Case, e *Evidence) { e.Verifications[1].BeforeSHA256 = unitHash },
		"missing measured baseline": func(c *Case, e *Evidence) { e.Verifications[1].BeforeSHA256 = "" },
		"unknown baseline fixture":  func(c *Case, e *Evidence) { c.Expected[1].BeforeInputID = "not-an-input" },
		"wrong baseline input hash": func(c *Case, e *Evidence) { c.Inputs[0].Digest.Value = unitHash },
	} {
		t.Run(name, func(t *testing.T) {
			c, e := unitRecord()
			mutate(&c, &e)
			e.CaseDigest = c.Digest()
			if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
				t.Fatal("unbound servicing baseline accepted")
			}
		})
	}
}
