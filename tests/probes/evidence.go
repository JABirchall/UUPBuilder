package probes

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"uupbuilder/internal/model"
)

type ObservedHost struct {
	OS     string     `json:"os"`
	Host   model.Host `json:"host"`
	Report Artifact   `json:"report"`
}

type Invocation struct {
	ID          string    `json:"id"`
	Operation   Operation `json:"operation"`
	ComponentID string    `json:"component_id"`
	Algorithms  []string  `json:"algorithms"`
	Arguments   []string  `json:"arguments"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	ExitCode    *int      `json:"exit_code"`
	Log         Artifact  `json:"log"`
}

type Output struct {
	Artifact   Artifact `json:"artifact"`
	ProducedBy string   `json:"produced_by"`
}

type Verification struct {
	ExpectationID  string             `json:"expectation_id"`
	OutputID       string             `json:"output_id"`
	InvocationID   string             `json:"invocation_id"`
	SHA256         string             `json:"sha256"`
	BeforeSHA256   string             `json:"before_sha256,omitempty"`
	Assertions     []string           `json:"assertions"`
	ObservedTarget model.Architecture `json:"observed_target"`
	Report         Artifact           `json:"report"`
}

type Evidence struct {
	CaseID        string         `json:"case_id"`
	CaseDigest    string         `json:"case_digest"`
	Status        Status         `json:"status"`
	ExecutionKind string         `json:"execution_kind"`
	Host          ObservedHost   `json:"host"`
	Inputs        []Artifact     `json:"inputs"`
	Components    []Component    `json:"components"`
	Invocations   []Invocation   `json:"invocations"`
	Outputs       []Output       `json:"outputs"`
	Verifications []Verification `json:"verifications"`
	Blockers      []Blocker      `json:"blockers"`
}

// ValidateEvidence validates records, not an attestation of external facts.
// Passing records must come from a trusted runner with retained byte artifacts;
// handwritten records (including unit tests) never establish Gate P or S.
func ValidateEvidence(required []Case, evidence []Evidence) error {
	if len(required) == 0 {
		return errors.New("evidence: empty required set")
	}
	requirements := map[string]Case{}
	for _, c := range required {
		if _, duplicate := requirements[c.ID]; duplicate {
			return errors.New("evidence: duplicate requirement")
		}
		if err := c.ValidateReady(); err != nil {
			return fmt.Errorf("case %s not proof-ready: %w", c.ID, err)
		}
		requirements[c.ID] = c
	}
	seen := map[string]bool{}
	for _, e := range evidence {
		c, ok := requirements[e.CaseID]
		if !ok || seen[e.CaseID] {
			return fmt.Errorf("evidence: unexpected/duplicate case %s", e.CaseID)
		}
		seen[e.CaseID] = true
		if err := validateRecord(c, e); err != nil {
			return fmt.Errorf("case %s: %w", c.ID, err)
		}
	}
	for _, c := range required {
		if !seen[c.ID] {
			return fmt.Errorf("case %s: missing evidence", c.ID)
		}
	}
	return nil
}

func validateRecord(c Case, e Evidence) error {
	if e.CaseDigest != c.Digest() {
		return errors.New("evidence: descriptor digest mismatch")
	}
	if e.Status != Passed {
		return fmt.Errorf("evidence: nonpassing status %q", e.Status)
	}
	if e.ExecutionKind != "native-runtime" || len(e.Blockers) != 0 {
		return errors.New("evidence: actual native runtime execution required, with no unresolved blockers")
	}
	h := e.Host
	if h.OS != c.Host.OS || h.Host.WindowsBuild < c.Host.MinimumBuild || h.Host.NativeArchitecture != c.Host.NativeArchitecture || h.Host.ProcessArchitecture != c.Host.ProcessArchitecture {
		return errors.New("evidence: observed OS/build/native/process host does not match requirement")
	}
	if h.Host.FileSystem.Name != "NTFS" || !h.Host.FileSystem.Local {
		return errors.New("evidence: local NTFS proof workspace required")
	}
	if err := h.Report.validate("host-report"); err != nil {
		return err
	}
	if !reflect.DeepEqual(c.Inputs, e.Inputs) {
		return errors.New("evidence: materialized input identities differ from frozen case")
	}
	if !reflect.DeepEqual(c.Components, e.Components) {
		return errors.New("evidence: provider/component/dependency identities differ from frozen case")
	}
	components := map[string]Component{}
	for _, component := range e.Components {
		components[component.Artifact.ID] = component
	}
	invocations := map[string]Invocation{}
	appliedAlgorithms := map[string]bool{}
	for _, inv := range e.Invocations {
		if textRequired("invocation.id", inv.ID) != nil || !operationValid(inv.Operation) {
			return errors.New("evidence: invalid invocation identity/operation")
		}
		if _, duplicate := invocations[inv.ID]; duplicate {
			return errors.New("evidence: duplicate invocation")
		}
		component, ok := components[inv.ComponentID]
		if !ok || component.Artifact.Role != "executable" {
			return errors.New("evidence: invocation must bind a pinned native executable")
		}
		if inv.StartedAt.IsZero() || inv.FinishedAt.IsZero() || !inv.FinishedAt.After(inv.StartedAt) || inv.ExitCode == nil || *inv.ExitCode != 0 {
			return errors.New("evidence: missing/failed/invalid runtime execution")
		}
		if len(inv.Arguments) == 0 {
			return errors.New("evidence: invocation arguments missing")
		}
		for _, arg := range inv.Arguments {
			if strings.ContainsAny(arg, "\x00\r\n") {
				return errors.New("evidence: unsafe invocation argument")
			}
		}
		if err := inv.Log.validate("log"); err != nil {
			return err
		}
		if err := uniqueText("invocation.algorithms", inv.Algorithms); err != nil {
			return err
		}
		if inv.Operation != Inspect {
			for _, algorithm := range inv.Algorithms {
				appliedAlgorithms[algorithm] = true
			}
		}
		invocations[inv.ID] = inv
	}
	for _, algorithm := range c.Algorithms {
		if !appliedAlgorithms[algorithm] {
			return fmt.Errorf("evidence: algorithm %s has no actual execution record", algorithm)
		}
	}
	outputs := map[string]Output{}
	for _, output := range e.Outputs {
		if err := output.Artifact.validate("output"); err != nil {
			return err
		}
		if _, duplicate := outputs[output.Artifact.ID]; duplicate {
			return errors.New("evidence: duplicate output")
		}
		if _, ok := invocations[output.ProducedBy]; !ok {
			return errors.New("evidence: output has no executed producer")
		}
		outputs[output.Artifact.ID] = output
	}
	verifications := map[string]Verification{}
	for _, v := range e.Verifications {
		if _, duplicate := verifications[v.ExpectationID]; duplicate {
			return errors.New("evidence: duplicate verification")
		}
		if err := v.Report.validate("verification-report"); err != nil {
			return err
		}
		verifications[v.ExpectationID] = v
	}
	if len(verifications) != len(c.Expected) {
		return errors.New("evidence: missing or extra verification")
	}
	for _, expected := range c.Expected {
		v, ok := verifications[expected.ID]
		if !ok {
			return fmt.Errorf("evidence: missing verification %s", expected.ID)
		}
		output, ok := outputs[expected.OutputID]
		if !ok || v.OutputID != expected.OutputID {
			return errors.New("evidence: missing/misbound expected output")
		}
		producer := invocations[output.ProducedBy]
		inspector, ok := invocations[v.InvocationID]
		if producer.Operation != expected.Operation || !ok || inspector.Operation != Inspect || inspector.ComponentID == producer.ComponentID || strings.EqualFold(components[inspector.ComponentID].Artifact.Digest.Value, components[producer.ComponentID].Artifact.Digest.Value) || inspector.StartedAt.Before(producer.FinishedAt) {
			return errors.New("evidence: independent subsequent inspection of the actual operation output required")
		}
		if output.Artifact.Digest.Algorithm != model.DigestSHA256 || !strings.EqualFold(output.Artifact.Digest.Value, expected.SHA256) || !strings.EqualFold(v.SHA256, expected.SHA256) {
			return errors.New("evidence: expected/produced/independently inspected SHA-256 mismatch")
		}
		if v.ObservedTarget != c.Target {
			return errors.New("evidence: independently inspected target mismatch")
		}
		if expected.Operation == Service && !strings.EqualFold(v.BeforeSHA256, expected.BeforeSHA256) {
			return errors.New("evidence: independently inspected servicing baseline mismatch")
		}
		if err := uniqueText("verification.assertions", v.Assertions); err != nil {
			return err
		}
		for _, assertion := range expected.Assertions {
			if !contains(v.Assertions, assertion) {
				return fmt.Errorf("evidence: missing independent content assertion %s", assertion)
			}
		}
	}
	return nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func RunCase(ctx context.Context, c Case, emit model.Emit) (Evidence, error) {
	e := Evidence{CaseID: c.ID, CaseDigest: c.Digest(), Status: Unverified, ExecutionKind: "not-executed"}
	var failures []error
	if ctx == nil {
		failures = append(failures, errors.New("context required"))
	} else if err := ctx.Err(); err != nil {
		failures = append(failures, err)
	} else {
		host, err := observeHost()
		e.Host = host
		if err != nil {
			e.Blockers = append(e.Blockers, Blocker{"host-observation-unverified", err.Error()})
		} else if host.OS != c.Host.OS || host.Host.NativeArchitecture != c.Host.NativeArchitecture || host.Host.ProcessArchitecture != c.Host.ProcessArchitecture || host.Host.WindowsBuild < c.Host.MinimumBuild {
			e.Blockers = append(e.Blockers, Blocker{"host-requirement-mismatch", "Observed OS/build/native/process architecture does not satisfy the requested case; cross-compilation and emulation cannot substitute."})
		}
	}
	if err := c.ValidateReady(); err != nil {
		e.Blockers = append(e.Blockers, Blocker{"prerequisites-unverified", err.Error()})
		failures = append(failures, err)
	}
	e.Blockers = append(e.Blockers, c.Pending...)
	// This is deliberately unfinished execution plumbing. Never route a request
	// to another shell/API to bypass the stopped downloaded-helper path.
	e.Blockers = append(e.Blockers, Blocker{"adapter-unimplemented", "No authorized concrete provider execution and independent inspection adapter is implemented."}, Blocker{"policy-execution-stopped", "Automatic approval review rejected pinned downloaded-helper extraction/direct execution with: blocked by policy. This path remains stopped; no alternative launch route is permitted."})
	seenBlockers := map[string]bool{}
	uniqueBlockers := make([]Blocker, 0, len(e.Blockers))
	for _, b := range e.Blockers {
		if !seenBlockers[b.Code] {
			uniqueBlockers = append(uniqueBlockers, b)
			seenBlockers[b.Code] = true
		}
	}
	e.Blockers = uniqueBlockers
	for _, b := range e.Blockers {
		failures = append(failures, fmt.Errorf("%s: %s", b.Code, b.Detail))
	}
	if emit != nil {
		emit(model.Event{JobID: c.ID, StageID: "provider-proof", Kind: model.EventError, Message: "unverified: provider execution adapter unfinished; real feasibility gates remain pending", Timestamp: time.Now().UTC()})
	}
	return e, errors.Join(failures...)
}
