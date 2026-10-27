// Package probes contains feasibility evidence contracts, not product capability claims.
package probes

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"uupbuilder/internal/model"
)

type Operation string

const (
	Extract     Operation = "extract"
	Service     Operation = "service"
	Reconstruct Operation = "reconstruct"
	MasterISO   Operation = "master-iso"
	Inspect     Operation = "inspect"
)

type Status string

const (
	Passed     Status = "passed"
	Failed     Status = "failed"
	Unverified Status = "unverified"
)

// Artifact binds a sanitized logical identity to bytes and their provenance.
// Metadata must never stand in for a payload or independently expected output.
type Artifact struct {
	ID         string       `json:"id"`
	Role       string       `json:"role"`
	Digest     model.Digest `json:"digest"`
	Size       int64        `json:"size"`
	Provenance string       `json:"provenance"`
}

type HostRequirement struct {
	OS                  string             `json:"os"`
	MinimumBuild        uint32             `json:"minimum_build"`
	NativeArchitecture  model.Architecture `json:"native_architecture"`
	ProcessArchitecture model.Architecture `json:"process_architecture"`
}

type Component struct {
	Artifact           Artifact           `json:"artifact"`
	NativeArchitecture model.Architecture `json:"native_architecture"`
	Dependencies       []string           `json:"dependencies"`
}

type Expectation struct {
	ID            string    `json:"id"`
	Operation     Operation `json:"operation"`
	OutputID      string    `json:"output_id"`
	SHA256        string    `json:"sha256"`
	BeforeSHA256  string    `json:"before_sha256,omitempty"`
	BeforeInputID string    `json:"before_input_id,omitempty"`
	Provenance    string    `json:"provenance"`
	Assertions    []string  `json:"assertions"`
}

type Blocker struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type Case struct {
	ID                        string               `json:"id"`
	Gate                      string               `json:"gate"`
	Host                      HostRequirement      `json:"host"`
	Target                    model.Architecture   `json:"target"`
	SourceFamily              string               `json:"source_family"`
	Source                    model.SourceIdentity `json:"source"`
	RevisionProvenance        string               `json:"revision_provenance"`
	Inputs                    []Artifact           `json:"inputs"`
	Components                []Component          `json:"components"`
	DependencyClosureComplete bool                 `json:"dependency_closure_complete"`
	Operations                []Operation          `json:"operations"`
	Algorithms                []string             `json:"algorithms"`
	Expected                  []Expectation        `json:"expected"`
	Pending                   []Blocker            `json:"pending"`
}

type MissingMaterial struct {
	Identity string   `json:"identity"`
	Failure  string   `json:"failure"`
	Evidence Artifact `json:"evidence"`
}

type SourceFamily struct {
	ID              string            `json:"id"`
	Observation     string            `json:"observation"`
	Availability    string            `json:"availability"`
	Implementation  string            `json:"implementation"`
	MediaCapability string            `json:"media_capability"`
	Proof           Status            `json:"proof"`
	Metadata        []Artifact        `json:"metadata"`
	Algorithms      []string          `json:"algorithms"`
	MissingUpstream []MissingMaterial `json:"missing_upstream"`
	ProofCases      []string          `json:"proof_cases"`
	Gaps            []string          `json:"gaps"`
}

type SourceCensus struct {
	Complete    bool           `json:"complete"`
	Limitations []string       `json:"limitations"`
	Families    []SourceFamily `json:"families"`
}

type CaseLedger struct {
	SchemaVersion int          `json:"schema_version"`
	Cases         []Case       `json:"cases"`
	Census        SourceCensus `json:"source_census"`
}

func LoadCases(r io.Reader) (CaseLedger, error) {
	var ledger CaseLedger
	encoded, err := io.ReadAll(io.LimitReader(r, (4<<20)+1))
	if err != nil {
		return ledger, err
	}
	if len(encoded) > 4<<20 {
		return ledger, errors.New("ledger: exceeds 4 MiB limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ledger); err != nil {
		return ledger, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ledger, errors.New("ledger: trailing data or invalid JSON")
	}
	if ledger.SchemaVersion != 1 {
		return ledger, errors.New("ledger: unsupported schema version")
	}
	if err := ValidateRequiredCases(ledger.Cases); err != nil {
		return ledger, err
	}
	if err := ledger.Census.Validate(); err != nil {
		return ledger, err
	}
	return ledger, nil
}

// ValidateRequiredCases checks coverage, not feasibility. Extra target values
// remain valid; the common matrix is a minimum, never a target allowlist.
func ValidateRequiredCases(cases []Case) error {
	ids, pairs := map[string]bool{}, map[string]bool{}
	for _, c := range cases {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("case %q: %w", c.ID, err)
		}
		if ids[c.ID] {
			return fmt.Errorf("duplicate case %q", c.ID)
		}
		ids[c.ID] = true
		if c.Gate == "P" {
			pair := string(c.Host.NativeArchitecture) + "/" + string(c.Target)
			if pairs[pair] {
				return fmt.Errorf("duplicate Gate P pair %s", pair)
			}
			pairs[pair] = true
		}
	}
	for _, h := range []string{"x86", "amd64", "arm64"} {
		for _, target := range []string{"x86", "amd64", "arm64"} {
			if !pairs[h+"/"+target] {
				return fmt.Errorf("missing required native host/target pair %s/%s", h, target)
			}
		}
	}
	return nil
}

func (a Artifact) validate(role string) error {
	if err := textRequired("artifact.id", a.ID); err != nil {
		return err
	}
	if err := textRequired("artifact.provenance", a.Provenance); err != nil {
		return err
	}
	if a.Size < 0 {
		return errors.New("artifact: negative size")
	}
	if err := a.Digest.Validate(); err != nil {
		return fmt.Errorf("artifact %s: %w", a.ID, err)
	}
	if role != "" && a.Role != role {
		return fmt.Errorf("artifact %s: expected role %s, got %s", a.ID, role, a.Role)
	}
	switch a.Role {
	case "metadata", "payload", "executable", "dll", "driver", "system-component", "output", "log", "host-report", "verification-report", "availability-report":
	default:
		return fmt.Errorf("artifact %s: unknown role %q", a.ID, a.Role)
	}
	if a.Role != "payload" && a.Digest.Algorithm != model.DigestSHA256 {
		return errors.New("artifact: measured evidence/component digests must use SHA-256")
	}
	return nil
}

func textRequired(key, value string) error {
	if strings.TrimSpace(value) == "" || strings.ContainsFunc(value, unicode.IsControl) {
		return fmt.Errorf("%s: nonempty safe text required", key)
	}
	return nil
}

func uniqueText(key string, values []string) error {
	seen := map[string]bool{}
	for _, v := range values {
		if err := textRequired(key, v); err != nil {
			return err
		}
		if seen[v] {
			return fmt.Errorf("%s: duplicate %q", key, v)
		}
		seen[v] = true
	}
	return nil
}

func operationValid(op Operation) bool {
	switch op {
	case Extract, Service, Reconstruct, MasterISO, Inspect:
		return true
	}
	return false
}

func (c Case) Validate() error {
	if err := textRequired("case.id", c.ID); err != nil {
		return err
	}
	if c.Gate != "P" && c.Gate != "S" {
		return errors.New("case: gate must be P or S")
	}
	if c.Host.OS != "windows" || c.Host.MinimumBuild < 10240 {
		return errors.New("case: Windows 10 or later host required")
	}
	switch c.Host.NativeArchitecture {
	case "x86", "amd64", "arm64":
	default:
		return errors.New("case: unsupported native host architecture")
	}
	if c.Host.ProcessArchitecture != c.Host.NativeArchitecture {
		return errors.New("case: native process required; WOW64/emulated processes are not native-host proof")
	}
	if err := c.Target.Validate(); err != nil {
		return err
	}
	if err := textRequired("case.source_family", c.SourceFamily); err != nil {
		return err
	}
	if len(c.Operations) == 0 {
		return errors.New("case: operations required")
	}
	ops := map[Operation]bool{}
	for _, op := range c.Operations {
		if !operationValid(op) || op == Inspect || ops[op] {
			return fmt.Errorf("case: invalid or duplicate operation %q", op)
		}
		ops[op] = true
	}
	if c.Gate == "P" {
		for _, op := range []Operation{Extract, Service, Reconstruct, MasterISO} {
			if !ops[op] {
				return fmt.Errorf("Gate P: missing %s", op)
			}
		}
	}
	if err := uniqueText("case.algorithms", c.Algorithms); err != nil {
		return err
	}
	if c.Source.UpdateID != "" {
		if err := c.Source.Validate(); err != nil {
			return err
		}
		if c.Source.Architecture != c.Target {
			return errors.New("case: source/target architecture mismatch")
		}
		if err := textRequired("case.revision_provenance", c.RevisionProvenance); err != nil {
			return err
		}
	} else if len(c.Pending) == 0 {
		return errors.New("case: source or explicit pending prerequisite required")
	}
	for _, b := range c.Pending {
		if textRequired("blocker.code", b.Code) != nil || textRequired("blocker.detail", b.Detail) != nil {
			return errors.New("case: malformed blocker")
		}
	}
	if err := validateArtifacts(c.Inputs); err != nil {
		return err
	}
	for _, a := range c.Inputs {
		if a.Role != "metadata" && a.Role != "payload" {
			return errors.New("case: only metadata/payload inputs allowed")
		}
	}
	if err := validateComponents(c.Components, c.Host.NativeArchitecture, c.DependencyClosureComplete); err != nil {
		return err
	}
	ids, outputs := map[string]bool{}, map[string]bool{}
	for _, expected := range c.Expected {
		if textRequired("expectation.id", expected.ID) != nil || textRequired("expectation.output_id", expected.OutputID) != nil || textRequired("expectation.provenance", expected.Provenance) != nil {
			return errors.New("case: incomplete expectation identity/provenance")
		}
		if ids[expected.ID] || outputs[expected.OutputID] || !ops[expected.Operation] {
			return errors.New("case: duplicate expectation/output or unexpected operation")
		}
		ids[expected.ID], outputs[expected.OutputID] = true, true
		if err := (model.Digest{Algorithm: model.DigestSHA256, Value: expected.SHA256}).Validate(); err != nil {
			return fmt.Errorf("expected output: %w", err)
		}
		if len(expected.Assertions) == 0 {
			return errors.New("case: independent content assertions required")
		}
		if err := uniqueText("expectation.assertions", expected.Assertions); err != nil {
			return err
		}
		for _, assertion := range operationAssertions(expected.Operation) {
			if !contains(expected.Assertions, assertion) {
				return fmt.Errorf("case: %s needs independent assertion %s", expected.Operation, assertion)
			}
		}
		if expected.Operation == Service {
			if err := (model.Digest{Algorithm: model.DigestSHA256, Value: expected.BeforeSHA256}).Validate(); err != nil {
				return errors.New("case: servicing needs independently known before-image SHA-256")
			}
			if strings.EqualFold(expected.BeforeSHA256, expected.SHA256) {
				return errors.New("case: unchanged image is not servicing proof")
			}
			baseline := false
			for _, input := range c.Inputs {
				if input.ID == expected.BeforeInputID && input.Role == "payload" && input.Digest.Algorithm == model.DigestSHA256 && strings.EqualFold(input.Digest.Value, expected.BeforeSHA256) {
					baseline = true
				}
			}
			if !baseline {
				return errors.New("case: servicing before-image SHA-256 must bind a real payload fixture input")
			}
		}
	}
	return nil
}

func validateArtifacts(artifacts []Artifact) error {
	seen := map[string]bool{}
	for _, a := range artifacts {
		if err := a.validate(""); err != nil {
			return err
		}
		if seen[a.ID] {
			return fmt.Errorf("duplicate artifact %s", a.ID)
		}
		seen[a.ID] = true
	}
	return nil
}

func validateComponents(components []Component, native model.Architecture, closed bool) error {
	ids := map[string]bool{}
	for _, component := range components {
		if err := component.Artifact.validate(""); err != nil {
			return err
		}
		switch component.Artifact.Role {
		case "executable", "dll", "driver", "system-component":
		default:
			return errors.New("component: invalid executable/DLL/driver/system role")
		}
		if component.NativeArchitecture != native {
			return errors.New("component: native architecture mismatch")
		}
		if ids[component.Artifact.ID] {
			return errors.New("component: duplicate identity")
		}
		ids[component.Artifact.ID] = true
		if err := uniqueText("component.dependencies", component.Dependencies); err != nil {
			return err
		}
	}
	if closed {
		if len(components) == 0 {
			return errors.New("component: empty dependency closure")
		}
		for _, component := range components {
			for _, dependency := range component.Dependencies {
				if !ids[dependency] {
					return fmt.Errorf("component: missing dependency %s", dependency)
				}
			}
		}
	}
	return nil
}

// ValidateReady intentionally rejects the checked-in pending descriptors.
// Research metadata and static provider candidates cannot authorize execution.
func (c Case) ValidateReady() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if len(c.Pending) != 0 {
		return errors.New("case: unresolved prerequisites")
	}
	if err := c.Source.Validate(); err != nil {
		return err
	}
	payload := false
	for _, input := range c.Inputs {
		payload = payload || input.Role == "payload"
	}
	if !payload {
		return errors.New("case: real payload fixture missing; metadata is insufficient")
	}
	if !c.DependencyClosureComplete {
		return errors.New("case: dependency closure unverified")
	}
	if err := validateComponents(c.Components, c.Host.NativeArchitecture, true); err != nil {
		return err
	}
	if len(c.Algorithms) == 0 {
		return errors.New("case: concrete algorithms unverified")
	}
	for _, op := range c.Operations {
		found := false
		for _, e := range c.Expected {
			found = found || e.Operation == op
		}
		if !found {
			return fmt.Errorf("case: independently expected %s output missing", op)
		}
	}
	return nil
}

// Digest binds evidence to the entire frozen descriptor, including pending
// prerequisites and independently expected results. It is not an output hash.
func (c Case) Digest() string {
	encoded, _ := json.Marshal(c)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (s SourceCensus) Validate() error {
	if len(s.Families) == 0 {
		return errors.New("census: no families")
	}
	if !s.Complete && len(s.Limitations) == 0 {
		return errors.New("census: incompleteness must retain its limitations")
	}
	if err := uniqueText("census.limitations", s.Limitations); err != nil {
		return err
	}
	ids := map[string]bool{}
	for _, family := range s.Families {
		if err := textRequired("family.id", family.ID); err != nil {
			return err
		}
		if ids[family.ID] {
			return errors.New("census: duplicate family")
		}
		ids[family.ID] = true
		if !oneOf(family.Observation, "observed", "documented", "unknown") || !oneOf(family.Availability, "available", "unavailable", "unknown") || !oneOf(family.Implementation, "implemented", "unimplemented", "unknown") || !oneOf(family.MediaCapability, "iso-capable", "update-selection-only", "missing-media", "unknown") {
			return fmt.Errorf("census: invalid classification for %s", family.ID)
		}
		if !oneOf(string(family.Proof), string(Passed), string(Failed), string(Unverified)) {
			return errors.New("census: unknown proof status")
		}
		if err := validateArtifacts(family.Metadata); err != nil {
			return err
		}
		for _, a := range family.Metadata {
			if a.Role != "metadata" {
				return errors.New("census: metadata role required")
			}
		}
		if family.Observation == "observed" && len(family.Metadata) == 0 {
			return errors.New("census: observed family requires actual metadata provenance")
		}
		for key, values := range map[string][]string{"algorithms": family.Algorithms, "proof_cases": family.ProofCases, "gaps": family.Gaps} {
			if err := uniqueText("family."+key, values); err != nil {
				return err
			}
		}
		if family.Proof == Passed && (family.Implementation != "implemented" || family.Observation != "observed" || family.Availability != "available" || len(family.ProofCases) == 0 || len(family.Algorithms) == 0 || len(family.Gaps) != 0) {
			return errors.New("census: passed family lacks implementation/availability/algorithm/fixture evidence")
		}
		if family.Proof != Passed && len(family.Gaps) == 0 {
			return errors.New("census: nonpassing family must retain concrete gaps")
		}
		if family.Availability == "unavailable" && len(family.MissingUpstream) == 0 {
			return errors.New("census: unavailable requires exact missing material and actual failure evidence")
		}
		if family.Availability != "unavailable" && len(family.MissingUpstream) > 0 {
			return errors.New("census: missing-material claim conflicts with availability")
		}
		for _, missing := range family.MissingUpstream {
			if textRequired("missing.identity", missing.Identity) != nil || !oneOf(missing.Failure, "http-404", "http-410", "resolver-confirmed-removed") {
				return errors.New("census: transient/unknown failure is not proof of removed upstream material")
			}
			if err := missing.Evidence.validate("availability-report"); err != nil {
				return err
			}
		}
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, a := range allowed {
		if value == a {
			return true
		}
	}
	return false
}

func operationAssertions(op Operation) []string {
	switch op {
	case Extract:
		return []string{"files-and-metadata-inspected"}
	case Service:
		return []string{"modification-observed"}
	case Reconstruct:
		return []string{"reconstructed-content-inspected"}
	case MasterISO:
		return []string{"filesystem-inspected", "boot-catalog-inspected", "target-boot-resources-inspected"}
	}
	return nil
}

// ValidateBuildable is a per-family gate, not a claim of census completeness.
// A sampled census remains incomplete even when a particular family is proved.
func (s SourceCensus) ValidateBuildable(family string, required []Case, evidence []Evidence) error {
	if err := s.Validate(); err != nil {
		return err
	}
	for _, entry := range s.Families {
		if entry.ID != family {
			continue
		}
		if entry.Proof != Passed || entry.MediaCapability != "iso-capable" {
			return fmt.Errorf("family %s: unverified or not established ISO-capable", family)
		}
		selected := []Case{}
		for _, id := range entry.ProofCases {
			found := false
			for _, c := range required {
				if c.ID == id && c.Gate == "S" && c.SourceFamily == family {
					for _, algorithm := range entry.Algorithms {
						if !contains(c.Algorithms, algorithm) {
							return fmt.Errorf("family %s: case %s omits required algorithm %s", family, id, algorithm)
						}
					}
					selected = append(selected, c)
					found = true
				}
			}
			if !found {
				return fmt.Errorf("family %s: missing bound Gate S case %s", family, id)
			}
		}
		return ValidateEvidence(selected, evidence)
	}
	return fmt.Errorf("family %s: unknown/unimplemented", family)
}
