package tools

import (
	"fmt"
	"slices"

	"uupbuilder/internal/model"
)

type Operation string

const (
	Extract     Operation = "extract"
	Inspect     Operation = "inspect"
	Service     Operation = "service"
	Reconstruct Operation = "reconstruct"
	MasterISO   Operation = "master-iso"
)

type Requirement struct {
	Host           model.Host
	Target         model.Architecture
	Operations     []Operation
	ManifestDigest string
}

// IntentOperations records documented investigation scope, never supported
// capabilities. Every schema-1 candidate retains its unresolved blockers.
type Candidate struct {
	ID                 string
	Version            string
	NativeArchitecture model.Architecture
	Route              string
	IntentOperations   []Operation
	Blockers           []Blocker
}
type Selection struct {
	Requirement Requirement
	Candidates  []Candidate
	Blockers    []Blocker
}
type BlockedError struct{ Selection Selection }

func (e *BlockedError) Error() string {
	return fmt.Sprintf("%s: native %s, target %s", ErrUnverified, e.Selection.Requirement.Host.NativeArchitecture, e.Selection.Requirement.Target)
}
func (e *BlockedError) Unwrap() error { return ErrUnverified }

func (r Requirement) Validate() error {
	if r.Host.WindowsBuild < 10240 || r.Host.NativeArchitecture.Validate() != nil || r.Host.ProcessArchitecture.Validate() != nil || r.Target.Validate() != nil || len(r.Operations) == 0 || !validSHA(r.ManifestDigest) {
		return ErrInvalidInput
	}
	ops := map[Operation]bool{}
	for _, op := range r.Operations {
		if !operationValid(op) || ops[op] {
			return ErrInvalidInput
		}
		ops[op] = true
	}
	return nil
}

// Select reports candidate facts and capability gaps. It never drops an
// upstream target, treats the process CPU as native, or infers generation/
// operation support from a tool's version or a PE machine header.
func (m TrustedManifest) Select(req Requirement) (Selection, error) {
	if err := req.Validate(); err != nil {
		return Selection{}, err
	}
	if req.ManifestDigest != m.digest {
		return Selection{}, ErrManifestDigest
	}
	req.Operations = slices.Clone(req.Operations)
	result := Selection{Requirement: req, Blockers: []Blocker{{Code: "capability-unverified", Detail: fmt.Sprintf("No trusted native runtime, source-generation and operation-specific evidence for native %s target %s operations %v", req.Host.NativeArchitecture, req.Target, req.Operations)}}}
	for _, p := range m.providers {
		if p.NativeArchitecture != req.Host.NativeArchitecture {
			continue
		}
		c := Candidate{ID: p.ID, Version: p.Version, NativeArchitecture: p.NativeArchitecture, Route: p.Route, IntentOperations: slices.Clone(p.IntentOperations), Blockers: slices.Clone(p.Pending)}
		for _, op := range req.Operations {
			if !slices.Contains(p.IntentOperations, op) {
				c.Blockers = append(c.Blockers, Blocker{Code: "operation-unavailable", Detail: fmt.Sprintf("Candidate %s has no implementation/evidence for %s on target %s", p.ID, op, req.Target)})
			}
		}
		result.Candidates = append(result.Candidates, c)
	}
	if len(result.Candidates) == 0 {
		result.Blockers = append(result.Blockers, Blocker{Code: "native-provider-unavailable", Detail: fmt.Sprintf("No pinned candidate for native host %s; target %s remains requested", req.Host.NativeArchitecture, req.Target)})
	}
	return result, nil
}

// VerifiedFile is a byte-identity snapshot, not an operation attestation. Paths
// from the private materializer are never returned by Ensure in schema 1.
type VerifiedFile struct {
	ProviderID         string
	LogicalPath        string
	Path               string
	SHA256             string
	Version            string
	Role               string
	NativeArchitecture model.Architecture
}

// Toolchain has no exported constructor or mutable collections. Schema 1 never
// produces an operational Toolchain; zero values carry no paths/capabilities.
type Toolchain struct {
	files          []VerifiedFile
	operations     []Operation
	manifestDigest string
	providerIDs    []string
}

func (t Toolchain) Files() []VerifiedFile   { return append([]VerifiedFile(nil), t.files...) }
func (t Toolchain) Operations() []Operation { return append([]Operation(nil), t.operations...) }
func (t Toolchain) ManifestDigest() string  { return t.manifestDigest }
func (t Toolchain) ProviderIDs() []string   { return slices.Clone(t.providerIDs) }
