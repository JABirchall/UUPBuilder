package probes

import (
	"context"
	"os"

	"uupbuilder/internal/model"
)

const ExpandCompDBCABV1 = "expand-compdb-cab-v1"
const ObserveWIMLZMSV1 = "observe-wim-lzms-solid-v1"

// RuntimeConfig is an internal probe request. It never accepts commands or
// arbitrary argument vectors, and never grants gate readiness. Roots locate
// retained research material; the case and recipe bind the actual identities.
type RuntimeConfig struct {
	CaseDigest      string           `json:"case_digest"`
	FixtureRoot     string           `json:"-" toml:"-"`
	WorkspaceParent string           `json:"-" toml:"-"`
	Inputs          []FileBinding    `json:"inputs"`
	Components      []FileBinding    `json:"components"`
	Recipe          string           `json:"recipe"`
	Extraction      CompDBExtraction `json:"extraction"`
	WIM             WIMExtraction    `json:"wim,omitempty"`
}

type FileBinding struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

type CompDBExtraction struct {
	InputID       string         `json:"input_id"`
	ExpectationID string         `json:"expectation_id"`
	ExpandID      string         `json:"expand_id"`
	CertutilID    string         `json:"certutil_id"`
	Member        string         `json:"member"`
	Identity      CompDBIdentity `json:"identity"`
}

type CompDBIdentity struct {
	Architecture model.Architecture `json:"architecture"`
	Type         string             `json:"type"`
	BuildID      string             `json:"build_id"`
	OSVersion    string             `json:"os_version"`
}

type WIMExtraction struct {
	InputID       string          `json:"input_id"`
	ExpectationID string          `json:"expectation_id"`
	CabinetID     string          `json:"cabinet_id"`
	CertutilID    string          `json:"certutil_id"`
	Member        string          `json:"member"`
	Identity      PackageIdentity `json:"identity"`
}

type PackageIdentity struct {
	Name           string             `json:"name"`
	Version        string             `json:"version"`
	Architecture   model.Architecture `json:"architecture"`
	PublicKeyToken string             `json:"public_key_token"`
	Language       string             `json:"language"`
}

type runtimeKey struct{}

// WithRuntime binds a snapshot to this request only. No process-global mutable
// fixture/configuration state exists. Configuration cannot supply proof facts.
func WithRuntime(ctx context.Context, config RuntimeConfig) context.Context {
	config.Inputs = append([]FileBinding(nil), config.Inputs...)
	config.Components = append([]FileBinding(nil), config.Components...)
	return context.WithValue(ctx, runtimeKey{}, config)
}

type proofWorkspace interface {
	artifactFiles
	MkdirAll(string) error
	Path() string
	Close() error
}

type processResult struct {
	PID            uint32
	Exit           uint32
	Stdout, Stderr string
	Cancelled      bool
}
type directRequest struct {
	ID, Executable string
	Arguments      []string
}

// Ports belong to this probe package. Only platform-specific construction can
// produce the real Windows adapter; tests inject explicitly synthetic ports.
type runtimePorts struct {
	observe          func() (ObservedHost, error)
	createWorkspace  func(string, string) (proofWorkspace, error)
	fileSystem       func(string) (model.FileSystemCapabilities, error)
	openComponent    func(string, model.Architecture) (*os.File, string, error)
	run              func(context.Context, proofWorkspace, directRequest, model.Emit) (processResult, error)
	decompress       func(context.Context, string, []byte, int) ([]byte, error)
	privateWorkspace func(proofWorkspace) any
	kind             string
}
