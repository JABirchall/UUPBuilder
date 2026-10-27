//go:build windows

// Package windows implements the Windows 10+ host boundary. It does not select
// tools, plan image operations, or authorize a frozen operation graph.
package windows

import (
	"context"
	"io"

	"uupbuilder/internal/model"
)

type CancellationPolicy string

const (
	// CancelTerminateTree is for operations whose caller permits forced stop.
	CancelTerminateTree CancellationPolicy = "terminate-owned-tree"
	// CancelWait defers cancellation until the operation exits naturally. Use it
	// for mutation that has no safe forced-interruption boundary.
	CancelWait CancellationPolicy = "wait-for-exit"
)

// Invocation accepts an absolute .exe and argv, never a shell command string.
// Directory is a logical path beneath Workspace (empty means its root).
// The caller must authorize the executable, arguments and cancellation policy.
type Invocation struct {
	Executable   string
	Arguments    []string
	Workspace    *Workspace
	Directory    string
	JobID        string
	OperationID  string
	Cancellation CancellationPolicy
}

// RunResult contains bounded tails of captured output (at most 64 KiB each).
type RunResult struct {
	ProcessID uint32
	ExitCode  uint32
	Stdout    string
	Stderr    string
	Cancelled bool
}

// WorkspaceIdentity is a recovery capability for a directory created by
// CreateWorkspace. Treat its random Token as private job state, not as a plan.
type WorkspaceIdentity struct {
	Path  string `json:"path"`
	JobID string `json:"job_id"`
	Token string `json:"token"`
}

// OwnedMount records a claimed empty directory, not evidence of an OS mount.
// J1 must journal actual mount intent/results and J2 authorize image operations.
type OwnedMount struct {
	Workspace    WorkspaceIdentity `json:"workspace"`
	RelativePath string            `json:"relative_path"`
	JobID        string            `json:"job_id"`
	OperationID  string            `json:"operation_id"`
	DirectoryID  FileIdentity      `json:"directory_id"`
}

// FileIdentity is an NTFS volume/file-index pair, stable across path renames.
type FileIdentity struct {
	VolumeSerial uint32 `json:"volume_serial"`
	FileIndex    uint64 `json:"file_index"`
}

// PeerIdentity binds a local process instance, token, session and executable.
// CreationTime is the native FILETIME value, preventing PID reuse ambiguity.
type PeerIdentity struct {
	ProcessID    uint32 `json:"process_id"`
	CreationTime uint64 `json:"creation_time"`
	UserSID      string `json:"user_sid"`
	SessionID    uint32 `json:"session_id"`
	Elevated     bool   `json:"elevated"`
	Executable   string `json:"executable"`
}

type WorkerConnection interface {
	io.ReadWriteCloser
	PeerIdentity() PeerIdentity
}

// WorkerDescriptor identifies a frozen job. No executable, command, argument,
// operation graph, credentials or signed locators are carried by this DTO.
// J2 must load and validate the frozen plan before servicing any operation.
type WorkerDescriptor struct {
	Version    uint32            `json:"version"`
	JobID      string            `json:"job_id"`
	PlanDigest string            `json:"plan_digest"`
	Workspace  WorkspaceIdentity `json:"workspace"`
}

type WorkerBootstrap struct {
	Descriptor WorkerDescriptor `json:"descriptor"`
	PipeName   string           `json:"pipe_name"`
	Parent     PeerIdentity     `json:"parent"`
}

// ProcessRunner is the narrow platform contract for W2 and engine consumers.
type ProcessRunner interface {
	Run(ctx context.Context, inv Invocation, emit model.Emit) (RunResult, error)
}
