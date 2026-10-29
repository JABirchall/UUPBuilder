// Package planner validates a draft into an immutable, locator-free operation graph.
package planner

import (
	"context"
	"errors"

	"uupbuilder/internal/model"
	"uupbuilder/internal/source"
	"uupbuilder/internal/tools"
)

type JobIntent string

const (
	BuildMedia   JobIntent = "build-media"
	DownloadOnly JobIntent = "download-only"
)

type OperationKind string

const (
	DownloadPayloads OperationKind = "download-payloads"
	AssembleImage    OperationKind = "assemble-image"
	InspectApps      OperationKind = "inspect-apps"
	ServiceImage     OperationKind = "service-image"
	CustomizeImage   OperationKind = "customize-image"
	ExportImage      OperationKind = "export-image"
	MasterISO        OperationKind = "master-iso"
	PublishISO       OperationKind = "publish-iso"
)

type Identity struct {
	Name    string
	Version string
	Digest  string
}
type InputIdentity struct {
	Name   string
	Digest string
}

// Operation is a fixed handler identity. It cannot carry executable paths,
// arguments, command text, runtime locators or additional authority.
type Operation struct {
	ID           string
	Kind         OperationKind
	SourceDigest string
	Rules        []Identity
	ToolDigests  []string
	Inputs       []InputIdentity
	DependsOn    []string
	OwnedPaths   []string
}
type Request struct {
	Selection     model.Selection
	Settings      model.ResolvedSettings
	Resolution    source.Resolution
	Host          model.Host
	DraftRevision uint64
	Intent        JobIntent
}
type Planner struct {
	InspectStorage   func(context.Context, string) (Volume, error)
	DefaultWorkspace string
	DefaultCache     string
	// SelectTools is the producer's read-only capability gate. Nil uses the
	// embedded trusted manifest, whose current candidates remain blocked.
	SelectTools func(tools.Requirement) (tools.Selection, error)
}
type Volume struct {
	Path           string
	ID             string
	FileSystem     model.FileSystemCapabilities
	AvailableBytes uint64
	MaxFileBytes   uint64
}
type Estimate struct {
	KnownPayloadBytes uint64
	ScratchBytes      uint64
	OutputBytes       uint64
	// Scratch/output are conservative estimates, never measured image sizes.
	ScratchEstimated bool
	OutputEstimated  bool
}
type StorageCheck struct {
	Role             string
	Volume           Volume
	RequiredBytes    uint64
	LargestFileBytes uint64
}
type frozen struct {
	Version         int
	Selection       model.Selection
	Requested       model.ResolvedSettings
	Effective       model.ResolvedSettings
	Manifest        model.PayloadManifest
	Host            model.Host
	InventoryDigest string
	AppPhase        string
	Operations      []Operation
	Tools           []tools.Requirement
	Applicability   []model.SettingApplicability
	DraftRevision   uint64
	Intent          JobIntent
	Estimate        Estimate
	Storage         []StorageCheck
}
type ReadyPlan struct {
	data   *frozen
	digest string
}

var (
	ErrIdentityChanged = errors.New("frozen plan identity changed")
	ErrInvalidPlan     = errors.New("invalid frozen plan")
	ErrBlocked         = errors.New("build preflight blocked")
)
