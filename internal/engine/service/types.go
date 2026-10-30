// Package service executes typed offline image servicing plans. Native helper
// exit status is followed by independent package and edition inspection.
package service

import (
	"context"
	"errors"
	"uupbuilder/internal/engine/rules"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
)

var ErrVerification = errors.New("serviced image verification failed")
var ErrProviderUnavailable = errors.New("offline servicing provider unavailable")

type ImageRef struct {
	WIMPath string
	Index   int
	Name    string
}
type PackageObservation struct {
	Identity metadata.PackageIdentity
	State    string
}
type ImageIdentity struct {
	Index        int
	Edition      string
	Architecture model.Architecture
	Language     string
	Packages     []PackageObservation
}
type InspectedImage struct {
	ImageRef
	Identity ImageIdentity
	SHA256   string
}
type UpdateInput struct {
	Resource metadata.ResourceReference
	Path     string
}
type Inspection struct {
	Edition  string
	Packages []PackageObservation
}
type ServiceRequest struct {
	Plan        planner.ServicePlan
	Images      []InspectedImage
	Payloads    []UpdateInput
	Transaction *jobstore.Transaction
}
type RetainedUpdate struct {
	ID, Path string
	Format   metadata.UpdateFormat
}
type ServicedImages struct {
	PlanDigest      string
	WIMPath         string
	Images          []ImageIdentity
	RetainedUpdates []RetainedUpdate
	RetainedBases   []string
	Outputs         []jobstore.OutputIdentity
}

// Backend only accepts fixed operations. A concrete implementation verifies
// its native tools; callers cannot provide arbitrary commands or arguments.
// Mounts and output paths are created by the active transaction, never adopted.
type Backend interface {
	Check(context.Context, ServiceRequest) error
	Export(context.Context, ImageRef, string, model.Emit) error
	Mount(context.Context, string, platform.OwnedMount, model.Emit) error
	Inspect(context.Context, platform.OwnedMount, model.Emit) (Inspection, error)
	Apply(context.Context, platform.OwnedMount, rules.UpdatePlan, string, model.Emit) error
	SetEdition(context.Context, platform.OwnedMount, string, model.Emit) error
	Cleanup(context.Context, platform.OwnedMount, bool, model.Emit) error
	Unmount(context.Context, platform.OwnedMount, bool, model.Emit) error
	InspectWIM(context.Context, string, model.Emit) ([]ImageIdentity, error)
}

type Executor struct{ Backend Backend }
