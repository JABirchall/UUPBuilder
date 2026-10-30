// Package output verifies and publishes the final Windows installation ISO.
package output

import (
	"context"
	"errors"
	"uupbuilder/internal/engine/isocontent"
	"uupbuilder/internal/engine/service"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
)

var ErrVerification = errors.New("ISO output verification failed")

// VerifiedArtifact can only carry a verification performed inside this package.
// Deserializing a report or constructing its zero value grants no publication.
type VerifiedArtifact struct{ state *verifiedState }
type verifiedState struct {
	path, planDigest, sha256 string
	size                     int64
	source                   model.SourceIdentity
	settings                 reportSettings
	tools                    []ToolIdentity
}

// File is an absolute materialized input/output with independently read bytes.
type File struct {
	Path, SHA256 string
	Size         int64
}
type ExportRequest struct {
	Plan       planner.ReadyPlan
	Customized service.CustomizedImages
	Directory  string
}
type ExportResult struct {
	PlanDigest    string
	Source        model.SourceIdentity
	Format        model.ImageFormat
	Files         []File
	Images        []service.ImageIdentity
	Customization service.CustomizedImages
	Tools         []ToolIdentity
}
type Exporter interface {
	Export(context.Context, string, string, model.ImageFormat, int) error
	VerifyImage(context.Context, string, model.ImageFormat) error
}
type MasterRequest struct {
	Plan   planner.ReadyPlan
	Export ExportResult
	// MediaDirectory contains the original source media plus the source-bound
	// assembled boot.wim and exactly Export.Files under sources/.
	MediaDirectory, ISOPath, Label string
	BootWIM                        File
	BootImages                     []service.ImageIdentity
}
type Masterer interface {
	Master(context.Context, string, string, isocontent.ISOExpectations) error
}
type PreparedISO struct {
	PlanDigest string
	Source     model.SourceIdentity
	Export     ExportResult
	Contents   isocontent.ISOExpectations
	Tools      []ToolIdentity
	BootWIM    File
	BootImages []service.ImageIdentity
}
type ToolIdentity struct{ Name, Version, SHA256 string }
type ToolReporter interface {
	ToolIdentities(context.Context) ([]ToolIdentity, error)
}
type PublishedArtifact struct{ state *publishedState }
type publishedState struct {
	artifact         model.Artifact
	checksum, report string
}
