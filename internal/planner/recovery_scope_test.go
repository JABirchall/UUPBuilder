package planner

import (
	"context"
	"strings"
	"testing"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/tools"
)

func TestExcludedRecoveryObservationDoesNotBlockISOMedia(t *testing.T) {
	p, req := fixture(t)
	req.Intent = BuildMedia
	req.Resolution.AppPhase = metadata.PhasePostAssembly
	req.Resolution.Classification = metadata.ClassificationMetadataIncomplete
	req.Resolution.Inventory.Classification = metadata.ClassificationMetadataIncomplete
	detail := "winre requires semantic inspection or explicit upstream absence evidence"
	req.Resolution.Inventory.Gaps = []metadata.Gap{{Code: "role-unresolved", Detail: detail}}
	req.Resolution.Diagnostics = []model.Diagnostic{{Code: "metadata-role-unresolved", Severity: model.SeverityError, Message: detail}}
	p.SelectTools = func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }
	plan, err := p.Resolve(context.Background(), req)
	if err != nil || plan.Validate() != nil {
		t.Fatalf("excluded recovery blocked ISO: %v", err)
	}
	// Ignoring an excluded recovery observation must not suppress Setup gaps.
	req.Resolution.Inventory.Gaps[0].Detail = "setup requires semantic inspection"
	req.Resolution.Diagnostics[0].Message = "setup requires semantic inspection"
	if _, err := p.Resolve(context.Background(), req); err == nil || !strings.Contains(err.Error(), "setup") {
		t.Fatalf("missing Setup content escaped preflight: %v", err)
	}
}
