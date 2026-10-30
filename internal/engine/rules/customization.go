package rules

import (
	"fmt"
	"uupbuilder/internal/model"
)

// Edge default preserves the source's browser policy. Edge is not universally
// an Appx/CBS package; forced removal/addition needs generation-specific media
// and servicing evidence and cannot be implemented by deleting its files.
func Edge(policy model.EdgePolicy) error {
	if policy != model.EdgeDefault {
		return fmt.Errorf("Edge policy %q requires an unavailable source-specific Edge installer/removal rule", policy)
	}
	return nil
}
