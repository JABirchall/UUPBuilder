// Package rules produces generation-specific typed decisions, never commands.
package rules

import (
	"fmt"
	"strconv"
	"strings"
	"uupbuilder/internal/metadata"
)

type Generation struct {
	ID                                         string
	Build                                      uint32
	Checkpoint, OfflineMSU, Cleanup, ResetBase bool
}

// U08 implements the selected 26H1 generation. Other targets stay selectable;
// an unimplemented generation gets an explicit preflight error.
func Select(inv metadata.Inventory) (Generation, error) {
	var build uint64
	observe := func(version string) error {
		parts := strings.Split(version, ".")
		if len(parts) < 3 {
			return fmt.Errorf("servicing requires inspected OS version, got %q", version)
		}
		value, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil || (build != 0 && build != value) {
			return fmt.Errorf("conflicting/invalid servicing OS versions")
		}
		build = value
		return nil
	}
	for _, image := range inv.Images {
		if image.InstallationType != "WindowsPE" && image.Edition != "" && image.Build != "" {
			if err := observe(image.Build); err != nil {
				return Generation{}, err
			}
		}
	}
	for _, comp := range inv.Compositions {
		if comp.OSVersion != "" {
			if err := observe(comp.OSVersion); err != nil {
				return Generation{}, err
			}
		}
	}
	if build != 28000 {
		return Generation{}, fmt.Errorf("servicing rules unavailable for inspected build %d (selected generation: 28000)", build)
	}
	return Generation{ID: "windows-client-28000-v1", Build: 28000, Checkpoint: true, OfflineMSU: true, Cleanup: true, ResetBase: true}, nil
}
