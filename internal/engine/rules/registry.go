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

// Generation capabilities describe documented offline DISM features, not a
// source allowlist or a certificate that a particular update is applicable.
// Windows client and Server 10.0 images share these servicing operations.
// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism-operating-system-package-servicing-command-line-options
func generationForBuild(build uint32) (Generation, error) {
	if build < 10240 {
		return Generation{}, fmt.Errorf("offline servicing requires inspected Windows 10.0 or later")
	}
	return Generation{ID: "windows-10.0-offline-v1", Build: build, Checkpoint: build >= 26100, OfflineMSU: true, Cleanup: true, ResetBase: true}, nil
}

// Validate rejects resealed plans whose feature flags differ from the inspected
// generation's feature ranges. Runtime/native applicability is checked at run.
func (g Generation) Validate() error {
	expected, err := generationForBuild(g.Build)
	if err != nil || g != expected {
		return fmt.Errorf("invalid servicing generation capabilities")
	}
	return nil
}

func Select(inv metadata.Inventory) (Generation, error) {
	var build uint32
	observe := func(version string) error {
		parts := strings.Split(version, ".")
		if len(parts) < 3 || len(parts) > 4 {
			return fmt.Errorf("servicing requires inspected OS version, got %q", version)
		}
		values := make([]uint32, len(parts))
		for i, part := range parts {
			value, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid inspected servicing OS version %q", version)
			}
			values[i] = uint32(value)
		}
		if values[0] != 10 || values[1] != 0 {
			return fmt.Errorf("offline servicing unavailable for inspected OS version %q", version)
		}
		if build != 0 && build != values[2] {
			return fmt.Errorf("conflicting inspected servicing OS versions")
		}
		build = values[2]
		return nil
	}
	for _, image := range inv.Images {
		if !strings.EqualFold(image.InstallationType, "WindowsPE") && image.Edition != "" {
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
	return generationForBuild(build)
}
