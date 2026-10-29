package planner

import (
	"fmt"
	"uupbuilder/internal/model"
)

func settingsApplicability(s model.ResolvedSettings) ([]model.SettingApplicability, error) {
	excluded := func(key string) ([]model.SettingApplicability, error) {
		return nil, fmt.Errorf("%w: %s explicitly requests an excluded standalone output or recovery feature", ErrBlocked, key)
	}
	if s.Output.Kind != model.OutputISO {
		return excluded("output.kind")
	}
	if s.Conversion.IncludeWinRE {
		return excluded("conversion.include_winre")
	}
	if s.Conversion.WinREUpdates != model.InclusionOmit {
		return excluded("conversion.winre_updates")
	}
	for _, target := range s.Conversion.Drivers.Targets {
		if target == model.DriverWinRE {
			return excluded("conversion.drivers.targets")
		}
	}
	// Applicability of conversion/app policies belongs to the corresponding
	// source-bound stage producers. Keeping the requested value is intentional.
	return []model.SettingApplicability{{Key: "output.kind", RequestedValue: "iso", EffectiveValue: "iso", Supported: true, Reason: "ISO file intent; execution still requires all registered stage providers."}}, nil
}
