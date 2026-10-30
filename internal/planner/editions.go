package planner

import (
	"fmt"
	"strings"
	"uupbuilder/internal/model"
)

func finalEditionOrder(selection model.Selection, settings model.ResolvedSettings) ([]string, error) {
	selected := append(append([]string(nil), selection.Editions...), settings.Conversion.Editions.Derived...)
	seen := map[string]bool{}
	for _, edition := range selected {
		key := strings.ToLower(edition)
		if seen[key] {
			return nil, fmt.Errorf("duplicate selected/derived edition %s", edition)
		}
		seen[key] = true
	}
	order := settings.Output.EditionOrder
	if len(order) == 0 {
		return selected, nil
	}
	if len(order) != len(selected) {
		return nil, fmt.Errorf("output.edition_order must contain every selected and derived edition exactly once")
	}
	for _, edition := range order {
		key := strings.ToLower(edition)
		if !seen[key] {
			return nil, fmt.Errorf("output.edition_order contains unselected/duplicate edition %s", edition)
		}
		delete(seen, key)
	}
	return append([]string(nil), order...), nil
}

func serviceStrategy(settings model.ResolvedSettings, plan ServicePlan) (model.ServicingStrategy, error) {
	strategy := settings.Conversion.ServicingStrategy
	editions := settings.Conversion.Editions.Strategy
	if strategy != model.ServicingAuto && editions != model.ServicingAuto && strategy != editions {
		return "", fmt.Errorf("conflicting servicing and edition strategies")
	}
	if strategy == model.ServicingAuto {
		strategy = editions
	}
	canShare := true
	for _, update := range plan.Updates {
		if update.Integrate && len(update.Editions) > 0 {
			canShare = false
		}
	}
	if strategy == model.ServicingSharedBase && !canShare {
		return "", fmt.Errorf("explicit shared-base cannot preserve edition-specific update applicability")
	}
	if strategy == model.ServicingAuto {
		strategy = model.ServicingPerEdition
		if canShare && len(plan.Editions) > len(plan.Bases) {
			strategy = model.ServicingSharedBase
		}
	}
	return strategy, nil
}
