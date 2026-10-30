package rules

import (
	"fmt"
	"strings"
	"uupbuilder/internal/metadata"
)

type EditionPlan struct {
	Edition, Base string
	Derive        bool
}

// Derivation clones its declared base then invokes native Set-Edition. Merely
// relabelling a WIM is never a valid edition conversion.
func Editions(inv metadata.Inventory, order, derived []string) ([]EditionPlan, []string, error) {
	available := map[string]string{}
	var defaults []string
	for _, image := range inv.Images {
		if image.Edition == "" || image.InstallationType == "WindowsPE" {
			continue
		}
		key := strings.ToLower(image.Edition)
		if available[key] != "" {
			return nil, nil, fmt.Errorf("ambiguous source edition %s", image.Edition)
		}
		available[key] = image.Edition
		defaults = append(defaults, image.Edition)
	}
	if len(available) == 0 {
		for _, comp := range inv.Compositions {
			for _, tag := range comp.Tags {
				if strings.EqualFold(tag.Name, "Edition") && tag.Value != "" {
					key := strings.ToLower(tag.Value)
					if available[key] == "" {
						available[key] = tag.Value
						defaults = append(defaults, tag.Value)
					}
				}
			}
		}
	}
	bases := map[string]string{}
	for _, base := range inv.EditionBases {
		key := strings.ToLower(base.Edition)
		if old := bases[key]; old != "" && !strings.EqualFold(old, base.Base) {
			return nil, nil, fmt.Errorf("conflicting base for %s", base.Edition)
		}
		bases[key] = base.Base
	}
	if len(order) == 0 {
		order = append(defaults, derived...)
	}
	if len(order) == 0 {
		return nil, nil, fmt.Errorf("no inspected source editions")
	}
	seen, used := map[string]bool{}, map[string]bool{}
	var plans []EditionPlan
	var required []string
	for _, edition := range order {
		key := strings.ToLower(edition)
		if seen[key] {
			return nil, nil, fmt.Errorf("duplicate final edition %s", edition)
		}
		seen[key] = true
		plan := EditionPlan{Edition: edition}
		if direct := available[key]; direct != "" {
			plan.Edition = direct
			plan.Base = direct
		} else {
			requested := false
			for _, value := range derived {
				requested = requested || strings.EqualFold(value, edition)
			}
			base := available[strings.ToLower(bases[key])]
			if !requested || base == "" {
				return nil, nil, fmt.Errorf("unsupported explicit edition %s: no inspected direct base", edition)
			}
			plan.Base = base
			plan.Derive = true
		}
		plans = append(plans, plan)
		baseKey := strings.ToLower(plan.Base)
		if !used[baseKey] {
			required = append(required, plan.Base)
			used[baseKey] = true
		}
	}
	return plans, required, nil
}
