package planner

import (
	"fmt"
	"strings"
	"uupbuilder/internal/engine/rules"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

type ServicePlan struct {
	Source                                    model.SourceIdentity
	InventoryDigest                           string
	Generation                                rules.Generation
	Policy                                    model.UpdatePolicy
	Strategy                                  model.ServicingStrategy
	Updates                                   []rules.UpdatePlan
	Editions                                  []rules.EditionPlan
	Bases                                     []string
	Cleanup, ResetBase, PreserveRequiredBases bool
	Digest                                    string
}

func BuildServicePlan(inv metadata.Inventory, settings model.ResolvedSettings) (ServicePlan, error) {
	if err := settings.Validate(); err != nil {
		return ServicePlan{}, err
	}
	generation, err := rules.Select(inv)
	if err != nil {
		return ServicePlan{}, err
	}
	plan := ServicePlan{Source: inv.Source, InventoryDigest: hash(inv), Generation: generation, Policy: settings.Conversion.Updates, Cleanup: settings.Conversion.Cleanup, PreserveRequiredBases: settings.Conversion.Editions.PreserveRequiredBases}
	if inv.Manifest.Validate() != nil || inv.Manifest.Source != inv.Source {
		return ServicePlan{}, fmt.Errorf("servicing source/manifest identity mismatch")
	}
	if plan.Updates, err = rules.OrderUpdates(inv, settings, generation); err != nil {
		return ServicePlan{}, err
	}
	if settings.Conversion.Updates != model.UpdatesOmit {
		for _, payload := range inv.Manifest.Payloads {
			if strings.HasSuffix(strings.ToLower(payload.Destination), ".msu") {
				classified := false
				for _, update := range inv.Updates {
					if update.Resource.Payload == payload.Identity {
						classified = true
						break
					}
				}
				if !classified {
					return ServicePlan{}, fmt.Errorf("servicing metadata unresolved: %s needs inspected package identities/dependencies", payload.Destination)
				}
			}
		}
	}
	if plan.Editions, plan.Bases, err = rules.Editions(inv, settings.Output.EditionOrder, settings.Conversion.Editions.Derived); err != nil {
		return ServicePlan{}, err
	}
	if plan.Strategy, err = serviceStrategy(settings, plan); err != nil {
		return ServicePlan{}, err
	}
	if plan.Cleanup && !generation.Cleanup {
		return ServicePlan{}, fmt.Errorf("cleanup unavailable for %s", generation.ID)
	}
	switch settings.Conversion.ResetBase {
	case model.ResetBaseOn:
		if !plan.Cleanup || !generation.ResetBase {
			return ServicePlan{}, fmt.Errorf("explicit reset-base requires applicable cleanup")
		}
		plan.ResetBase = true
	case model.ResetBaseAuto:
		// Auto preserves rollback capability. Only explicit On is irreversible.
		plan.ResetBase = false
	}
	plan = copyOf(plan)
	plan.Digest = plan.digest()
	return plan, plan.Validate()
}

func (p ServicePlan) digest() string { p.Digest = ""; return hash(p) }
func (p ServicePlan) Validate() error {
	if p.Digest != p.digest() {
		return ErrIdentityChanged
	}
	if p.Source.Validate() != nil || p.Generation.ID != "windows-client-28000-v1" || p.Generation.Build != 28000 || len(p.Editions) == 0 || len(p.Bases) == 0 {
		return ErrInvalidPlan
	}
	if p.Policy != model.UpdatesIntegrate && p.Policy != model.UpdatesExternal && p.Policy != model.UpdatesOmit {
		return ErrInvalidPlan
	}
	if p.Strategy != model.ServicingPerEdition && p.Strategy != model.ServicingSharedBase {
		return ErrInvalidPlan
	}
	if p.ResetBase && (!p.Cleanup || !p.Generation.ResetBase) || p.Cleanup && !p.Generation.Cleanup || p.Policy == model.UpdatesOmit && len(p.Updates) > 0 {
		return ErrInvalidPlan
	}
	seen := map[string]bool{}
	for _, edition := range p.Editions {
		key := strings.ToLower(edition.Edition)
		if key == "" || seen[key] || edition.Base == "" || edition.Derive == strings.EqualFold(edition.Edition, edition.Base) {
			return ErrInvalidPlan
		}
		seen[key] = true
	}
	for _, update := range p.Updates {
		if update.Integrate != (p.Policy == model.UpdatesIntegrate) || p.Policy == model.UpdatesExternal && !update.Retain {
			return ErrInvalidPlan
		}
	}
	return nil
}

func (p ServicePlan) validateSettings(selection model.Selection, settings model.ResolvedSettings) error {
	if p.Policy != settings.Conversion.Updates || p.Cleanup != settings.Conversion.Cleanup || p.ResetBase != (settings.Conversion.ResetBase == model.ResetBaseOn) || p.PreserveRequiredBases != settings.Conversion.Editions.PreserveRequiredBases {
		return ErrInvalidPlan
	}
	strategy, err := serviceStrategy(settings, p)
	if err != nil || strategy != p.Strategy {
		return ErrInvalidPlan
	}
	order, err := finalEditionOrder(selection, settings)
	if err != nil || len(order) != len(p.Editions) {
		return ErrInvalidPlan
	}
	for i, edition := range order {
		if !strings.EqualFold(edition, p.Editions[i].Edition) {
			return ErrInvalidPlan
		}
	}
	return nil
}

// OutputPaths is the complete set of stage-owned files, fixed before the graph
// is frozen. Temporary bases are internal files and never final WIM indices.
func (p ServicePlan) OutputPaths() []string {
	paths := []string{"result.json", "serviced.wim"}
	for i := range p.Editions {
		paths = append(paths, fmt.Sprintf("edition-%03d.wim", i+1))
	}
	if p.Strategy == model.ServicingSharedBase {
		for i := range p.Bases {
			paths = append(paths, fmt.Sprintf("base-%03d.wim", i+1))
		}
	}
	for i, update := range p.Updates {
		if update.Retain {
			paths = append(paths, fmt.Sprintf("update-%03d.%s", i+1, update.Format))
		}
	}
	return paths
}
