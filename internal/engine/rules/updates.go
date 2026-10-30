package rules

import (
	"fmt"
	"sort"
	"strings"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

type UpdatePlan struct {
	metadata.Update
	Integrate, Retain, Expand bool
}

// Every declared checkpoint must be present. Independent work is ordered SSU,
// checkpoint, LCU, ordinary updates, enablement. Dependencies come from inspected
// facts, not KBs.
// https://learn.microsoft.com/windows/deployment/update/catalog-checkpoint-cumulative-updates
func OrderUpdates(inv metadata.Inventory, settings model.ResolvedSettings, generation Generation) ([]UpdatePlan, error) {
	c := settings.Conversion
	for _, update := range inv.Updates {
		if update.Target != "" && update.Target != metadata.RoleOS && update.Target != metadata.RoleWinRE {
			return nil, fmt.Errorf("unsupported update target %q", update.Target)
		}
	}
	if c.Updates == model.UpdatesOmit {
		return nil, nil
	}
	known := map[string]UpdatePlan{}
	rank := map[metadata.UpdateKind]int{metadata.UpdateServicingStack: 0, metadata.UpdateCheckpoint: 1, metadata.UpdateCumulative: 2, metadata.UpdateRegular: 3, metadata.UpdateEnablement: 4}
	for _, update := range inv.Updates {
		if update.Target == metadata.RoleWinRE {
			if !c.IncludeWinRE && c.WinREUpdates == model.InclusionOmit {
				continue
			}
			return nil, fmt.Errorf("WinRE update servicing is excluded from this workflow")
		}
		if update.Kind == metadata.UpdateEnablement && c.EnablementPackages == model.InclusionOmit {
			continue
		}
		if _, ok := rank[update.Kind]; !ok {
			return nil, fmt.Errorf("unsupported update kind %q", update.Kind)
		}
		if update.Kind == metadata.UpdateCheckpoint && !generation.Checkpoint {
			return nil, fmt.Errorf("checkpoint unsupported by %s", generation.ID)
		}
		if update.ID == "" || known[update.ID].ID != "" || len(update.Packages) == 0 {
			return nil, fmt.Errorf("ambiguous update or missing expected CBS identities: %q", update.ID)
		}
		if update.Format != metadata.UpdateCAB && update.Format != metadata.UpdateMSU {
			return nil, fmt.Errorf("unsupported update container %q", update.Format)
		}
		found := false
		for _, payload := range inv.Manifest.Payloads {
			if payload.Identity == update.Resource.Payload {
				found = true
			}
		}
		if !found || update.Resource.Member != "" {
			return nil, fmt.Errorf("update %s needs verified standalone CAB/MSU payload", update.ID)
		}
		for _, pack := range update.Packages {
			if pack.Name == "" || pack.Version == "" || pack.PublicKeyToken == "" || (pack.Architecture != inv.Source.Architecture && pack.Architecture != "neutral") {
				return nil, fmt.Errorf("invalid expected package for %s", update.ID)
			}
		}
		plan := UpdatePlan{Update: update, Integrate: c.Updates == model.UpdatesIntegrate, Retain: c.Updates == model.UpdatesExternal}
		if update.Format == metadata.UpdateMSU {
			policy := c.CumulativeUpdates
			if update.Kind == metadata.UpdateCheckpoint {
				policy = c.CheckpointUpdates
			}
			if c.CumulativeMSU == model.MSUExpand && policy == model.ExpansionPreserve {
				return nil, fmt.Errorf("conflicting expansion choices for %s", update.ID)
			}
			plan.Expand = plan.Integrate && (policy == model.ExpansionExpand || c.CumulativeMSU == model.MSUExpand || !generation.OfflineMSU)
			plan.Retain = plan.Retain || c.CumulativeMSU == model.MSUKeep
			if plan.Expand && len(update.Members) == 0 {
				return nil, fmt.Errorf("%s: explicit expansion requires inspected ordered CAB members", update.ID)
			}
		}
		known[update.ID] = plan
	}
	if c.EnablementPackages == model.InclusionInclude {
		found := false
		for _, update := range known {
			found = found || update.Kind == metadata.UpdateEnablement
		}
		if !found {
			return nil, fmt.Errorf("explicit enablement inclusion has no inspected package")
		}
	}
	var keys []string
	for id := range known {
		keys = append(keys, id)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := known[keys[i]], known[keys[j]]
		if rank[a.Kind] != rank[b.Kind] {
			return rank[a.Kind] < rank[b.Kind]
		}
		return keys[i] < keys[j]
	})
	state := map[string]int{}
	var result []UpdatePlan
	var visit func(string) error
	visit = func(id string) error {
		if state[id] == 2 {
			return nil
		}
		if state[id] == 1 {
			return fmt.Errorf("update dependency cycle at %s", id)
		}
		update, ok := known[id]
		if !ok {
			return fmt.Errorf("missing update predecessor %s", id)
		}
		state[id] = 1
		for _, dep := range update.Predecessors {
			if prior, ok := known[dep]; ok && rank[prior.Kind] > rank[update.Kind] {
				return fmt.Errorf("invalid predecessor kind for %s", id)
			}
			if err := visit(dep); err != nil {
				return err
			}
		}
		state[id] = 2
		result = append(result, update)
		return nil
	}
	for _, id := range keys {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func Applies(update UpdatePlan, edition string) bool {
	if update.Target != "" && update.Target != metadata.RoleOS {
		return false
	}
	if len(update.Editions) == 0 {
		return true
	}
	for _, candidate := range update.Editions {
		if strings.EqualFold(candidate, edition) {
			return true
		}
	}
	return false
}
