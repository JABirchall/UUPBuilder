package planner

import (
	"fmt"
	"strings"
	"uupbuilder/internal/engine/rules"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

type FeatureOperation struct {
	Name    string
	Enable  bool
	Sources []metadata.ResourceReference
}
type DriverOperation struct {
	Target model.DriverTarget
	Source string
}
type CustomizationPlan struct {
	Source          model.SourceIdentity
	Manifest        model.PayloadManifest
	InventoryDigest string
	Generation      rules.Generation
	Apps            AppPlan
	Features        []FeatureOperation
	Drivers         []DriverOperation
	Editions        []string
	Digest          string
}

func PlanFeatures(inv metadata.Inventory, s model.ConversionSettings) ([]FeatureOperation, error) {
	if !s.NetFX3 {
		return nil, nil
	}
	if _, e := rules.Select(inv); e != nil {
		return nil, e
	}
	op := FeatureOperation{Name: "NetFx3", Enable: true}
	for _, p := range inv.Packages {
		if strings.EqualFold(p.Identity.Name, "Microsoft-Windows-NetFx3-OnDemand-Package") && (p.Identity.Architecture == "neutral" || p.Identity.Architecture == inv.Source.Architecture) && appEvidence(inv, p.Evidence) {
			op.Sources = append(op.Sources, p.Evidence.Document.Resource)
		}
	}
	if len(op.Sources) == 0 {
		return nil, fmt.Errorf("NetFx3 source-specific OnDemand package inventory unavailable")
	}
	return []FeatureOperation{op}, nil
}
func PlanDrivers(inv metadata.Inventory, s model.DriverSettings) ([]DriverOperation, error) {
	operations, err := driverOperations(s)
	if err != nil {
		return nil, err
	}
	if len(operations) > 0 {
		if _, err = rules.Select(inv); err != nil {
			return nil, err
		}
	}
	return operations, nil
}

func driverOperations(s model.DriverSettings) ([]DriverOperation, error) {
	for _, t := range s.Targets {
		if t == model.DriverWinRE {
			return nil, fmt.Errorf("WinRE driver target is excluded")
		}
	}
	if !s.Enabled {
		return nil, nil
	}
	if s.Source == "" {
		return nil, fmt.Errorf("driver source required")
	}
	osTarget, peTarget := false, false
	for _, t := range s.Targets {
		switch t {
		case model.DriverOS:
			osTarget = true
		case model.DriverWinPE:
			peTarget = true
		case model.DriverShared:
			osTarget = true
			peTarget = true
		default:
			return nil, fmt.Errorf("unknown driver target %q", t)
		}
	}
	var out []DriverOperation
	if osTarget {
		out = append(out, DriverOperation{model.DriverOS, s.Source})
	}
	if peTarget {
		out = append(out, DriverOperation{model.DriverWinPE, s.Source})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("driver targets required")
	}
	return out, nil
}
func BuildCustomizationPlan(inv metadata.Inventory, s model.ResolvedSettings, editions []string) (CustomizationPlan, error) {
	if err := ValidateRequestedSettings(s); err != nil {
		return CustomizationPlan{}, err
	}
	p := CustomizationPlan{Source: inv.Source, Manifest: inv.Manifest, InventoryDigest: hash(inv), Editions: append([]string(nil), editions...)}
	var e error
	if p.Generation, e = rules.Select(inv); e != nil {
		return p, e
	}
	if p.Apps, e = PlanApps(inv, s.Apps); e != nil {
		return p, e
	}
	if p.Features, e = PlanFeatures(inv, s.Conversion); e != nil {
		return p, e
	}
	if p.Drivers, e = PlanDrivers(inv, s.Conversion.Drivers); e != nil {
		return p, e
	}
	p.Digest = p.digest()
	return copyOf(p), p.Validate()
}
func (p CustomizationPlan) digest() string { p.Digest = ""; return hash(p) }
func (p CustomizationPlan) Validate() error {
	if p.Digest != p.digest() {
		return ErrIdentityChanged
	}
	if p.Source.Validate() != nil || p.Manifest.Validate() != nil || p.Manifest.Source != p.Source || p.Apps.Source != p.Source || p.Apps.ManifestDigest != p.Manifest.Digest || len(p.Editions) == 0 || p.Generation.Validate() != nil {
		return ErrInvalidPlan
	}
	if p.Apps.InventoryDigest != p.InventoryDigest || hash(p.Apps.Requested) != hash(p.Apps.Effective) || p.Apps.Deferred && (len(p.Apps.Provision) > 0 || len(p.Apps.Remove) > 0) {
		return ErrInvalidPlan
	}
	if len(p.Features) > 1 {
		return ErrInvalidPlan
	}
	for _, f := range p.Features {
		if f.Name != "NetFx3" || !f.Enable || len(f.Sources) == 0 {
			return ErrInvalidPlan
		}
		for _, ref := range f.Sources {
			found := false
			for _, payload := range p.Manifest.Payloads {
				found = found || payload.Identity == ref.Payload
			}
			if !found {
				return ErrInvalidPlan
			}
		}
	}
	seen := map[model.DriverTarget]bool{}
	for _, d := range p.Drivers {
		if (d.Target != model.DriverOS && d.Target != model.DriverWinPE) || d.Source == "" || seen[d.Target] {
			return ErrInvalidPlan
		}
		seen[d.Target] = true
	}
	return nil
}
func (p CustomizationPlan) MatchesSettings(s model.ResolvedSettings) bool {
	if hash(p.Apps.Requested) != hash(s.Apps) {
		return false
	}
	if s.Conversion.NetFX3 != (len(p.Features) == 1 && p.Features[0].Name == "NetFx3" && p.Features[0].Enable) {
		return false
	}
	drivers, e := driverOperations(s.Conversion.Drivers)
	return e == nil && hash(drivers) == hash(p.Drivers)
}
func (p CustomizationPlan) OutputPaths() []string {
	paths := []string{"result.json", "customized.wim"}
	for i := range p.Editions {
		paths = append(paths, fmt.Sprintf("customize-os-%03d.wim", i+1))
	}
	for _, d := range p.Drivers {
		if d.Target == model.DriverWinPE {
			paths = append(paths, "customized-boot.wim", "customize-pe-001.wim", "customize-pe-002.wim")
			break
		}
	}
	return paths
}
