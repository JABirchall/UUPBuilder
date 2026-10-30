package planner

import (
	"fmt"
	"strconv"
	"strings"
	"uupbuilder/internal/engine/rules"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

type AppProvision struct {
	Package      metadata.AppPackage
	Bundle       *metadata.AppBundle
	External     []AppExternalFile
	Dependencies []metadata.ResourceReference
	Resources    []metadata.ResourceReference
	License      *metadata.ResourceReference
	LicenseXML   []byte
	SkipLicense  bool
	Stub         model.AppStubPolicy
}

type AppExternalFile struct {
	Name     string
	Resource metadata.ResourceReference
}

func (p AppProvision) Source() metadata.ResourceReference {
	if p.Bundle != nil {
		return p.Bundle.Evidence.Document.Resource
	}
	return p.Package.Evidence.Document.Resource
}
func (p AppProvision) ObservedIdentity() metadata.AppIdentity {
	if p.Bundle != nil {
		return p.Bundle.Identity
	}
	return p.Package.Identity
}

type AppPlan struct {
	Source                          model.SourceIdentity
	ManifestDigest, InventoryDigest string
	Requested, Effective            model.AppSettings
	EffectiveIDs                    []string
	Deferred                        bool
	Provision                       []AppProvision
	Remove                          []metadata.AppIdentity
}

func appEvidence(inv metadata.Inventory, e metadata.Evidence) bool {
	if e.Source != inv.Source || e.Selector == "" {
		return false
	}
	for _, d := range inv.Documents {
		if d.Reference == e.Document {
			return true
		}
	}
	return false
}
func appArch(a model.Architecture) model.Architecture {
	if a == "x64" {
		return "amd64"
	}
	return a
}
func versionCompare(a, b string) (int, error) {
	left, right := strings.Split(a, "."), strings.Split(b, ".")
	if len(left) != 4 || len(right) != 4 {
		return 0, fmt.Errorf("invalid app version")
	}
	cmp := 0
	for i := range left {
		x, e := strconv.ParseUint(left[i], 10, 16)
		if e != nil {
			return 0, e
		}
		y, e := strconv.ParseUint(right[i], 10, 16)
		if e != nil {
			return 0, e
		}
		if cmp == 0 && x != y {
			if x > y {
				cmp = 1
			} else {
				cmp = -1
			}
		}
	}
	return cmp, nil
}

// PlanApps keeps request IDs verbatim. Rules bind those IDs to actual manifest
// families; absent legacy manifests remain deferred for the graph's barrier.
func PlanApps(inv metadata.Inventory, settings model.AppSettings) (AppPlan, error) {
	p := AppPlan{Source: inv.Source, ManifestDigest: inv.Manifest.Digest, InventoryDigest: hash(inv), Requested: copyOf(settings), Effective: copyOf(settings)}
	fail := func(s string) (AppPlan, error) { return AppPlan{}, fmt.Errorf("app plan: %s", s) }
	if inv.Source.Validate() != nil || inv.Manifest.Validate() != nil || inv.Manifest.Source != inv.Source {
		return fail("source identity mismatch")
	}
	if err := rules.Edge(settings.Edge); err != nil {
		return AppPlan{}, err
	}
	if settings.Mode != model.AppsDefault && settings.Mode != model.AppsCustom && settings.Mode != model.AppsNone {
		return fail("invalid mode")
	}
	if settings.StubPolicy != model.AppStubAuto && settings.StubPolicy != model.AppStub && settings.StubPolicy != model.AppFull {
		return fail("invalid stub policy")
	}
	if len(inv.Apps.Packages) == 0 {
		p.Deferred = true
		return p, nil
	}
	for _, app := range inv.Apps.Packages {
		if app.Phase == metadata.PhaseUnknown || app.Phase == metadata.PhasePostAssembly {
			p.Deferred = true
			return p, nil
		}
	}
	byID := map[string]metadata.AppSelectionRule{}
	byFamily := map[metadata.AppFamily]metadata.AppSelectionRule{}
	for _, r := range inv.Apps.SelectionRules {
		if !appEvidence(inv, r.Evidence) || r.ID == "" {
			return fail("unbound selection rule")
		}
		if _, ok := byID[r.ID]; ok {
			return fail("ambiguous request ID " + r.ID)
		}
		byID[r.ID] = r
		byFamily[r.Family] = r
	}
	if settings.Mode == model.AppsDefault {
		for _, id := range inv.Apps.DefaultIDs {
			if _, ok := byID[id]; !ok {
				return fail("default app manifest missing: " + id)
			}
		}
	}
	if len(byID) == 0 {
		return fail("source request-to-family rules unavailable")
	}
	selected := map[metadata.AppFamily]bool{}
	for _, r := range inv.Apps.SelectionRules {
		if r.Required || settings.Mode == model.AppsDefault && r.Default {
			selected[r.Family] = true
		}
	}
	for _, f := range inv.Apps.RequiredFamilies {
		selected[f] = true
	}
	if settings.Mode == model.AppsCustom {
		// Presets are request provenance, materialized into Include by the editor.
		if settings.Preset != "" && len(settings.Include) == 0 {
			return fail("preset has no materialized requested IDs")
		}
		for _, id := range settings.Include {
			r, ok := byID[id]
			if !ok {
				return fail("requested ID not in source: " + id)
			}
			selected[r.Family] = true
		}
	}
	choose := func(f metadata.AppFamily, arch model.Architecture) (metadata.AppPackage, error) {
		var best metadata.AppPackage
		count := 0
		for _, a := range inv.Apps.Packages {
			if a.Family != f || a.ResourcePackage || (appArch(a.Identity.Architecture) != "neutral" && appArch(a.Identity.Architecture) != appArch(arch)) {
				continue
			}
			cmp, e := versionCompare(a.Identity.Version, "0.0.0.0")
			if e != nil || cmp < 0 {
				return best, fmt.Errorf("invalid version")
			}
			if count == 0 {
				best = a
				count = 1
				continue
			}
			cmp, _ = versionCompare(a.Identity.Version, best.Identity.Version)
			if cmp == 0 {
				return best, fmt.Errorf("ambiguous package family %s", f.Name)
			}
			if cmp > 0 {
				best = a
			}
		}
		if count == 0 {
			return best, fmt.Errorf("missing compatible package %s", f.Name)
		}
		return best, nil
	}
	states := map[metadata.AppFamily]int{}
	var visit func(metadata.AppFamily, model.Architecture) error
	visit = func(f metadata.AppFamily, arch model.Architecture) error {
		if states[f] == 2 {
			return nil
		}
		if states[f] == 1 {
			return fmt.Errorf("app dependency cycle at %s", f.Name)
		}
		states[f] = 1
		app, e := choose(f, arch)
		if e != nil {
			return e
		}
		if !appEvidence(inv, app.Evidence) {
			return fmt.Errorf("unbound app manifest %s", f.Name)
		}
		op := AppProvision{Package: app, Stub: model.AppStubAuto}
		for _, bundle := range inv.Apps.Bundles {
			if bundle.Identity.Name != f.Name || bundle.Identity.Publisher != f.Publisher {
				continue
			}
			matches := false
			for _, child := range bundle.Packages {
				if child.Type == "application" && child.Version == app.Identity.Version && appArch(child.Architecture) == appArch(app.Identity.Architecture) {
					matches = true
				}
			}
			if !matches {
				continue
			}
			if op.Bundle != nil {
				return fmt.Errorf("ambiguous app bundle %s", f.Name)
			}
			if !appEvidence(inv, bundle.Evidence) {
				return fmt.Errorf("unbound bundle manifest")
			}
			owned := bundle
			op.Bundle = &owned
			for _, child := range bundle.Packages {
				var ref metadata.ResourceReference
				found := false
				for _, payload := range inv.Manifest.Payloads {
					if payload.Destination == child.FileName {
						if found {
							return fmt.Errorf("ambiguous external bundle file %s", child.FileName)
						}
						ref = metadata.ResourceReference{Payload: payload.Identity}
						found = true
					}
				}
				if !found {
					return fmt.Errorf("missing declared external bundle file %s", child.FileName)
				}
				op.External = append(op.External, AppExternalFile{Name: child.FileName, Resource: ref})
			}
		}
		rule, ok := byFamily[f]
		if !ok {
			return fmt.Errorf("missing license/selection rule for %s", f.Name)
		}
		if !app.Framework {
			op.Stub = settings.StubPolicy
			// This is a native preference, retained verbatim. Only native image
			// acceptance can establish which requested apps actually have stubs.
		}
		for _, dep := range app.Dependencies {
			if dep.Optional {
				continue
			}
			dependency, e := choose(dep.Family, app.Identity.Architecture)
			if e != nil {
				return e
			}
			cmp, e := versionCompare(dependency.Identity.Version, dep.MinVersion)
			if e != nil || cmp < 0 || !dependency.Framework {
				return fmt.Errorf("unsatisfied framework dependency %s", dep.Family.Name)
			}
			if e = visit(dep.Family, app.Identity.Architecture); e != nil {
				return e
			}
			for _, planned := range p.Provision {
				if planned.Package.Family == dependency.Family {
					op.Dependencies = append(op.Dependencies, planned.Source())
				}
			}
		}
		op.SkipLicense = rule.LicenseFree
		if !op.SkipLicense {
			for _, link := range app.Licenses {
				if link.Family != f || !appEvidence(inv, link.Evidence) {
					continue
				}
				for _, license := range inv.Apps.LicenseDocuments {
					if license.Resource == link.Resource && strings.EqualFold(license.PackageFamilyName, metadata.AppFamilyName(f)) && strings.EqualFold(license.Usage, "Offline") && strings.EqualFold(license.BindingType, "Machine") {
						ref := link.Resource
						op.License = &ref
						op.LicenseXML = append([]byte(nil), license.Original...)
						for _, doc := range inv.Documents {
							if doc.Reference.Resource == ref && doc.Format == metadata.FormatStoreLicenseXML {
								op.LicenseXML = append([]byte(nil), doc.Original...)
							}
						}
					}
				}
			}
			if op.License == nil {
				return fmt.Errorf("missing linked offline machine license for %s", f.Name)
			}
		}
		for _, resource := range inv.Apps.Packages {
			if op.Bundle == nil && resource.Family == f && resource.ResourcePackage && (appArch(resource.Identity.Architecture) == "neutral" || appArch(resource.Identity.Architecture) == appArch(inv.Source.Architecture)) {
				for _, lang := range resource.Languages {
					if strings.EqualFold(lang, inv.Source.Language) || strings.EqualFold(lang, strings.Split(inv.Source.Language, "-")[0]) {
						if !appEvidence(inv, resource.Evidence) {
							return fmt.Errorf("unbound resource manifest")
						}
						op.Resources = append(op.Resources, resource.Evidence.Document.Resource)
						break
					}
				}
			}
		}
		p.Provision = append(p.Provision, op)
		states[f] = 2
		return nil
	}
	// Source order is deterministic; dependency traversal orders frameworks first.
	for _, r := range inv.Apps.SelectionRules {
		if selected[r.Family] {
			p.EffectiveIDs = append(p.EffectiveIDs, r.ID)
			if e := visit(r.Family, inv.Source.Architecture); e != nil {
				return AppPlan{}, e
			}
		}
	}
	for f := range selected {
		if states[f] != 2 {
			return fail("requested family has no rule: " + f.Name)
		}
	}
	removeFamilies := map[metadata.AppFamily]bool{}
	for _, a := range inv.Apps.Packages {
		if !a.Framework && !a.ResourcePackage && states[a.Family] != 2 && !removeFamilies[a.Family] {
			p.Remove = append(p.Remove, a.Identity)
			removeFamilies[a.Family] = true
		}
	}
	return copyOf(p), nil
}
