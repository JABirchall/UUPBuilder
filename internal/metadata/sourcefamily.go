package metadata

import "fmt"

type Classification string

// ClassificationSourceUnavailable describes standard installation-media
// capability only. It does not discard download identities or decide whether a
// later image-only operation is possible. No classification asserts buildability.

const (
	ClassificationMetadataIncomplete Classification = "metadata-incomplete"
	ClassificationImplementationGap  Classification = "implementation-gap"
	ClassificationSourceUnavailable  Classification = "source-unavailable"
	ClassificationUpdateOnly         Classification = "update-only"
	ClassificationSemanticInventory  Classification = "semantic-inventory"
)

type LayoutKind string

const (
	LayoutUpdateOnly LayoutKind = "update-only"
	LayoutFullMedia  LayoutKind = "full-media"
)

type LayoutEvidence struct {
	Kind     LayoutKind
	Family   string
	Evidence Evidence
}

func (inv *Inventory) finish() error {
	inv.compositionGaps()
	present := make(map[Role]bool)
	absent := make(map[Role]bool)
	for _, role := range inv.Roles {
		present[role.Role] = true
	}
	for _, absence := range inv.Absences {
		if present[absence.Role] {
			return fmt.Errorf("%w: present and absent role %q", ErrConflictingMetadata, absence.Role)
		}
		absent[absence.Role] = true
	}
	updateOnly := len(inv.Layouts) > 0 && inv.Layouts[0].Kind == LayoutUpdateOnly
	if updateOnly && (present[RoleOS] || present[RoleSetup]) {
		return fmt.Errorf("%w: update-only source has media image roles", ErrConflictingMetadata)
	}
	if !updateOnly {
		for _, role := range []Role{RoleSetup, RoleOS, RoleWinRE} {
			if !present[role] && !absent[role] {
				inv.gap("role-unresolved", string(role)+" requires semantic inspection or explicit upstream absence evidence", nil)
			}
		}
	}
	if len(inv.Layouts) == 0 {
		inv.gap("layout-unresolved", "no source-bound layout/family evidence", nil)
	}
	// Merely enumerating possible target editions is not a derivation rule.
	if len(inv.EditionBases) == 0 {
		inv.gap("edition-bases-unresolved", "no source-bound derived edition base rules inspected", nil)
	}
	if len(inv.Apps.Packages) == 0 {
		inv.gap("app-inventory-unresolved", "no app package metadata examined; absence of apps is not established", nil)
	} else {
		inv.gap("app-selection-rules-unresolved", "edition-specific app defaults/requirements are not established by package identities alone", nil)
	}
	for i := range inv.Apps.Packages {
		app := &inv.Apps.Packages[i]
		if app.Phase == PhaseUnknown {
			inv.gap("app-phase-unresolved", app.Family.Name, &app.Evidence.Document)
		}
		if len(app.Licenses) == 0 {
			inv.gap("app-license-unresolved", app.Family.Name+": license requirement/linkage is not established", &app.Evidence.Document)
		}
		for _, dependency := range app.Dependencies {
			resolved := false
			for _, candidate := range inv.Apps.Packages {
				if candidate.Framework && candidate.Family == dependency.Family && versionAtLeast(candidate.Identity.Version, dependency.MinVersion) && appArchitectureCompatible(inv.Source.Architecture, app.Identity.Architecture, candidate.Identity.Architecture) {
					resolved = true
					break
				}
			}
			if !resolved && !dependency.Optional {
				inv.gap("app-dependency-unresolved", app.Family.Name+" -> "+dependency.Family.Name, &app.Evidence.Document)
			}
		}
	}
	inv.Classification = ClassificationMetadataIncomplete
	for _, gap := range inv.Gaps {
		if gap.Code == "unsupported-schema" || gap.Code == "unsupported-format" {
			inv.Classification = ClassificationImplementationGap
			break
		}
	}
	if len(inv.Gaps) == 0 {
		inv.Classification = ClassificationSemanticInventory
	}
	if updateOnly {
		inv.Classification = ClassificationUpdateOnly
	}
	if absent[RoleSetup] || absent[RoleOS] {
		inv.Classification = ClassificationSourceUnavailable
	}
	return nil
}
