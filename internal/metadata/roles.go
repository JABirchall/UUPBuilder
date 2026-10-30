package metadata

import (
	"fmt"
	"strings"
	"uupbuilder/internal/model"
)

type Role string

const (
	RoleSetup Role = "setup"
	RoleOS    Role = "os"
	RoleWinRE Role = "winre"
)

type RoleEvidence struct {
	Role       Role
	Resource   ResourceReference
	ImageIndex int
	Evidence   Evidence
}
type AbsenceEvidence struct {
	Role     Role
	Reason   string
	Evidence Evidence
}
type EditionBase struct {
	Edition, Base string
	Evidence      Evidence
}

func validRole(role Role) bool { return role == RoleSetup || role == RoleOS || role == RoleWinRE }
func (inv *Inventory) validateEvidence(e Evidence) error {
	if e.Source != inv.Source || strings.TrimSpace(e.Selector) == "" {
		return ErrInvalidEvidence
	}
	for _, doc := range inv.Documents {
		if doc.Reference == e.Document {
			return nil
		}
	}
	return ErrInvalidEvidence
}
func validReference(ref ResourceReference, known map[model.PayloadIdentity]bool) bool {
	return known[ref.Payload] && validMember(ref.Member)
}
func (inv *Inventory) applyEvidence(result ProviderResult, known map[model.PayloadIdentity]bool) error {
	for _, rule := range result.AppSelections {
		if rule.ID == "" || rule.Family.Name == "" || rule.Family.Publisher == "" || inv.validateEvidence(rule.Evidence) != nil {
			return ErrInvalidEvidence
		}
		found := false
		for _, app := range inv.Apps.Packages {
			found = found || app.Family == rule.Family
		}
		if !found {
			return ErrInvalidEvidence
		}
		for _, old := range inv.Apps.SelectionRules {
			if old.ID == rule.ID {
				return ErrConflictingMetadata
			}
		}
		inv.Apps.SelectionRules = append(inv.Apps.SelectionRules, rule)
	}
	if err := inv.applyUpdates(result.Updates, known); err != nil {
		return err
	}
	for _, binding := range result.PayloadBindings {
		if err := inv.bindPayload(binding, known); err != nil {
			return err
		}
	}
	for _, role := range result.Roles {
		if !validRole(role.Role) || !validReference(role.Resource, known) || role.ImageIndex < 0 || inv.validateEvidence(role.Evidence) != nil {
			return ErrInvalidEvidence
		}
		if role.ImageIndex > 0 {
			found := false
			for _, image := range inv.Images {
				if image.Resource == role.Resource && image.Index == role.ImageIndex {
					if err := inv.architecture(image.Architecture); err != nil {
						return err
					}
					if image.Architecture == "" {
						inv.gap("image-architecture-unresolved", string(role.Role)+" image has no architecture", &image.Evidence.Document)
					}
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%w: role image is not inspected", ErrInvalidEvidence)
			}
		}
		duplicate := false
		for _, old := range inv.Roles {
			if old.Resource == role.Resource && old.ImageIndex == role.ImageIndex {
				if old.Role != role.Role {
					return ErrConflictingMetadata
				}
				duplicate = true
			}
		}
		if !duplicate {
			inv.Roles = append(inv.Roles, role)
		}
	}
	for _, absence := range result.Absences {
		if !validRole(absence.Role) || strings.TrimSpace(absence.Reason) == "" || inv.validateEvidence(absence.Evidence) != nil {
			return ErrInvalidEvidence
		}
		inv.Absences = append(inv.Absences, absence)
	}
	for _, layout := range result.Layouts {
		if (layout.Kind != LayoutUpdateOnly && layout.Kind != LayoutFullMedia) || strings.TrimSpace(layout.Family) == "" || inv.validateEvidence(layout.Evidence) != nil {
			return ErrInvalidEvidence
		}
		for _, old := range inv.Layouts {
			if old.Kind != layout.Kind || old.Family != layout.Family {
				return ErrConflictingMetadata
			}
		}
		inv.Layouts = append(inv.Layouts, layout)
	}
	for _, base := range result.EditionBases {
		if strings.TrimSpace(base.Edition) == "" || strings.TrimSpace(base.Base) == "" || base.Edition == base.Base || inv.validateEvidence(base.Evidence) != nil {
			return ErrInvalidEvidence
		}
		for _, old := range inv.EditionBases {
			if old.Edition == base.Edition && old.Base != base.Base {
				return ErrConflictingMetadata
			}
		}
		inv.EditionBases = append(inv.EditionBases, base)
	}
	for _, license := range result.Licenses {
		if !validReference(license.Resource, known) || inv.validateEvidence(license.Evidence) != nil {
			return ErrInvalidEvidence
		}
		found := false
		for i := range inv.Apps.Packages {
			if inv.Apps.Packages[i].Family == license.Family {
				found = true
				inv.Apps.Packages[i].Licenses = append(inv.Apps.Packages[i].Licenses, license)
			}
		}
		if !found {
			return fmt.Errorf("%w: unknown license family", ErrInvalidEvidence)
		}
	}
	for _, phase := range result.AppPhases {
		if (phase.Phase != PhaseOfflineProvisioning && phase.Phase != PhasePostAssembly) || inv.validateEvidence(phase.Evidence) != nil {
			return ErrInvalidEvidence
		}
		found := false
		for i := range inv.Apps.Packages {
			app := &inv.Apps.Packages[i]
			if app.Family == phase.Family {
				found = true
				if app.Phase != PhaseUnknown && app.Phase != phase.Phase {
					return ErrConflictingMetadata
				}
				app.Phase = phase.Phase
				evidence := phase.Evidence
				app.PhaseEvidence = &evidence
			}
		}
		if !found {
			return fmt.Errorf("%w: unknown phase family", ErrInvalidEvidence)
		}
	}
	return nil
}
