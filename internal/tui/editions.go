package tui

import (
	"slices"
	"strings"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
)

// These are selection offers. Build preparation independently verifies the
// selected source's EditionMappings.xml before planning native Set-Edition.
var additionalEditions = []struct {
	ID, Name, Base string
}{
	{"ProfessionalWorkstation", "Pro for Workstations", "Professional"},
	{"ProfessionalEducation", "Pro Education", "Professional"},
	{"Education", "Education", "Professional"},
	{"Enterprise", "Enterprise", "Professional"},
	{"ServerRdsh", "Enterprise multi-session", "Professional"},
	{"IoTEnterprise", "IoT Enterprise", "Professional"},
	{"IoTEnterpriseK", "IoT Enterprise K", "Professional"},
	{"ProfessionalWorkstationN", "Pro for Workstations N", "ProfessionalN"},
	{"ProfessionalEducationN", "Pro Education N", "ProfessionalN"},
	{"EducationN", "Education N", "ProfessionalN"},
	{"EnterpriseN", "Enterprise N", "ProfessionalN"},
}

func editionIndex(editions []string, id string) int {
	return slices.IndexFunc(editions, func(edition string) bool { return strings.EqualFold(edition, id) })
}

func requestedEditions(cfg config.Config) []string {
	return append(slices.Clone(cfg.Image.Editions), cfg.Conversion.Editions.Derived...)
}

func (m Model) availableEditions() []catalog.Edition {
	choices := slices.Clone(m.image.editions)
	for _, edition := range additionalEditions {
		if m.image.hasEdition(edition.ID) || !m.image.hasEdition(edition.Base) || editionIndex(m.cfg.Image.Editions, edition.Base) < 0 {
			continue
		}
		base := "Pro"
		if edition.Base == "ProfessionalN" {
			base = "Pro N"
		}
		choices = append(choices, catalog.Edition{ID: edition.ID, Name: edition.Name + " · from " + base})
	}
	return choices
}

func (m Model) editionAvailable(id string) bool {
	if editionIndex(m.cfg.Image.Editions, id) >= 0 && !m.image.hasEdition(id) {
		return false
	}
	if slices.ContainsFunc(m.availableEditions(), func(e catalog.Edition) bool { return strings.EqualFold(e.ID, id) }) {
		return true
	}
	if editionIndex(m.cfg.Conversion.Editions.Derived, id) < 0 {
		return false
	}
	for _, edition := range additionalEditions {
		if strings.EqualFold(edition.ID, id) {
			return false // A known offer requires its selected, advertised base.
		}
	}
	// Configured derivations beyond these offers retain the existing source
	// applicability path; selection suggestions are not a product allowlist.
	return true
}

func (m Model) editionSelected(id string) bool {
	return editionIndex(m.cfg.Image.Editions, id) >= 0 || editionIndex(m.cfg.Conversion.Editions.Derived, id) >= 0
}

func (m Model) imageReady() bool {
	if !m.image.ready(m.cfg.Image) {
		return false
	}
	for _, id := range m.cfg.Conversion.Editions.Derived {
		if !m.editionAvailable(id) {
			return false
		}
	}
	return true
}

func (m Model) editionChoices() []catalog.Edition {
	choices := m.availableEditions()
	for _, id := range requestedEditions(m.cfg) {
		if !slices.ContainsFunc(choices, func(e catalog.Edition) bool { return strings.EqualFold(e.ID, id) }) {
			name := "Unavailable request"
			if m.editionAvailable(id) {
				name = "Derived request · source check pending"
			}
			choices = append(choices, catalog.Edition{ID: id, Name: name})
		}
	}
	return choices
}

func (m *Model) toggleEdition(id string) {
	if !m.image.languageChecked || m.image.editionStatus.loading {
		return
	}
	if index := editionIndex(m.cfg.Image.Editions, id); index >= 0 {
		m.cfg.Image.Editions = slices.Delete(m.cfg.Image.Editions, index, index+1)
	} else if index := editionIndex(m.cfg.Conversion.Editions.Derived, id); index >= 0 {
		m.cfg.Conversion.Editions.Derived = slices.Delete(m.cfg.Conversion.Editions.Derived, index, index+1)
	} else {
		choices := m.availableEditions()
		index := slices.IndexFunc(choices, func(e catalog.Edition) bool { return strings.EqualFold(e.ID, id) })
		if index < 0 {
			return
		}
		id = choices[index].ID
		if m.image.hasEdition(id) {
			m.cfg.Image.Editions = append(m.cfg.Image.Editions, id)
		} else {
			m.cfg.Conversion.Editions.Derived = append(m.cfg.Conversion.Editions.Derived, id)
		}
	}
	// The Conversion editor applies its field values on Save and Build.
	_ = m.conversion.set("conversion.editions.derived", strings.Join(m.cfg.Conversion.Editions.Derived, ", "))
	m.image.editionCursor = min(m.image.editionCursor, max(0, len(m.editionChoices())-1))
	m.revision++
	m.notice = "Edition selection changed; app applicability must be checked again."
	m.invalidateApps()
}
