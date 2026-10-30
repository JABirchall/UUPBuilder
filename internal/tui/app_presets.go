package tui

import (
	"slices"
	"strings"

	"uupbuilder/internal/model"
	"uupbuilder/internal/source"
)

const allOfferedPreset = "all-offered"

// Examined offers are tied to the exact current source observation. They are
// requests only: this gate does not validate installable app applicability.
func (m Model) appOffersExamined() bool {
	return m.imageReady() && !m.apps.status.loading && m.apps.status.err == nil &&
		!m.apps.status.checkedAt.IsZero() && m.apps.endpoint == m.cfg.Catalog.Endpoint &&
		m.apps.snapshot.State == source.AppCatalogAvailable &&
		sameAppSelection(m.apps.selection, m.cfg.Image) && sameAppSelection(m.apps.snapshot.Selection, m.cfg.Image)
}

func offeredToSelectedEdition(entry source.AppCatalogEntry, selected []string) bool {
	if entry.FeatureID == "" || (entry.Type != "MSIX" && entry.Type != "MSIXBundle") {
		return false
	}
	for _, ref := range entry.Editions {
		for _, edition := range selected {
			if strings.EqualFold(ref.Edition, edition) {
				return true
			}
		}
	}
	return false
}

func (m *Model) applyAppPreset(id string) {
	if id != allOfferedPreset || !m.appOffersExamined() {
		return
	}
	var include []string
	for _, entry := range m.apps.snapshot.Entries {
		if offeredToSelectedEdition(entry, m.cfg.Image.Editions) {
			include = append(include, entry.FeatureID)
		}
	}
	slices.Sort(include)
	include = slices.Compact(include)
	if m.cfg.Apps.Mode == model.AppsCustom && m.cfg.Apps.Preset == id && slices.Equal(m.cfg.Apps.Include, include) {
		return
	}
	m.cfg.Apps.Mode = model.AppsCustom
	m.cfg.Apps.Preset = id
	m.cfg.Apps.Include = include
	m.appEdited()
}

// Select-all acts on visible offered families. Hidden and unresolved requests
// survive; a second activation deselects those same offered families.
func (m *Model) toggleAllVisibleApps() {
	if !m.appOffersExamined() {
		return
	}
	var ids []string
	allSelected := m.cfg.Apps.Mode == model.AppsCustom
	for _, choice := range m.appChoices() {
		if choice.entry != nil {
			ids = append(ids, choice.featureID)
			allSelected = allSelected && slices.Contains(m.cfg.Apps.Include, choice.featureID)
		}
	}
	if len(ids) == 0 {
		return
	}
	include := slices.Clone(m.cfg.Apps.Include)
	if allSelected {
		include = slices.DeleteFunc(include, func(id string) bool { return slices.Contains(ids, id) })
	} else {
		for _, id := range ids {
			if !slices.Contains(include, id) {
				include = append(include, id)
			}
		}
	}
	m.cfg.Apps.Mode = model.AppsCustom
	m.cfg.Apps.Preset = ""
	m.cfg.Apps.Include = include
	m.apps.focus = 2
	m.apps.cursor = min(m.apps.cursor, max(0, len(m.appChoices())-1))
	m.appEdited()
}
