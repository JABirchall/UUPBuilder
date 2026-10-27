package tui

import (
	"context"
	"slices"

	tea "charm.land/bubbletea/v2"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
)

type imageState struct {
	focus                                     int // target, language, editions
	archCursor, languageCursor, editionCursor int
	sourceGeneration, editionGeneration       uint64
	languageCancel, editionCancel             context.CancelFunc
	languageStatus, editionStatus             requestStatus
	languages                                 []catalog.Language
	editions                                  []catalog.Edition
	languageChecked, editionsChecked          bool
}

func (m *Model) invalidateSource() {
	if m.image.languageCancel != nil {
		m.image.languageCancel()
	}
	m.image.sourceGeneration++
	m.image.languages = nil
	m.image.languageStatus = requestStatus{}
	m.image.languageChecked = false
	m.image.languageCursor = 0
	m.invalidateEditions()
}
func (m *Model) invalidateEditions() {
	m.appsUnchecked = true
	if m.image.editionCancel != nil {
		m.image.editionCancel()
	}
	m.image.editionGeneration++
	m.image.editions = nil
	m.image.editionStatus = requestStatus{}
	m.image.editionsChecked = false
	m.image.editionCursor = 0
	m.cfg.Image.Editions = nil
}
func (m *Model) acceptLanguages(msg languagesResultMsg) tea.Cmd {
	if msg.generation != m.image.sourceGeneration || msg.updateID != m.cfg.Image.UpdateID {
		return nil
	}
	m.image.languageStatus = resultStatus(msg.err, msg.checkedAt)
	if !usable(msg.err) {
		return nil
	}
	m.image.languages = slices.Clone(msg.languages)
	m.image.languageCursor = min(m.image.languageCursor, max(0, len(msg.languages)-1))
	m.image.languageChecked = false
	if m.cfg.Image.Language == "" {
		return nil
	}
	for i, language := range msg.languages {
		if language.ID == m.cfg.Image.Language {
			m.image.languageChecked = true
			m.image.languageCursor = i
			return m.beginEditions(false)
		}
	}
	m.cfg.Image.Language = ""
	m.invalidateEditions()
	m.revision++
	m.notice = "Requested language is unavailable for this exact source; language, editions and app applicability invalidated."
	return nil
}
func (m *Model) selectLanguage(language string) tea.Cmd {
	if m.cfg.Image.UpdateID == "" || m.image.languageStatus.loading {
		return nil
	}
	for i, choice := range m.image.languages {
		if choice.ID != language {
			continue
		}
		if m.cfg.Image.Language == language && m.image.languageChecked {
			return nil
		}
		m.invalidateEditions()
		m.cfg.Image.Language = language
		m.image.languageChecked = true
		m.image.languageCursor = i
		m.revision++
		m.notice = "Language changed: editions cleared; app applicability must be checked again."
		return m.beginEditions(false)
	}
	return nil
}
func (m *Model) acceptEditions(msg editionsResultMsg) {
	if msg.generation != m.image.editionGeneration || msg.updateID != m.cfg.Image.UpdateID || msg.language != m.cfg.Image.Language {
		return
	}
	m.image.editionStatus = resultStatus(msg.err, msg.checkedAt)
	if !usable(msg.err) {
		return
	}
	m.image.editions = slices.Clone(msg.editions)
	m.image.editionsChecked = true
	m.image.editionCursor = min(m.image.editionCursor, max(0, len(m.editionChoices())-1))
	for _, id := range m.cfg.Image.Editions {
		if !m.image.hasEdition(id) {
			m.notice = "A requested edition is unavailable. Remove its marked selection or choose another source; app applicability is unchecked."
			break
		}
	}
}
func (s imageState) hasEdition(id string) bool {
	return slices.ContainsFunc(s.editions, func(e catalog.Edition) bool { return e.ID == id })
}
func (s imageState) ready(selection model.Selection) bool {
	if !s.languageChecked || !s.editionsChecked || s.languageStatus.loading || s.editionStatus.loading || !usable(s.languageStatus.err) || !usable(s.editionStatus.err) || selection.Validate() != nil {
		return false
	}
	for _, id := range selection.Editions {
		if !s.hasEdition(id) {
			return false
		}
	}
	return true
}
func (m Model) editionChoices() []catalog.Edition {
	choices := slices.Clone(m.image.editions)
	for _, id := range m.cfg.Image.Editions {
		if !m.image.hasEdition(id) {
			choices = append(choices, catalog.Edition{ID: id, Name: "Unavailable request"})
		}
	}
	return choices
}
func (m *Model) toggleEdition(id string) {
	if !m.image.languageChecked || m.image.editionStatus.loading {
		return
	}
	index := slices.Index(m.cfg.Image.Editions, id)
	if index >= 0 {
		m.cfg.Image.Editions = slices.Delete(m.cfg.Image.Editions, index, index+1)
	} else {
		if !m.image.hasEdition(id) {
			return
		}
		m.cfg.Image.Editions = append(m.cfg.Image.Editions, id)
	}
	m.revision++
	m.notice = "Edition selection changed; app applicability must be checked again."
}
