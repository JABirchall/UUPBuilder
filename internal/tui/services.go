package tui

import (
	"context"
	"errors"
	"time"

	tea "charm.land/bubbletea/v2"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
	"uupbuilder/internal/source"
)

// Catalog uses public discovery values. Planner/controller ports belong to
// their future producers and are deliberately not guessed here.
type Catalog interface {
	Search(context.Context, string) ([]catalog.Build, error)
	Languages(context.Context, string) ([]catalog.Language, error)
	Editions(context.Context, string, string) ([]catalog.Edition, error)
}
type Dependencies struct {
	Catalog           Catalog
	AppCatalog        source.AppCatalog
	AppCatalogFactory func(endpoint string) source.AppCatalog
	// CatalogFactory recomposes the existing discovery port after a loaded
	// endpoint change. A fixed injected Catalog can omit it and reject changes.
	CatalogFactory func(endpoint string) Catalog
	ConfigPath     string
	Context        context.Context
	Host           model.Host // Informational only; never restricts targets.
	Builder        BuildService
}

var _ Catalog = (*catalog.Client)(nil)

const discoveryTimeout = 45 * time.Second
const searchDebounce = 300 * time.Millisecond

type requestStatus struct {
	loading   bool
	err       error
	checkedAt time.Time
	staleAt   time.Time
}

func resultStatus(err error, checked time.Time) requestStatus {
	s := requestStatus{err: err, checkedAt: checked}
	var stale *catalog.StaleError
	if errors.As(err, &stale) {
		s.staleAt = stale.FetchedAt
	}
	return s
}
func usable(err error) bool {
	var stale *catalog.StaleError
	return err == nil || errors.As(err, &stale)
}
func (m *Model) requestContext(force bool) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(m.ctx, discoveryTimeout)
	if force {
		ctx = catalog.WithRefresh(ctx)
	}
	return ctx, cancel
}
func (m *Model) beginSearch(force bool) tea.Cmd {
	if m.builds.cancel != nil {
		m.builds.cancel()
	}
	m.builds.generation++
	m.builds.pending = false
	m.builds.status.loading = true
	ctx, cancel := m.requestContext(force)
	m.builds.cancel = cancel
	generation, query, service := m.builds.generation, m.builds.query, m.deps.Catalog
	return func() tea.Msg {
		defer cancel()
		rows, err := service.Search(ctx, query)
		return searchResultMsg{generation: generation, query: query, builds: rows, err: err, checkedAt: time.Now()}
	}
}
func (m *Model) beginLanguages(force bool) tea.Cmd {
	m.image.languageOpen = false
	if m.image.languageCancel != nil {
		m.image.languageCancel()
	}
	m.image.sourceGeneration++
	m.image.languageStatus.loading = true
	ctx, cancel := m.requestContext(force)
	m.image.languageCancel = cancel
	generation, id, service := m.image.sourceGeneration, m.cfg.Image.UpdateID, m.deps.Catalog
	return func() tea.Msg {
		defer cancel()
		rows, err := service.Languages(ctx, id)
		return languagesResultMsg{generation: generation, updateID: id, languages: rows, err: err, checkedAt: time.Now()}
	}
}
func (m *Model) beginEditions(force bool) tea.Cmd {
	if m.image.editionCancel != nil {
		m.image.editionCancel()
	}
	m.image.editionGeneration++
	m.image.editionStatus.loading = true
	ctx, cancel := m.requestContext(force)
	m.image.editionCancel = cancel
	generation, id, language, service := m.image.editionGeneration, m.cfg.Image.UpdateID, m.cfg.Image.Language, m.deps.Catalog
	return func() tea.Msg {
		defer cancel()
		rows, err := service.Editions(ctx, id, language)
		return editionsResultMsg{generation: generation, updateID: id, language: language, editions: rows, err: err, checkedAt: time.Now()}
	}
}
