package tui

import (
	"context"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
)

type buildsState struct {
	query          string
	search, filter textinput.Model
	archFilter     model.Architecture
	generation     uint64
	pending        bool
	status         requestStatus
	cancel         context.CancelFunc
	records        []catalog.Build
	cursor         int
}

func newBuildsState() buildsState {
	newInput := func(placeholder string, limit int) textinput.Model {
		input := textinput.New()
		input.Prompt = ""
		input.Placeholder = placeholder
		input.CharLimit = limit
		input.SetWidth(60)
		input.SetVirtualCursor(true)
		input.SetStyles(textinput.Styles{Focused: textinput.StyleState{Text: lipgloss.NewStyle()}, Blurred: textinput.StyleState{Text: lipgloss.NewStyle()}})
		return input
	}
	return buildsState{search: newInput("upstream query", 512), filter: newInput("local text", 256)}
}
func (s buildsState) visible() []catalog.Build {
	rows := make([]catalog.Build, 0, len(s.records))
	filter := strings.ToLower(s.filter.Value())
	for _, b := range s.records {
		if s.archFilter != "" && s.archFilter != b.Architecture {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToLower(b.Title+" "+b.Build+" "+string(b.Architecture)+" "+b.UpdateID), filter) {
			continue
		}
		rows = append(rows, b)
	}
	return rows
}

// Architectures retains all retrieved targets, including unknown values, and
// uses neither host architecture nor inferred release siblings.
func (m Model) Architectures() []model.Architecture {
	var out []model.Architecture
	for _, b := range m.builds.records {
		if !slices.Contains(out, b.Architecture) {
			out = append(out, b.Architecture)
		}
	}
	if m.cfg.Image.UpdateID != "" && !slices.Contains(out, m.cfg.Image.Architecture) {
		out = append(out, m.cfg.Image.Architecture)
	}
	slices.Sort(out)
	return out
}
func (m Model) changeQuery(query string) (tea.Model, tea.Cmd) {
	query = boundedText(query, 512)
	if query == m.builds.query {
		return m, nil
	}
	if m.builds.cancel != nil {
		m.builds.cancel()
	}
	m.builds.generation++
	m.builds.query = query
	m.builds.search.SetValue(query)
	m.builds.records = nil
	m.builds.cursor = 0
	m.builds.pending = true
	m.builds.status = requestStatus{}
	generation := m.builds.generation
	return m, tea.Tick(searchDebounce, func(time.Time) tea.Msg { return searchDebouncedMsg{generation: generation, query: query} })
}
func (m *Model) acceptSearch(msg searchResultMsg) {
	if msg.generation != m.builds.generation || msg.query != m.builds.query {
		return
	}
	m.builds.status = resultStatus(msg.err, msg.checkedAt)
	if !usable(msg.err) {
		return
	}
	m.builds.records = slices.Clone(msg.builds)
	m.builds.cursor = min(m.builds.cursor, max(0, len(m.builds.visible())-1))
	for _, b := range m.builds.records {
		if b.UpdateID == m.cfg.Image.UpdateID && b.Architecture == m.cfg.Image.Architecture {
			copy := b
			m.source = &copy
			break
		}
	}
	m.syncArchitectureCursor()
}
func (m *Model) selectBuild(id string) tea.Cmd {
	for _, b := range m.builds.records {
		if b.UpdateID != id {
			continue
		}
		m.navigate(Image)
		if m.cfg.Image.UpdateID == b.UpdateID && m.cfg.Image.Architecture == b.Architecture {
			return nil
		}
		m.invalidateSource()
		copy := b
		m.source = &copy
		m.cfg.Image = model.Selection{UpdateID: b.UpdateID, Architecture: b.Architecture}
		m.revision++
		m.notice = "Source changed: language and editions cleared; app applicability must be checked again."
		m.syncArchitectureCursor()
		return m.beginLanguages(false)
	}
	return nil
}
func (m *Model) changeArchitecture(arch model.Architecture) {
	if arch == m.cfg.Image.Architecture || !slices.Contains(m.Architectures(), arch) {
		return
	}
	m.invalidateSource()
	m.cfg.Image = model.Selection{Architecture: arch}
	m.source = nil
	m.revision++
	m.notice = "Architecture changed: select an exact source record. Language, editions and app applicability invalidated."
	m.builds.archFilter = arch
	m.builds.cursor = 0
	m.navigate(Builds)
}
func (m *Model) syncArchitectureCursor() {
	m.image.archCursor = max(0, slices.Index(m.Architectures(), m.cfg.Image.Architecture))
}
