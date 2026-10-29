package tui

import (
	"context"
	"fmt"
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
	for _, b := range s.records {
		if s.matches(b) {
			rows = append(rows, b)
		}
	}
	return rows
}

func (s buildsState) matches(b catalog.Build) bool {
	filter := strings.ToLower(s.filter.Value())
	return (s.archFilter == "" || s.archFilter == b.Architecture) &&
		(filter == "" || strings.Contains(strings.ToLower(b.Title+" "+b.Build+" "+string(b.Architecture)+" "+b.UpdateID), filter))
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
	previous := m.builds.visibleGroups()
	var focused *buildGroup
	if m.builds.cursor < len(previous) {
		focused = &previous[m.builds.cursor]
	}
	m.builds.records = slices.Clone(msg.builds)
	groups := m.builds.visibleGroups()
	m.builds.cursor = min(m.builds.cursor, max(0, len(groups)-1))
	for i, group := range groups {
		if (focused != nil && group.title == focused.title && group.build == focused.build) ||
			(focused == nil && group.contains(m.cfg.Image.UpdateID)) {
			m.builds.cursor = i
			break
		}
	}
	for _, b := range m.builds.records {
		if b.UpdateID != m.cfg.Image.UpdateID {
			continue
		}
		if b.Architecture != m.cfg.Image.Architecture {
			requested := m.cfg.Image.Architecture
			m.invalidateSource()
			m.cfg.Image = model.Selection{Architecture: requested}
			m.source = nil
			m.revision++
			m.notice = fmt.Sprintf("Target mismatch: source %s reports %s; requested %s. Select an exact source record again; dependent choices cleared.", b.UpdateID, b.Architecture, requested)
		} else {
			copy := b
			m.source = &copy
		}
		break
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
func (m *Model) changeArchitecture(arch model.Architecture) tea.Cmd {
	if arch == m.cfg.Image.Architecture || !slices.Contains(m.Architectures(), arch) {
		return nil
	}
	if group, ok := m.selectedGroup(); ok && slices.Contains(group.architectures(), arch) {
		return m.selectBuild(preferredBuild(group.records, arch, m.cfg.Image.UpdateID).UpdateID)
	}
	m.invalidateSource()
	m.cfg.Image = model.Selection{Architecture: arch}
	m.source = nil
	m.revision++
	m.notice = "Architecture changed: select an exact source record. Language, editions and app applicability invalidated."
	m.builds.archFilter = arch
	m.builds.cursor = 0
	m.navigate(Builds)
	return nil
}
func (m *Model) syncArchitectureCursor() {
	m.image.archCursor = max(0, slices.Index(m.imageArchitectures(), m.cfg.Image.Architecture))
}
