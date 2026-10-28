package tui

import (
	"fmt"
	"slices"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

type hit struct {
	x, y, width int
	msg         tea.Msg
}

func (h hit) contains(x, y int) bool { return y == h.y && x >= h.x && x < h.x+h.width }

type row struct {
	text string
	msg  tea.Msg
}

var accent = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#c5a2ff"))

const appsUncheckedNotice = "Apps: unchecked; requested policies retained."

// terminalText removes ANSI/OSC sequences, controls and invisible formatting
// from untrusted catalogue, error and configuration text before styling it.
func terminalText(value string) string {
	value = ansi.Strip(strings.ToValidUTF8(value, ""))
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, value)
}
func boundedText(value string, limit int) string {
	runes := []rune(terminalText(value))
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}
func fit(value string, width int) string {
	value = ansi.Truncate(value, max(0, width), "...")
	return value + strings.Repeat(" ", max(0, width-ansi.StringWidth(value)))
}
func wrapped(value string, width, maxLines int) []string {
	lines := strings.Split(ansi.Hardwrap(ansi.Wrap(value, max(1, width), ""), max(1, width), true), "\n")
	if len(lines) > maxLines {
		lines = lines[:maxLines]
		lines[len(lines)-1] = ansi.Truncate(lines[len(lines)-1], max(1, width-3), "") + "..."
	}
	return lines
}
func (m Model) contentWidth() int {
	if m.width >= 96 {
		return m.width - 20
	}
	return m.width
}

func (m Model) View() tea.View {
	content, _ := m.layout()
	v := tea.NewView(content)
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	return v
}

// layout computes both cells and hit regions from the same current state, so
// a resize, filter or scrolled list cannot leave stale mouse coordinates.
func (m Model) layout() (string, []hit) {
	w, h := max(1, m.width), max(1, m.height)
	lines := []string{fit(accent.Render("UUP / IMAGE BUILDER")+"  | Workspace", w), strings.Repeat("-", w)}
	var hits []hit
	normal := w >= 96
	if !normal {
		x, y := 0, len(lines)
		nav := ""
		for i, name := range areaNames {
			label := fmt.Sprintf("%d %s", i+1, name)
			if Area(i) == m.area {
				label = "[" + label + "]"
			}
			if x > 0 && x+len(label) > w {
				lines = append(lines, fit(nav, w))
				nav = ""
				x = 0
				y++
			}
			hits = append(hits, hit{x: x, y: y, width: len(label), msg: NavigateMsg{Area: Area(i)}})
			nav += label + "  "
			x += len(label) + 2
		}
		lines = append(lines, fit(nav, w), strings.Repeat("-", w))
	}
	footer := wrapped(m.footer(), w, 3)
	summary := m.summaryLines(w)
	notice := []string{}
	if m.notice != "" {
		notice = wrapped("! "+terminalText(m.notice), w, 2)
	}
	// Keep source identity and contextual keys visible while lists scroll.
	bodyHeight := max(0, h-len(lines)-1-len(summary)-len(notice)-len(footer))
	contentWidth := m.contentWidth()
	rows := m.areaRows(contentWidth, bodyHeight)
	if m.showHelp {
		rows = nil
		for _, line := range m.helpLines() {
			for _, part := range wrapped(line, contentWidth, 3) {
				rows = append(rows, row{text: part})
			}
		}
	}
	bodyY := len(lines)
	for i := 0; i < bodyHeight; i++ {
		text := ""
		if i < len(rows) {
			text = rows[i].text
		}
		x := 0
		if normal {
			nav := ""
			if i < len(areaNames) {
				nav = fmt.Sprintf(" %d %s", i+1, areaNames[i])
				if Area(i) == m.area {
					nav = accent.Render(">" + nav[1:])
				}
				hits = append(hits, hit{x: 0, y: bodyY + i, width: 18, msg: NavigateMsg{Area: Area(i)}})
			}
			lines = append(lines, fit(nav, 18)+"| "+fit(text, contentWidth))
			x = 20
		} else {
			lines = append(lines, fit(text, contentWidth))
		}
		if i < len(rows) && rows[i].msg != nil && !m.showHelp {
			hits = append(hits, hit{x: x, y: bodyY + i, width: contentWidth, msg: rows[i].msg})
		}
	}
	lines = append(lines, strings.Repeat("-", w))
	for _, line := range append(append(summary, notice...), footer...) {
		lines = append(lines, fit(line, w))
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	return strings.Join(lines, "\n"), hits
}

func (m Model) summaryLines(width int) []string {
	label := "none selected"
	if m.source != nil {
		label = terminalText(m.source.Title) + " | " + terminalText(m.source.Build)
	} else if m.cfg.Image.UpdateID != "" {
		label = "configured source (title not retrieved)"
	}
	lines := []string{ansi.Truncate(fmt.Sprintf("Source: %s | Draft r%d", label, m.revision), width, "...")}
	id := "select an exact catalogue record"
	if m.cfg.Image.UpdateID != "" {
		id = terminalText(m.cfg.Image.UpdateID)
	}
	lines = append(lines, wrapped("ID: "+id, width, 4)...)
	language := terminalText(m.cfg.Image.Language)
	if language == "" {
		language = "choose"
	}
	editions := terminalText(strings.Join(m.cfg.Image.Editions, ", "))
	if editions == "" {
		editions = "choose"
	}
	lines = append(lines, wrapped(fmt.Sprintf("Target: %s | Language: %s | Editions: %s", terminalText(string(m.cfg.Image.Architecture)), language, editions), width, 2)...)
	if m.appsUnchecked {
		lines = append(lines, wrapped(appsUncheckedNotice, width, 2)...)
	}
	return lines
}

func statusText(s requestStatus, empty string) string {
	if s.loading {
		return "Loading catalogue..."
	}
	if !s.staleAt.IsZero() {
		return "Stale cache " + s.staleAt.UTC().Format("2006-01-02 15:04Z") + " | r retry: " + boundedText(s.err.Error(), 300)
	}
	if s.err != nil {
		return "Failed | r retry: " + boundedText(s.err.Error(), 300)
	}
	if s.checkedAt.IsZero() {
		return empty
	}
	return "Available (cache or network) | checked " + s.checkedAt.UTC().Format("15:04Z") + " | r refresh"
}

func (m Model) areaRows(width, height int) []row {
	switch m.area {
	case Builds:
		return m.buildRows(width, height)
	case Image:
		return m.imageRows(width, height)
	case Apps:
		return []row{{text: "Choose included apps"}, {text: "App inventory has not been resolved for this image."}, {text: "Requested app policies are retained; applicability is unchecked."}}
	case Conversion:
		return m.conversionRows(width, height)
	case Review:
		return []row{{text: "Review build"}, {text: "Source metadata, settings and preflight must be resolved first."}, {text: "No build can be started from this browsing view."}}
	case Progress:
		return []row{{text: "Build progress"}, {text: "No job is connected."}, {text: "Progress will use actual stages and measured work."}}
	}
	return nil
}

func (m Model) buildRows(width, height int) []row {
	target := terminalText(string(m.builds.archFilter))
	if target == "" {
		target = "all"
	}
	status := statusText(m.builds.status, "Ready to search UUP Dump")
	if m.builds.pending {
		status = "Waiting for query... (300ms debounce)"
	}
	filter := m.builds.filter
	filter.SetWidth(max(1, width-30-ansi.StringWidth(target)))
	rows := []row{{text: accent.Render("Choose a Windows build")}, {text: "Source type: not yet resolved from package metadata"}, {text: "Search (/): " + m.builds.search.View()}, {text: "Filter (f): " + strings.TrimRight(filter.View(), " ") + " | Target (a): " + target}, {text: status}}
	visible := m.builds.visible()
	rows = append(rows, row{text: fmt.Sprintf("%d of %d records | exact UUID/revision per row", len(visible), len(m.builds.records))})
	if len(visible) == 0 && !m.builds.pending && !m.builds.status.loading && m.builds.status.err == nil {
		rows = append(rows, row{text: "No matches. Change the upstream query or local filters."})
	}
	count := max(1, (height-len(rows))/2)
	start := max(0, m.builds.cursor-count+1)
	for i := start; i < min(len(visible), start+count); i++ {
		b := visible[i]
		mark := " "
		if b.UpdateID == m.cfg.Image.UpdateID {
			mark = "*"
		}
		if i == m.builds.cursor {
			mark = ">"
		}
		text := fmt.Sprintf("%s %s | %s | %s", mark, terminalText(b.Title), terminalText(b.Build), terminalText(string(b.Architecture)))
		rows = append(rows, row{text: text, msg: SelectBuildMsg{UpdateID: b.UpdateID}}, row{text: "  " + terminalText(b.UpdateID), msg: SelectBuildMsg{UpdateID: b.UpdateID}})
	}
	return rows
}

func (m Model) imageRows(width, height int) []row {
	rows := []row{{text: accent.Render("Configure the image")}, {text: "One target, one language, one or more editions"}}
	if m.cfg.Image.UpdateID == "" {
		return append(rows, row{text: "Select an exact source in Builds to load language and editions."})
	}
	arches := m.Architectures()
	archText := make([]string, 0, len(arches))
	for i, arch := range arches {
		name := terminalText(string(arch))
		if i == m.image.archCursor && m.image.focus == 0 {
			name = ">" + name
		}
		archText = append(archText, name)
	}
	targetLine := "Target: " + strings.Join(archText, "  ")
	if ansi.StringWidth(targetLine) > width && len(arches) > m.image.archCursor {
		marker := ""
		if m.image.focus == 0 {
			marker = ">"
		}
		targetLine = fmt.Sprintf("Target: %s%s [%d/%d] up/down", marker, terminalText(string(arches[m.image.archCursor])), m.image.archCursor+1, len(arches))
	}
	rows = append(rows, row{text: targetLine, msg: imageFocusMsg{field: 0}})
	rows = append(rows, row{text: statusText(m.image.languageStatus, "Choose a source to load languages")})
	language := "no languages available"
	if len(m.image.languages) > m.image.languageCursor {
		choice := m.image.languages[m.image.languageCursor]
		language = fmt.Sprintf("%s - %s [%d/%d]", terminalText(choice.ID), terminalText(choice.Name), m.image.languageCursor+1, len(m.image.languages))
		if m.cfg.Image.Language == choice.ID {
			language += " (selected)"
		}
	}
	prefix := "  "
	if m.image.focus == 1 {
		prefix = "> "
	}
	rows = append(rows, row{text: prefix + "Language: " + language, msg: imageFocusMsg{field: 1}})
	rows = append(rows, row{text: statusText(m.image.editionStatus, "Select language to load editions")}, row{text: "Editions (space): catalogue choices; derivations need metadata"})
	choices := m.editionChoices()
	count := max(1, height-len(rows)-1)
	start := max(0, m.image.editionCursor-count+1)
	for i := start; i < min(len(choices), start+count); i++ {
		choice := choices[i]
		check := "[ ]"
		if slices.Contains(m.cfg.Image.Editions, choice.ID) {
			check = "[x]"
		}
		prefix = "  "
		if m.image.focus == 2 && i == m.image.editionCursor {
			prefix = "> "
		}
		unavailable := ""
		if !m.image.hasEdition(choice.ID) {
			unavailable = " ! unavailable"
		}
		rows = append(rows, row{text: prefix + check + " " + terminalText(choice.Name) + " (" + terminalText(choice.ID) + ")" + unavailable, msg: editionClickMsg{index: i, edition: choice.ID}})
	}
	if m.image.ready(m.cfg.Image) {
		rows = append(rows, row{text: "Enter from editions: continue to Apps", msg: NavigateMsg{Area: Apps}})
	} else {
		rows = append(rows, row{text: "Choose a language and at least one available edition."})
	}
	return rows
}
