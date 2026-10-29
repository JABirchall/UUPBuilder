package tui

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/pelletier/go-toml/v2"
)

type hit struct {
	x, y, width int
	msg         tea.Msg
}

func (h hit) contains(x, y int) bool { return y == h.y && x >= h.x && x < h.x+h.width }

type row struct {
	text string
	msg  tea.Msg
	hits []hit // relative horizontal cells for controls sharing a rendered row
}

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
	width = max(0, width)
	value = ansi.Truncate(value, width, strings.Repeat(".", min(3, width)))
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

const sidebarWidth = 21 // includes its right divider

func (m Model) contentWidth() int {
	width := m.width - 2
	if m.width >= 96 {
		width -= sidebarWidth
	}
	return max(1, width-2*m.contentPadding())
}
func (m Model) contentPadding() int {
	if m.width < 50 {
		return 1
	}
	return 2
}

func (m Model) View() tea.View {
	content, _ := m.layout()
	v := tea.NewView(content)
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.BackgroundColor = canvasColor
	v.ForegroundColor = textColor
	return v
}

// layout computes visible cells and hit regions together, including clipping.
// Resizing and scrolling never retain coordinates from an earlier frame.
func (m Model) layout() (string, []hit) {
	w, h := max(1, m.width), max(1, m.height)
	if w < 8 || h < 5 {
		return canvas.Render(fit("UUP / IMAGE BUILDER", w)), nil
	}
	inner := w - 2
	lines := []string{divider.Render("┌" + strings.Repeat("─", inner) + "┐")}
	var hits []hit
	frame := func(text string) string {
		return divider.Render("│") + canvas.Render(fit(text, inner)) + divider.Render("│")
	}
	headerHeight := 1
	if h >= 28 {
		headerHeight = 3
	}
	button := "View TOML (t)"
	if m.showTOML {
		button = "Close TOML"
	}
	buttonWidth := min(17, inner-2)
	buttonX := inner - buttonWidth - 1
	buttonRows := controlRows("", button, buttonWidth, m.showTOML, headerHeight == 1, viewTOMLMsg{})
	if headerHeight == 1 {
		buttonRows[0].text = divider.Render("│") + accent.Render(fit(button, buttonWidth-2)) + divider.Render("│")
	}
	for i := 0; i < headerHeight; i++ {
		left := ""
		if i == 0 {
			left = accent.Render("UUP / IMAGE BUILDER")
		} else if i == 1 {
			left = muted.Render("TUI workspace · live catalogue / current draft")
		}
		padding := min(2, buttonX)
		lines = append(lines, frame(strings.Repeat(" ", padding)+fit(left, max(0, buttonX-padding))+buttonRows[i].text+" "))
		hits = append(hits, hit{x: buttonX + 1, y: len(lines) - 1, width: buttonWidth, msg: viewTOMLMsg{}})
	}
	lines = append(lines, divider.Render("├"+strings.Repeat("─", inner)+"┤"))
	normal := w >= 96
	if !normal && !m.showTOML && !m.showHelp {
		var nav string
		x := 0
		for i, name := range areaNames {
			label := fmt.Sprintf("%02d %s", i+1, name)
			width := min(inner, ansi.StringWidth(label)+2)
			if x > 0 && x+width > inner {
				lines = append(lines, frame(nav))
				nav, x = "", 0
			}
			nav += navigationLine(" "+label, width, Area(i) == m.area)
			hits = append(hits, hit{x: 1 + x, y: len(lines), width: width, msg: NavigateMsg{Area: Area(i)}})
			x += width
		}
		lines = append(lines, frame(nav), divider.Render("├"+strings.Repeat("─", inner)+"┤"))
	}
	footer := wrapped(keyHints(m.footer()), max(1, inner-4), 2)
	if h < 22 {
		footer = footer[:1]
	}
	bodyHeight := max(0, h-len(lines)-len(footer)-2)
	width := m.contentWidth()
	summary := m.summaryRows(width, h < 28)
	if m.showTOML || m.showHelp {
		summary = nil
	}
	summaryLimit := max(0, bodyHeight-3)
	hasNotice := m.notice != "" && !m.showTOML && !m.showHelp
	if hasNotice && bodyHeight > 0 {
		summaryLimit = max(1, summaryLimit)
	}
	if len(summary) > summaryLimit {
		if hasNotice && summaryLimit > 0 {
			// Config outcomes must survive compact clipping; optional source
			// details yield before the final sanitized notice row.
			notice := summary[len(summary)-1]
			summary = append(summary[:summaryLimit-1], notice)
		} else {
			summary = summary[:summaryLimit]
		}
	}
	areaHeight := max(0, bodyHeight-len(summary))
	rows := m.areaRows(width, areaHeight)
	if m.showHelp {
		rows = nil
		for i, line := range m.helpLines() {
			for _, part := range wrapped(line, width, 3) {
				if i == 0 {
					part = heading.Render(part)
				}
				rows = append(rows, row{text: part})
			}
		}
	} else if m.showTOML {
		rows = m.tomlRows(width, areaHeight)
	}
	bodyY := len(lines)
	for i := 0; i < bodyHeight; i++ {
		var r row
		if i < areaHeight && i < len(rows) {
			r = rows[i]
		} else if i >= areaHeight {
			r = summary[i-areaHeight]
		}
		left := ""
		contentX := 1 + m.contentPadding()
		if normal {
			left = m.sidebarLine(i, bodyHeight)
			contentX += sidebarWidth
			if !m.showTOML && !m.showHelp && i >= 1 && i <= 11 && i%2 == 1 {
				hits = append(hits, hit{x: 2, y: bodyY + i, width: sidebarWidth - 3, msg: NavigateMsg{Area: Area((i - 1) / 2)}})
			}
		}
		padding := strings.Repeat(" ", m.contentPadding())
		lines = append(lines, frame(left+padding+fit(r.text, width)+padding))
		if !m.showHelp && !m.showTOML {
			if r.msg != nil {
				hits = append(hits, hit{x: contentX, y: bodyY + i, width: width, msg: r.msg})
			}
			for _, target := range r.hits {
				target.x += contentX
				target.y = bodyY + i
				hits = append(hits, target)
			}
		}
	}
	lines = append(lines, divider.Render("├"+strings.Repeat("─", inner)+"┤"))
	for _, line := range footer {
		lines = append(lines, frame("  "+line))
	}
	lines = append(lines, divider.Render("└"+strings.Repeat("─", inner)+"┘"))
	if len(lines) > h {
		lines = lines[:h]
	}
	hits = slices.DeleteFunc(hits, func(target hit) bool {
		return target.y < 0 || target.y >= len(lines) || target.x < 0 || target.x+target.width > w
	})
	return canvas.Render(strings.Join(lines, "\n")), hits
}

func (m Model) sidebarLine(y, height int) string {
	text := ""
	if y >= 1 && y <= 11 && y%2 == 1 {
		area := Area((y - 1) / 2)
		text = navigationLine(fmt.Sprintf(" %02d %s", area+1, area), sidebarWidth-3, area == m.area)
	} else if y >= max(13, height-4) {
		path := terminalText(filepath.Base(m.configActions.path))
		if path == "." || path == "" {
			path = "unsaved draft"
		}
		host := "Windows 10+"
		if m.deps.Host.NativeArchitecture != "" {
			host += " / " + terminalText(string(m.deps.Host.NativeArchitecture))
		}
		metadata := []string{path, host, "Host ≠ ISO target"}
		index := y - max(13, height-4)
		if index < len(metadata) {
			text = muted.Render(fit(" "+metadata[index], sidebarWidth-3))
		}
	}
	return " " + fit(text, sidebarWidth-2) + divider.Render("│")
}

func (m Model) summaryRows(width int, dense bool) []row {
	label := "none selected"
	if m.source != nil {
		label = terminalText(m.source.Title) + " · " + terminalText(m.source.Build)
	} else if m.cfg.Image.UpdateID != "" {
		label = "configured source (title not retrieved)"
	}
	language := terminalText(m.cfg.Image.Language)
	if language == "" {
		language = "choose"
	}
	editions := terminalText(strings.Join(m.cfg.Image.Editions, ", "))
	if editions == "" {
		editions = "choose"
	}
	target := fmt.Sprintf("Target: %s | Language: %s | Editions: %s", terminalText(string(m.cfg.Image.Architecture)), language, editions)
	rows := []row{{text: rule(width)}, {text: muted.Render("Source: ") + label}}
	if !dense {
		id := terminalText(m.cfg.Image.UpdateID)
		if id == "" {
			id = "select an exact catalogue record"
		}
		rows = append(rows, row{text: muted.Render("ID: " + id)})
	}
	rows = append(rows, row{text: muted.Render(target)})
	if m.appsUnchecked {
		rows = append(rows, row{text: muted.Render(appsUncheckedNotice)})
	}
	if m.notice != "" {
		rows = append(rows, row{text: muted.Render("! " + terminalText(m.notice))})
	}
	if !dense && m.area == Builds && width >= 76 {
		label := "Configure image →"
		var msg tea.Msg
		if m.cfg.Image.UpdateID != "" {
			msg = NavigateMsg{Area: Image}
		} else if builds := m.builds.visible(); len(builds) > m.builds.cursor {
			label, msg = "Select source →", SelectBuildMsg{UpdateID: builds[m.builds.cursor].UpdateID}
		}
		if msg != nil {
			action := controlRows("", label, 23, true, false, msg)
			for i, r := range action {
				rows[i+1].text = fit(rows[i+1].text, width-25) + "  " + r.text
				rows[i+1].hits = []hit{{x: width - 23, width: 23, msg: msg}}
			}
		}
	}
	return rows
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
		return []row{{text: heading.Render("Choose included apps")}, {}, {text: muted.Render("App inventory has not been resolved for this image.")}, {text: "Requested app policies are retained; applicability is unchecked."}}
	case Conversion:
		return m.conversionRows(width, height)
	case Review:
		return []row{{text: heading.Render("Review build")}, {}, {text: "Source metadata, settings and preflight must be resolved first."}, {text: muted.Render("No build can be started from this browsing view.")}}
	case Progress:
		return []row{{text: heading.Render("Build progress")}, {}, {text: muted.Render("No job is connected.")}}
	}
	return nil
}

func (m Model) buildRows(width, height int) []row {
	target := terminalText(string(m.builds.archFilter))
	if target == "" {
		target = "all"
	}
	rows := []row{{text: heading.Render("Choose a Windows build")}}
	if height >= 11 {
		rows = append(rows, row{text: muted.Render("Live UUP Dump catalogue · select an exact source record.")})
	}
	if m.height >= 28 && height >= 14 {
		rows = append(rows, row{})
	}
	if width >= 58 && height >= 11 {
		searchWidth, filterWidth := (width-4)/2, (width-4)/3
		targetWidth := width - 4 - searchWidth - filterWidth
		rows = append(rows, joinControls(
			controlRows("Search builds (/)", inputView(m.builds.search, searchWidth-4), searchWidth, m.builds.search.Focused(), false, buildInputMsg{}),
			controlRows("Filter (f)", inputView(m.builds.filter, filterWidth-4), filterWidth, m.builds.filter.Focused(), false, buildInputMsg{filter: true}),
			controlRows("Target (a)", target+" ▾", targetWidth, false, false, cycleTargetFilterMsg{}),
		)...)
	} else if height >= 5 || m.editing() {
		rows = append(rows, controlRows("Search (/)", inputView(m.builds.search, width-15), width, m.builds.search.Focused(), true, buildInputMsg{})...)
		rows = append(rows, controlRows("Filter (f)", inputView(m.builds.filter, width-25)+" ["+target+"]", width, m.builds.filter.Focused(), true, buildInputMsg{filter: true})...)
	}
	visible := m.builds.visible()
	status := statusText(m.builds.status, "Ready to search UUP Dump")
	if m.builds.pending {
		status = "Waiting for query... (300ms debounce)"
	}
	if height-len(rows) >= 3 {
		rows = append(rows, row{text: muted.Render(fmt.Sprintf("%d of %d records · %s", len(visible), len(m.builds.records), status))})
	}
	if len(visible) == 0 {
		if !m.builds.pending && !m.builds.status.loading && m.builds.status.err == nil {
			rows = append(rows, row{text: "No matches. Change the upstream query or local filters."})
		}
		return rows
	}
	rowHeight := 2
	if m.height >= 28 && height >= 14 {
		rowHeight = 3
	}
	count := max(1, (height-len(rows))/rowHeight)
	start := max(0, m.builds.cursor-count+1)
	for i := start; i < min(len(visible), start+count); i++ {
		b := visible[i]
		mark := " "
		if b.UpdateID == m.cfg.Image.UpdateID {
			mark = "*"
		}
		selected := i == m.builds.cursor
		if selected {
			mark = ">"
		}
		text := sides(fmt.Sprintf("%s %s · %s", mark, terminalText(b.Title), terminalText(b.Build)), terminalText(string(b.Architecture)), width-2)
		msg := SelectBuildMsg{UpdateID: b.UpdateID}
		secondary := selectedLine("   "+terminalText(b.UpdateID), width, selected)
		if !selected {
			secondary = muted.Render(fit("   "+terminalText(b.UpdateID), width))
		}
		primary := heading
		if selected {
			primary = active.Bold(true)
		}
		rows = append(rows, row{text: primary.Render(fit(" "+text+" ", width)), msg: msg}, row{text: secondary, msg: msg})
		if rowHeight == 3 {
			rows = append(rows, row{text: rule(width)})
		}
	}
	return rows
}

func (m Model) imageRows(width, height int) []row {
	rows := []row{{text: heading.Render("Configure the image")}}
	if height >= 10 {
		rows = append(rows, row{text: muted.Render("One target, one language, one or more editions.")})
	}
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
	targetLine := strings.Join(archText, "  ")
	if ansi.StringWidth(targetLine) > width-12 && len(arches) > m.image.archCursor {
		marker := ""
		if m.image.focus == 0 {
			marker = ">"
		}
		targetLine = fmt.Sprintf("%s%s [%d/%d] up/down", marker, terminalText(string(arches[m.image.archCursor])), m.image.archCursor+1, len(arches))
	}
	dense := height < 15
	rows = append(rows, controlRows("Target", targetLine, width, m.image.focus == 0, dense, imageFocusMsg{field: 0})...)
	language := "no languages available"
	if len(m.image.languages) > m.image.languageCursor {
		choice := m.image.languages[m.image.languageCursor]
		language = fmt.Sprintf("%s · %s [%d/%d]", terminalText(choice.ID), terminalText(choice.Name), m.image.languageCursor+1, len(m.image.languages))
		if m.cfg.Image.Language == choice.ID {
			language += " (selected)"
		}
	}
	rows = append(rows, controlRows("Language", language, width, m.image.focus == 1, dense, imageFocusMsg{field: 1})...)
	if height-len(rows) >= 6 {
		rows = append(rows, row{text: muted.Render(statusText(m.image.languageStatus, "Choose a source to load languages"))}, row{text: muted.Render(statusText(m.image.editionStatus, "Select language to load editions"))})
	}
	rows = append(rows, row{text: accent.Render("Editions (space to toggle)")})
	choices := m.editionChoices()
	count := max(1, height-len(rows)-1)
	start := max(0, m.image.editionCursor-count+1)
	for i := start; i < min(len(choices), start+count); i++ {
		choice := choices[i]
		check := "[ ]"
		if slices.Contains(m.cfg.Image.Editions, choice.ID) {
			check = "[x]"
		}
		prefix := "  "
		selected := m.image.focus == 2 && i == m.image.editionCursor
		if selected {
			prefix = "> "
		}
		unavailable := ""
		if !m.image.hasEdition(choice.ID) {
			unavailable = " ! unavailable"
		}
		rows = append(rows, row{text: selectedLine(prefix+check+" "+terminalText(choice.Name)+" ("+terminalText(choice.ID)+")"+unavailable, width, selected), msg: editionClickMsg{index: i, edition: choice.ID}})
	}
	if m.image.ready(m.cfg.Image) {
		rows = append(rows, row{text: accent.Render("Continue to Apps → (enter from editions)"), msg: NavigateMsg{Area: Apps}})
	} else {
		rows = append(rows, row{text: muted.Render("Choose a language and at least one available edition.")})
	}
	// Very short views prioritize the control the keyboard is actually moving.
	// Other image fields remain reachable through Tab rather than hiding the
	// selected edition underneath explanatory rows.
	if height < 6 && len(rows) > height {
		for i, r := range rows {
			focused := false
			switch msg := r.msg.(type) {
			case imageFocusMsg:
				focused = m.image.focus == msg.field
			case editionClickMsg:
				focused = m.image.focus == 2 && msg.index == m.image.editionCursor
			}
			if focused {
				return append(rows[:1:1], rows[i:]...)
			}
		}
	}
	return rows
}

func (m Model) tomlLines(width int) []string {
	data, err := toml.Marshal(m.cfg)
	if err != nil {
		return []string{"Unable to encode draft: " + terminalText(err.Error())}
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		lines = append(lines, strings.Split(ansi.Hardwrap(terminalText(line), max(1, width), true), "\n")...)
	}
	return lines
}
func (m *Model) scrollTOML(delta int) {
	m.tomlOffset = max(0, min(m.tomlOffset+delta, len(m.tomlLines(m.contentWidth()-2))-1))
}
func (m Model) tomlRows(width, height int) []row {
	rows := []row{{text: heading.Render("Read-only draft TOML")}, {text: muted.Render("Current requested values · no file is loaded or saved.")}}
	code := m.tomlLines(width - 2)
	count := max(1, height-len(rows)-2)
	start := min(m.tomlOffset, max(0, len(code)-count))
	rows = append(rows, row{text: divider.Render("┌" + strings.Repeat("─", max(0, width-2)) + "┐")})
	for i := start; i < min(len(code), start+count); i++ {
		rows = append(rows, row{text: divider.Render("│") + panel.Render(fit(code[i], width-2)) + divider.Render("│")})
	}
	rows = append(rows, row{text: divider.Render("└" + strings.Repeat("─", max(0, width-2)) + "┘")})
	return rows
}
