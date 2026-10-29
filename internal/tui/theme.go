package tui

import (
	"strings"

	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// Workspace's palette is independent of the user's terminal theme. Styles
// include backgrounds so selected cells and empty canvas stay coherent.
var (
	canvasColor = lipgloss.Color("#15121e")
	textColor   = lipgloss.Color("#e7e0ef")
	mutedColor  = lipgloss.Color("#b0a3bd")
	lineColor   = lipgloss.Color("#463a56")
	accentColor = lipgloss.Color("#c5a2ff")
	activeColor = lipgloss.Color("#39274f")
	panelColor  = lipgloss.Color("#201b2a")
	canvas      = lipgloss.NewStyle().Foreground(textColor).Background(canvasColor)
	muted       = canvas.Foreground(mutedColor)
	divider     = canvas.Foreground(lineColor)
	accent      = canvas.Bold(true).Foreground(accentColor)
	heading     = canvas.Bold(true)
	active      = canvas.Foreground(accentColor).Background(activeColor)
	panel       = canvas.Background(panelColor)
)

func rule(width int) string { return divider.Render(strings.Repeat("─", max(0, width))) }

func selectedLine(text string, width int, selected bool) string {
	if selected {
		return active.Render(fit(text, width))
	}
	return canvas.Render(fit(text, width))
}

func navigationLine(text string, width int, selected bool) string {
	if selected {
		return active.Render(fit(text, width))
	}
	return muted.Render(fit(text, width))
}

func keyHints(text string) string {
	parts := strings.Split(text, " | ")
	for i, part := range parts {
		key, description, _ := strings.Cut(part, " ")
		parts[i] = accent.Bold(false).Render(key) + muted.Render(" "+description)
	}
	return strings.Join(parts, muted.Render(" | "))
}

func sides(left, right string, width int) string {
	right = ansi.Truncate(right, max(0, width/3), "…")
	return fit(left, max(0, width-ansi.StringWidth(right)-1)) + " " + right
}

// Every border row shares the control's hit region. Dense terminals use a
// single bordered row, preserving the same keyboard and mouse action.
func controlRows(label, value string, width int, selected, dense bool, msg any) []row {
	width = max(2, width)
	style := divider
	if selected {
		style = active
	}
	if dense {
		prefix := ""
		if selected {
			prefix = "> "
		}
		label = ansi.Truncate(label, min(20, width/2), "…")
		return []row{{text: style.Render("│") + selectedLine(prefix+label+" | "+value, width-2, selected) + style.Render("│"), msg: msg}}
	}
	borderLabel := ""
	if label != "" {
		borderLabel = " " + label + " "
	}
	labelWidth := min(width-2, ansi.StringWidth(borderLabel))
	labelStyle := muted
	if selected {
		labelStyle = active
	}
	top := style.Render("┌") + labelStyle.Render(ansi.Truncate(borderLabel, labelWidth, "")) + style.Render(strings.Repeat("─", max(0, width-2-labelWidth))+"┐")
	return []row{
		{text: top, msg: msg},
		{text: style.Render("│") + selectedLine(" "+value, width-2, selected) + style.Render("│"), msg: msg},
		{text: style.Render("└" + strings.Repeat("─", width-2) + "┘"), msg: msg},
	}
}

func inputView(input textinput.Model, width int) string {
	input.SetWidth(max(1, width))
	input.SetValue(terminalText(input.Value()))
	input.SetStyles(textinput.Styles{
		Focused: textinput.StyleState{Text: canvas, Placeholder: muted, Prompt: canvas},
		Blurred: textinput.StyleState{Text: canvas, Placeholder: muted, Prompt: canvas},
	})
	return input.View()
}

func joinControls(groups ...[]row) []row {
	var rows []row
	for y := range len(groups[0]) {
		var r row
		x := 0
		for i, group := range groups {
			if i > 0 {
				r.text += "  "
				x += 2
			}
			cell := group[y]
			width := ansi.StringWidth(cell.text)
			r.text += cell.text
			if cell.msg != nil {
				r.hits = append(r.hits, hit{x: x, width: width, msg: cell.msg})
			}
			x += width
		}
		rows = append(rows, r)
	}
	return rows
}
