package tui

import (
	"fmt"
	"strings"
)

func (m Model) reviewRows(width, height int) []row {
	rows := []row{{text: heading.Render("Review build")}}
	if !m.buildAction.reviewed {
		return append(rows, row{text: "Select Build ISO in Conversion to check required tools."})
	}
	if m.buildAction.draft.Revision != m.revision {
		return append(rows, row{text: "Draft changed. Select Build ISO again before starting."})
	}
	rows = append(rows, row{text: accent.Render("Start build (enter)"), msg: StartBuildMsg{}}, row{text: "Back to Conversion (esc)", msg: NavigateMsg{Area: Conversion}})
	details := m.reviewDetails(width)
	count := max(0, height-len(rows))
	start := min(m.buildAction.reviewOffset, max(0, len(details)-count))
	return append(rows, details[start:min(len(details), start+count)]...)
}

func (m Model) reviewDetails(width int) []row {
	cfg := m.buildAction.draft.Config
	details := []string{
		"Source: " + cfg.Image.UpdateID,
		fmt.Sprintf("Target: %s / %s / %s", cfg.Image.Architecture, cfg.Image.Language, strings.Join(requestedEditions(cfg), ", ")),
		fmt.Sprintf("Apps: %s | include: %s | stubs: %s | Edge: %s", cfg.Apps.Mode, strings.Join(cfg.Apps.Include, ", "), cfg.Apps.StubPolicy, cfg.Apps.Edge),
		fmt.Sprintf("Updates: %s | cleanup: %t | reset base: %s", cfg.Conversion.Updates, cfg.Conversion.Cleanup, cfg.Conversion.ResetBase),
		fmt.Sprintf("ISO: %s | install.%s", cfg.Output.Directory, cfg.Output.ImageFormat),
		"All requested settings: View TOML (t)",
		"Source applicability is checked after Start build.",
	}
	details = append(details, m.buildAction.tools...)
	var rows []row
	for _, text := range details {
		for _, line := range wrapped(terminalText(text), width, 0) {
			rows = append(rows, row{text: line})
		}
	}
	return rows
}

func (m Model) progressRows(width, height int) []row {
	width, height = max(0, width), max(0, height)
	rows := []row{{text: heading.Render("Build progress")}}
	if m.buildAction.status == "" {
		rows = append(rows, row{text: "Start a build from Review to see progress and logs."})
		for i := range rows {
			rows[i].text = fit(rows[i].text, width)
		}
		return rows[:min(len(rows), height)]
	}
	rows = append(rows, row{text: fmt.Sprintf("%s | %s", terminalText(m.buildAction.status), terminalText(m.buildAction.stage))})
	if m.buildAction.busy {
		rows = append(rows, row{text: accent.Render("Cancel build (c)"), msg: CancelBuildMsg{}})
	}
	budget := max(0, height-len(rows)-1)
	if len(m.buildAction.logs) > 0 && budget > 3 {
		budget--
	}
	rows = append(rows, m.buildAction.downloadRows(width, min(9, budget))...)
	rows = append(rows, row{text: muted.Render("Logs · up/down or page up/down · end follows latest")})
	count := max(0, height-len(rows))
	end := max(0, len(m.buildAction.logs)-m.buildAction.offset)
	start := max(0, end-count)
	for _, line := range m.buildAction.logs[start:end] {
		rows = append(rows, row{text: fit(line, width)})
	}
	for i := range rows {
		rows[i].text = fit(rows[i].text, width)
	}
	return rows[:min(len(rows), height)]
}
