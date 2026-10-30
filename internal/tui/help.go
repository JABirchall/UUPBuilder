package tui

func (m Model) helpLines() []string {
	lines := []string{"Keyboard help - " + m.area.String(), "1-6: open an area   ctrl+left/right: change area", "up/down or j/k: move   tab: next field/area", "enter: choose / continue   esc: leave field / back", "t: read-only draft TOML (outside text fields); esc closes", "TOML: up/down, page up/down, home/end or mouse wheel scroll", "?: contextual help   f1: help anywhere   ctrl+c: quit"}
	switch m.area {
	case Builds:
		lines = append(lines, "/: edit upstream query (300ms debounce)", "f: filter retrieved sources locally; paste an exact UUID/revision", "a: target filter   r: refresh from upstream / retry", "One row per exact title/build; all available targets are shown.", "Choose uses the filtered/requested target, otherwise the first source.", "For repeated targets, keep the requested UUID or use the first source.")
	case Image:
		lines = append(lines, "tab: target, language, editions   space: choose / toggle edition", "r: refresh the focused language/edition choices", "Targets use actual sources in the selected title/build version.", "Missing source: return to Builds to select an exact record.", "Repeated targets use the first source; UUID filters select revisions.", "App requests are retained; their applicability needs checking.")
	case Conversion:
		lines = append(lines, "up/down or tab: settings, TOML actions and Build ISO", "enter / space: cycle choices, edit text, or run selected action", "Text: enter applies; esc cancels. Lists use commas.", "Select config path, then Load or Save. Save reports backup/normalization.", "Build ISO checks tool availability, then opens Review.", "Downloads and native work begin only after Start build in Review.")
	case Apps:
		lines = append(lines, "/: search source families locally; enter/esc leaves search", "tab: mode, stub preference, family list, All offered preset", "d/c/n: engine defaults, explicit custom requests, or no apps", "a: All offered from current examined source; replaces custom requests", "ctrl+a: select/deselect visible offered families; hidden requests stay", "space: toggle focused raw FeatureID; enter from list: conversion", "Preset requests are saved once; source changes never reapply them.", "r: retry small source metadata; no app package bodies are fetched", "Source dependencies and edition hints do not establish policy locks.", "Manifest, package closure, licensing and provisioning checks remain pending.")
	case Review:
		lines = append(lines, "enter: start the reviewed build; esc: return to Conversion", "t: inspect every requested setting before starting", "Editing the draft invalidates this review; select Build ISO again.")
	case Progress:
		lines = append(lines, "up/down, page up/down: scroll logs; end: follow latest", "c: cancel active work and wait for cleanup", "Source downloads, tool acquisition and native output appear here.")
	default:
		lines = append(lines, "This area will use its owning editor or job controller.", "Navigation does not start, pause or change a build job.")
	}
	return lines
}
func (m Model) footer() string {
	if m.showTOML {
		return "up/down scroll | pgup/pgdown page | home/end | esc / t close | ctrl+c quit"
	}
	if m.showHelp {
		return "esc / ? close help | 1-6 areas | ctrl+c quit"
	}
	if m.editing() {
		if m.conversion.input.Focused() {
			return "type value | enter apply | esc cancel | f1 help"
		}
		return "type query/filter | enter apply | esc leave field | f1 help"
	}
	switch m.area {
	case Builds:
		return "↑↓ move | / search | f filter | a target | enter select | r refresh | t TOML | esc back | ? help"
	case Image:
		if m.image.focus < 2 {
			return "tab field | ↑↓ move | space / enter choose | r retry | t TOML | esc back | ? help"
		}
		return "tab field | ↑↓ move | space toggle | enter choose/next | r retry | t TOML | esc back | ? help"
	case Conversion:
		return "↑↓ / tab field | enter / space edit or run | t TOML | esc back | ? help | ctrl+c quit"
	case Apps:
		return "↑↓ move | space request | / search | a All offered | ctrl+a visible | tab control | d/c/n mode | enter next | r retry | t TOML | esc back | ? help"
	case Review:
		return "enter Start build | ↑↓ details | esc back | t all settings | ? help | ctrl+c quit"
	case Progress:
		return "↑↓ logs | pgup/pgdown | end follow latest | c cancel | esc back | 1-6 areas | ctrl+c quit"
	default:
		return "1-6 areas | ctrl+left/right navigate | t TOML | esc back | ? help | ctrl+c quit"
	}
}
