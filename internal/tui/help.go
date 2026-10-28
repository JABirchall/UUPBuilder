package tui

func (m Model) helpLines() []string {
	lines := []string{"Keyboard help - " + m.area.String(), "1-6: open an area   ctrl+left/right: change area", "up/down or j/k: move   tab: next field/area", "enter: choose / continue   esc: leave field / back", "?: contextual help   f1: help anywhere   ctrl+c: quit"}
	switch m.area {
	case Builds:
		lines = append(lines, "/: edit upstream query (300ms debounce)", "f: filter retrieved records locally   a: target filter", "r: refresh from upstream / retry", "Each row is an exact UUID/revision, never a guessed release group.")
	case Image:
		lines = append(lines, "tab: target, language, editions   space: toggle edition", "r: refresh the focused language/edition choices", "Changing target requires selecting an exact catalogue record.", "App requests are retained; their applicability needs checking.")
	case Conversion:
		lines = append(lines, "up/down or tab: settings and TOML actions", "enter / space: cycle choices, edit text, or run selected action", "Text: enter applies; esc cancels. Lists use commas.", "Select config path, then Load or Save. Save reports backup/normalization.", "Requested values are retained; effective values need source applicability.")
	default:
		lines = append(lines, "This area will use its owning editor or job controller.", "Navigation does not start, pause or change a build job.")
	}
	return lines
}
func (m Model) footer() string {
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
		return "up/down move | / search | f filter | a target | enter select | r refresh | esc back | ? help"
	case Image:
		return "tab field | up/down move | space toggle | enter choose/next | r retry | esc back | ? help"
	case Conversion:
		return "up/down / tab field | enter / space edit or run | esc back | ? help | ctrl+c quit"
	default:
		return "1-6 areas | ctrl+left/right navigate | esc back | ? help | ctrl+c quit"
	}
}
