package tui

import tea "charm.land/bubbletea/v2"

type Area int

const (
	Builds Area = iota
	Image
	Apps
	Conversion
	Review
	Progress
)

var areaNames = [...]string{"Builds", "Image", "Apps", "Conversion", "Review", "Progress"}

func (a Area) String() string {
	if a < Builds || a > Progress {
		return "Unknown"
	}
	return areaNames[a]
}
func (m Model) ActiveArea() Area { return m.area }
func (m *Model) navigate(area Area) {
	if area < Builds || area > Progress {
		return
	}
	m.area = area
	m.builds.search.Blur()
	m.builds.filter.Blur()
	m.conversion.input.Blur()
	m.apps.search.Blur()
}
func (m Model) editing() bool {
	return m.builds.search.Focused() || m.builds.filter.Focused() || m.conversion.input.Focused() || m.apps.search.Focused()
}
func (m Model) updateKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		m.Close()
		return m, tea.Quit
	}
	if m.showTOML {
		switch key {
		case "esc", "t":
			m.showTOML = false
		case "up", "k":
			m.scrollTOML(-1)
		case "down", "j":
			m.scrollTOML(1)
		case "pgup":
			m.scrollTOML(-max(1, m.height-10))
		case "pgdown", "space", " ":
			m.scrollTOML(max(1, m.height-10))
		case "home":
			m.tomlOffset = 0
		case "end":
			m.scrollTOML(len(m.tomlLines(m.contentWidth() - 2)))
		}
		return m, nil
	}
	if key == "f1" {
		m.showHelp = !m.showHelp
		return m, nil
	}
	if m.showHelp {
		if key == "esc" || key == "?" {
			m.showHelp = false
		}
		return m, nil
	}
	if m.editing() {
		if m.apps.search.Focused() {
			return m.updateAppInput(msg)
		}
		if m.conversion.input.Focused() {
			return m.updateConversionInput(msg)
		}
		if key == "esc" || key == "enter" {
			m.builds.search.Blur()
			m.builds.filter.Blur()
			if key == "enter" && m.builds.pending {
				cmd := m.beginSearch(false)
				return m, cmd
			}
			return m, nil
		}
		return m.updateInput(msg)
	}
	if key == "?" {
		m.showHelp = true
		return m, nil
	}
	if key == "t" {
		return m.Update(viewTOMLMsg{})
	}
	if len(key) == 1 && key[0] >= '1' && key[0] <= '6' {
		return m.Update(NavigateMsg{Area: Area(key[0] - '1')})
	}
	if m.area == Apps {
		switch key {
		case "a":
			return m.Update(appPresetMsg{id: allOfferedPreset})
		case "ctrl+a":
			return m.Update(appSelectAllMsg{})
		case "d":
			return m.Update(appModeMsg{mode: "default"})
		case "c":
			return m.Update(appModeMsg{mode: "custom"})
		case "n":
			return m.Update(appModeMsg{mode: "none"})
		}
	}
	switch key {
	case "ctrl+right":
		return m.Update(NavigateMsg{Area: (m.area + 1) % 6})
	case "ctrl+left", "shift+tab":
		return m.Update(NavigateMsg{Area: (m.area + 5) % 6})
	case "esc":
		if m.area > Builds {
			return m.Update(NavigateMsg{Area: m.area - 1})
		}
	case "r":
		return m.Update(RefreshMsg{})
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "tab":
		if m.area == Image {
			m.image.focus = (m.image.focus + 1) % 3
		} else if m.area == Conversion {
			m.move(1)
		} else if m.area == Apps {
			m.apps.focus = (m.apps.focus + 1) % 4
		} else {
			return m.Update(NavigateMsg{Area: (m.area + 1) % 6})
		}
	case "/":
		if m.area == Builds {
			cmd := m.builds.search.Focus()
			return m, cmd
		}
		if m.area == Apps {
			return m, m.apps.search.Focus()
		}
	case "f":
		if m.area == Builds {
			cmd := m.builds.filter.Focus()
			return m, cmd
		}
	case "a":
		if m.area == Builds {
			m.cycleFilter()
		}
	case "enter":
		return m.activate()
	case "space", " ":
		if m.area == Apps {
			if m.apps.focus != 2 {
				return m.activateAppControl()
			}
			choices := m.appChoices()
			if len(choices) > m.apps.cursor {
				m.toggleApp(choices[m.apps.cursor].featureID)
			}
			return m, nil
		}
		if m.area == Conversion || (m.area == Image && m.image.focus < 2) {
			return m.activate()
		}
		if m.area == Image && m.image.focus == 2 {
			choices := m.editionChoices()
			if len(choices) > m.image.editionCursor {
				m.toggleEdition(choices[m.image.editionCursor].ID)
			}
		}
	}
	return m, nil
}

func (m Model) updateInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.apps.search.Focused() {
		return m.updateAppInput(msg)
	}
	if m.conversion.input.Focused() {
		return m.updateConversionInput(msg)
	}
	if m.builds.search.Focused() {
		var cmd tea.Cmd
		m.builds.search, cmd = m.builds.search.Update(msg)
		if m.builds.search.Value() != m.builds.query {
			return m.changeQuery(m.builds.search.Value())
		}
		return m, cmd
	}
	var cmd tea.Cmd
	m.builds.filter, cmd = m.builds.filter.Update(msg)
	m.builds.cursor = 0
	return m, cmd
}
func (m *Model) move(delta int) {
	if m.area == Apps {
		m.apps.cursor = max(0, min(m.apps.cursor+delta, len(m.appChoices())-1))
	}
	if m.area == Conversion {
		m.conversion.cursor = max(0, min(m.conversion.cursor+delta, configControlCount+len(m.conversion.fields)-1))
	}
	if m.area == Builds {
		m.builds.cursor = max(0, min(m.builds.cursor+delta, len(m.builds.visibleGroups())-1))
	}
	if m.area == Image {
		switch m.image.focus {
		case 0:
			m.image.archCursor = max(0, min(m.image.archCursor+delta, len(m.imageArchitectures())-1))
		case 1:
			m.image.languageCursor = max(0, min(m.image.languageCursor+delta, len(m.image.languages)-1))
		case 2:
			m.image.editionCursor = max(0, min(m.image.editionCursor+delta, len(m.editionChoices())-1))
		}
	}
}
func (m Model) activate() (tea.Model, tea.Cmd) {
	if m.area == Apps {
		return m.activateAppControl()
	}
	if m.area == Conversion {
		return m.activateConversion()
	}
	if m.area == Builds {
		rows := m.builds.visibleGroups()
		if len(rows) > m.builds.cursor {
			return m.Update(SelectBuildMsg{UpdateID: m.groupBuild(rows[m.builds.cursor]).UpdateID})
		}
	}
	if m.area == Image {
		switch m.image.focus {
		case 0:
			choices := m.imageArchitectures()
			if len(choices) > m.image.archCursor {
				return m.Update(ChangeArchitectureMsg{Architecture: choices[m.image.archCursor]})
			}
		case 1:
			if len(m.image.languages) > m.image.languageCursor {
				return m.Update(SelectLanguageMsg{Language: m.image.languages[m.image.languageCursor].ID})
			}
		case 2:
			if m.image.ready(m.cfg.Image) {
				m.navigate(Apps)
				return m, m.beginApps(false)
			} else {
				m.notice = "Choose an available language and at least one available edition before continuing."
			}
		}
	}
	return m, nil
}
func (m *Model) cycleFilter() {
	choices := m.Architectures()
	index := -1
	for i, arch := range choices {
		if arch == m.builds.archFilter {
			index = i
			break
		}
	}
	m.builds.archFilter = ""
	if index+1 < len(choices) {
		m.builds.archFilter = choices[index+1]
	}
	m.builds.cursor = 0
}
