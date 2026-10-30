package tui

import (
	"fmt"
	"testing"

	tea "charm.land/bubbletea/v2"
	"uupbuilder/internal/catalog"
)

func dropdownImage(t *testing.T, width, height int) Model {
	t.Helper()
	m := chosen(t)
	m.image.languages = nil
	for i := 1; i <= 12; i++ {
		m.image.languages = append(m.image.languages, catalog.Language{ID: fmt.Sprintf("lang-%02d", i), Name: fmt.Sprintf("Language %02d", i)})
	}
	m.cfg.Image.Language = "lang-01"
	m.image.languageCursor = 0
	return send(m, tea.WindowSizeMsg{Width: width, Height: height})
}

func languageOptionHits(m Model) []hit {
	_, hits := m.layout()
	var choices []hit
	for _, h := range hits {
		if _, ok := h.msg.(SelectLanguageMsg); ok {
			choices = append(choices, h)
		}
	}
	return choices
}

func TestImageLanguageDropdownShowsSixScrollableMouseChoices(t *testing.T) {
	for _, size := range [][2]int{{120, 32}, {68, 24}, {68, 25}} {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			m := dropdownImage(t, size[0], size[1])
			defer m.Close()
			before := m.Snapshot()
			_, hits := m.layout()
			for _, h := range hits {
				if field, ok := h.msg.(imageFocusMsg); ok && field.field == 1 {
					m = send(m, tea.MouseClickMsg{X: h.x, Y: h.y, Button: tea.MouseLeft})
					break
				}
			}
			choices := languageOptionHits(m)
			if len(choices) != 6 {
				t.Fatalf("open dropdown shows %d clickable options, want 6", len(choices))
			}
			t.Logf("Open language dropdown (%dx%d):\n%s", size[0], size[1], structuralView(m.View().Content))
			if m.cfg.Image.Language != before.Config.Image.Language || m.revision != before.Revision {
				t.Fatal("opening the dropdown changed the selected language")
			}
			for i := 0; i < 7; i++ {
				m = send(m, key(tea.KeyDown, ""))
			}
			choices = languageOptionHits(m)
			if len(choices) != 6 || choices[0].msg.(SelectLanguageMsg).Language != "lang-03" || choices[5].msg.(SelectLanguageMsg).Language != "lang-08" {
				t.Fatalf("keyboard scrolling did not keep six options and the highlighted eighth language visible: %+v", choices)
			}
			last := choices[5]
			m = send(m, tea.MouseWheelMsg{X: last.x, Y: last.y, Button: tea.MouseWheelDown})
			choices = languageOptionHits(m)
			if len(choices) != 6 || choices[5].msg.(SelectLanguageMsg).Language != "lang-09" {
				t.Fatal("mouse wheel did not scroll the language dropdown")
			}
			last = choices[5]
			m, cmd := step(m, tea.MouseClickMsg{X: last.x, Y: last.y, Button: tea.MouseLeft})
			if m.cfg.Image.Language != "lang-09" || m.revision != before.Revision+1 || len(m.cfg.Image.Editions) != 0 || cmd == nil {
				t.Fatal("clicking a scrolled option did not select it and reload its editions")
			}
			if result := cmd().(editionsResultMsg); result.language != "lang-09" {
				t.Fatalf("requested editions for the wrong language: %s", result.language)
			}
			if len(languageOptionHits(m)) != 0 {
				t.Fatal("selecting a language did not close the dropdown")
			}
		})
	}
}

func TestImageLanguageDropdownKeyboardDismissalAndSelection(t *testing.T) {
	m := dropdownImage(t, 120, 32)
	defer m.Close()
	m = send(m, key(tea.KeyTab, ""))
	m = send(m, key(tea.KeyEnter, ""))
	if len(languageOptionHits(m)) != 6 {
		t.Fatal("Enter did not open the language dropdown")
	}
	m = send(m, key(tea.KeyDown, ""))
	m = send(m, key(tea.KeyEscape, ""))
	if m.area != Image || m.cfg.Image.Language != "lang-01" || len(languageOptionHits(m)) != 0 {
		t.Fatal("Escape did not dismiss the dropdown without changing the selection or leaving Image")
	}
	m = send(m, key(tea.KeyEnter, ""))
	if m.image.languageCursor != 0 {
		t.Fatal("reopening did not highlight the selected language")
	}
	m = send(m, key(tea.KeyDown, ""))
	m, cmd := step(m, key(tea.KeyEnter, ""))
	if m.cfg.Image.Language != "lang-02" || cmd == nil || len(languageOptionHits(m)) != 0 {
		t.Fatal("Enter did not select the highlighted language and close the dropdown")
	}
	m = send(m, key(tea.KeyEnter, ""))
	m = send(m, key(tea.KeyTab, ""))
	if m.image.focus != 2 || len(languageOptionHits(m)) != 0 {
		t.Fatal("Tab did not close the dropdown and move to editions")
	}
}

func TestImageLanguageDropdownScrollBoundsAndRefresh(t *testing.T) {
	m := dropdownImage(t, 68, 24)
	defer m.Close()
	m = send(m, key(tea.KeyTab, ""))
	m = send(m, key(tea.KeyEnter, ""))
	for i := 0; i < 20; i++ {
		m = send(m, key(tea.KeyDown, ""))
	}
	choices := languageOptionHits(m)
	if len(choices) != 6 || choices[0].msg.(SelectLanguageMsg).Language != "lang-07" || choices[5].msg.(SelectLanguageMsg).Language != "lang-12" {
		t.Fatal("scrolling past the last language lost the final six choices")
	}
	for i := 0; i < 20; i++ {
		m = send(m, key(tea.KeyUp, ""))
	}
	choices = languageOptionHits(m)
	if len(choices) != 6 || choices[0].msg.(SelectLanguageMsg).Language != "lang-01" || choices[5].msg.(SelectLanguageMsg).Language != "lang-06" {
		t.Fatal("scrolling past the first language lost the first six choices")
	}
	m, cmd := step(m, RefreshMsg{})
	if cmd == nil || len(languageOptionHits(m)) != 0 {
		t.Fatal("refresh left stale language options clickable")
	}
	m = send(m, key(tea.KeyEnter, ""))
	if len(languageOptionHits(m)) != 0 {
		t.Fatal("loading languages can be opened")
	}
}
