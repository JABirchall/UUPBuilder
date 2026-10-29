package tui

import (
	"reflect"
	"testing"

	tea "charm.land/bubbletea/v2"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
)

func TestImageSpaceSelectsFocusedLanguageAndLoadsCurrentEditions(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	m.cfg.Apps.Include = []string{"Requested.Family"}
	m = send(m, key(tea.KeyTab, ""))
	m = send(m, key(tea.KeyDown, ""))
	before := m.Snapshot()
	oldGeneration := m.image.editionGeneration
	if before.Config.Image.Language != "en-us" || m.image.languages[m.image.languageCursor].ID != "de-de" {
		t.Fatal("fixture must highlight a different language from the current selection")
	}

	m, cmd := step(m, key(' ', " "))
	after := m.Snapshot()
	if after.Config.Image.Language != "de-de" || after.Revision != before.Revision+1 {
		t.Fatalf("Space did not select the focused language and revise the draft: %+v", after)
	}
	if len(after.Config.Image.Editions) != 0 || len(m.image.editions) != 0 || m.image.editionsChecked || after.ImageReady || !m.image.editionStatus.loading {
		t.Fatal("language selection retained editions or failed to start their replacement")
	}
	if after.AppsApplicable || after.AppsNotice == "" || !reflect.DeepEqual(after.Config.Apps.Include, []string{"Requested.Family"}) {
		t.Fatal("language selection lost app intent or its applicability invalidation")
	}
	if cmd == nil {
		t.Fatal("Space did not return the edition discovery command")
	}
	m = send(m, editionsResultMsg{generation: oldGeneration, updateID: firstID, language: "en-us", editions: []catalog.Edition{{ID: "obsolete"}}})
	if len(m.image.editions) != 0 || m.image.editionsChecked || !m.image.editionStatus.loading {
		t.Fatal("previous language response replaced the pending edition request")
	}
	result, ok := cmd().(editionsResultMsg)
	if !ok || result.updateID != firstID || result.language != "de-de" || result.generation != m.image.editionGeneration || result.err != nil {
		t.Fatalf("Space returned the wrong edition request: %+v", result)
	}
	m = send(m, result)
	if !m.image.editionsChecked || m.image.editionStatus.loading || len(m.image.editions) != 2 || m.cfg.Image.Language != "de-de" || len(m.cfg.Image.Editions) != 0 || m.area != Image {
		t.Fatal("current edition response did not complete discovery for the single selected language")
	}
}

func TestImageSpaceSelectsFocusedTargetsActualSource(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	m = send(m, key(tea.KeyDown, ""))
	before := m.Snapshot()
	m, cmd := step(m, key(' ', " "))
	after := m.Snapshot()
	if after.Config.Image.Architecture != "arm64" || after.Config.Image.UpdateID != secondID || after.Config.Image.Language != "" || len(after.Config.Image.Editions) != 0 {
		t.Fatalf("Space did not choose the actual source for a target change: %+v", after.Config.Image)
	}
	if after.Revision != before.Revision+1 || after.ImageReady || !after.HasCatalogRecord || cmd == nil || m.area != Image {
		t.Fatal("target change did not discover the actual group source in Image")
	}
	if result := cmd().(languagesResultMsg); result.updateID != secondID {
		t.Fatalf("Space requested languages for the wrong source: %+v", result)
	}
}

func TestImageSpaceRespectsUnavailableLanguageChoices(t *testing.T) {
	for _, state := range []string{"empty", "loading", "no source"} {
		t.Run(state, func(t *testing.T) {
			m := chosen(t)
			defer m.Close()
			m = send(m, key(tea.KeyTab, ""))
			m = send(m, key(tea.KeyDown, ""))
			switch state {
			case "empty":
				m.image.languages = nil
			case "loading":
				m.image.languageStatus.loading = true
			case "no source":
				m.cfg.Image.UpdateID = ""
			}
			before := m.Snapshot()
			m, cmd := step(m, key(' ', " "))
			if cmd != nil || !reflect.DeepEqual(before, m.Snapshot()) {
				t.Fatal("Space changed the draft or requested editions without usable language choices")
			}
		})
	}
}

func TestImageSpaceWithNoTargetChoicesDoesNothing(t *testing.T) {
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	defer m.Close()
	m = send(m, NavigateMsg{Area: Image})
	before := m.Snapshot()
	m, cmd := step(m, key(' ', " "))
	if cmd != nil || !reflect.DeepEqual(before, m.Snapshot()) {
		t.Fatal("Space changed the draft without a target choice")
	}
}

func TestImageSpaceTogglesEditionWithoutContinuing(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	m = send(m, key(tea.KeyTab, ""))
	m = send(m, key(tea.KeyTab, ""))
	before := m.revision
	m, cmd := step(m, key(' ', " "))
	if cmd != nil || len(m.cfg.Image.Editions) != 0 || m.revision != before+1 || m.area != Image {
		t.Fatal("Space did not toggle the selected edition in place")
	}
	m = send(m, key(' ', " "))
	if !reflect.DeepEqual(m.cfg.Image.Editions, []string{"professional"}) || m.area != Image {
		t.Fatal("Space continued instead of selecting the edition")
	}
	m = send(m, key(tea.KeyEnter, ""))
	if m.area != Apps {
		t.Fatal("Enter did not retain edition continuation")
	}
}

func TestSpaceRemainsLiteralWhileEditing(t *testing.T) {
	for _, field := range []string{"search", "filter", "config path"} {
		t.Run(field, func(t *testing.T) {
			m := browse(t)
			defer m.Close()
			switch field {
			case "search":
				m = send(m, key('/', "/"))
			case "filter":
				m = send(m, key('f', "f"))
			case "config path":
				m = send(m, NavigateMsg{Area: Conversion})
				m = send(m, key(tea.KeyEnter, ""))
			}
			m = send(m, key('a', "a"))
			m = send(m, key(' ', " "))
			m = send(m, key('b', "b"))
			value := m.builds.search.Value()
			if field == "filter" {
				value = m.builds.filter.Value()
			} else if field == "config path" {
				value = m.conversion.input.Value()
			}
			if value != "a b" || !m.editing() {
				t.Fatalf("Space did not remain literal text: %q", value)
			}
		})
	}
}

func TestImageSpaceScrollsTOMLInsteadOfSelecting(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	m = send(m, key(tea.KeyTab, ""))
	m = send(m, key(tea.KeyDown, ""))
	m = send(m, key('t', "t"))
	before := m.Snapshot()
	m, cmd := step(m, key(' ', " "))
	if cmd != nil || !m.showTOML || m.tomlOffset == 0 || !reflect.DeepEqual(before, m.Snapshot()) {
		t.Fatal("Space selected an Image choice instead of scrolling read-only TOML")
	}
}
