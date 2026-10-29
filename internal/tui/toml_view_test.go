package tui

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// Viewing must serialize the current draft, never load, normalize or save the
// selected file, start discovery, or invalidate the caller's snapshot.
func TestViewTOMLIsReadOnlyCurrentDraftAndEscapeRestoresArea(t *testing.T) {
	m := chosen(t)
	m = send(m, ConversionFieldChangedMsg{Key: "downloads.parallel_files", Value: "7"})
	m = send(m, NavigateMsg{Area: Conversion})
	path := filepath.Join(t.TempDir(), "profile.toml")
	const disk = "# intentionally not the draft\nkeep = 'verbatim'\n"
	if err := os.WriteFile(path, []byte(disk), 0600); err != nil {
		t.Fatal(err)
	}
	m = send(m, ConfigPathChangedMsg{Path: path})
	before := m.Snapshot()
	m, cmd := step(m, key('t', "t"))
	if cmd != nil {
		t.Fatal("viewing emitted an IO command")
	}
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, "Read-only draft TOML") {
		t.Fatalf("shortcut did not open TOML: %s", view)
	}
	// Scroll the real view to reach later config sections.
	for i := 0; i < 100 && !strings.Contains(view, "parallel_files = 7"); i++ {
		m = send(m, key(tea.KeyDown, ""))
		view = ansi.Strip(m.View().Content)
	}
	if !strings.Contains(view, "parallel_files = 7") {
		t.Fatal("TOML view does not expose the current unsaved draft")
	}
	m = send(m, key(tea.KeyEscape, ""))
	if strings.Contains(ansi.Strip(m.View().Content), "Read-only draft TOML") || m.ActiveArea() != Conversion {
		t.Fatal("Escape did not restore the current area")
	}
	if !reflect.DeepEqual(before, m.Snapshot()) {
		t.Fatal("viewing changed the draft, revision, path or notice")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != disk {
		t.Fatalf("viewing wrote the selected file: %q %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("viewing created a backup or another file: %v %v", entries, err)
	}
}

func TestViewTOMLShortcutDoesNotStealTextInput(t *testing.T) {
	for _, input := range []string{"search", "filter", "config"} {
		t.Run(input, func(t *testing.T) {
			m := browse(t)
			switch input {
			case "search":
				m = send(m, key('/', "/"))
			case "filter":
				m = send(m, key('f', "f"))
			case "config":
				m = send(m, NavigateMsg{Area: Conversion})
				m = send(m, key(tea.KeyEnter, ""))
			}
			m = send(m, key('t', "t"))
			if !m.editing() || strings.Contains(ansi.Strip(m.View().Content), "Read-only draft TOML") {
				t.Fatal("TOML shortcut stole a typed character")
			}
			value := m.builds.search.Value()
			if input == "filter" {
				value = m.builds.filter.Value()
			} else if input == "config" {
				value = m.conversion.input.Value()
			}
			if value != "t" {
				t.Fatalf("typed character lost: %q", value)
			}
		})
	}
}

func TestWorkspaceVisibleControlsUseCurrentCellsAfterResize(t *testing.T) {
	m := browse(t)
	for _, size := range [][2]int{{120, 34}, {68, 26}, {104, 30}} {
		m = send(m, NavigateMsg{Area: Builds})
		m.builds.archFilter = "arm64"
		m = send(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		lines := strings.Split(ansi.Strip(m.View().Content), "\n")
		clicked := false
		for y, line := range lines {
			if x := strings.Index(line, "upstream query"); x >= 0 {
				m = send(m, tea.MouseClickMsg{X: ansi.StringWidth(line[:x]), Y: y, Button: tea.MouseLeft})
				clicked = true
				break
			}
		}
		if !clicked || !m.builds.search.Focused() {
			t.Fatalf("%v: displayed search field does not accept mouse focus", size)
		}
		m = send(m, key(tea.KeyEscape, ""))
		lines = strings.Split(ansi.Strip(m.View().Content), "\n")
		for y, line := range lines {
			if x := strings.Index(line, "View TOML"); x >= 0 {
				m = send(m, tea.MouseClickMsg{X: ansi.StringWidth(line[:x]), Y: y, Button: tea.MouseLeft})
				break
			}
		}
		if !strings.Contains(ansi.Strip(m.View().Content), "Read-only draft TOML") {
			t.Fatalf("%v: displayed TOML action did not open", size)
		}
		m = send(m, key(tea.KeyEscape, ""))
		lines = strings.Split(ansi.Strip(m.View().Content), "\n")
		for y, line := range lines {
			if x := strings.Index(line, secondID); x >= 0 {
				m = send(m, tea.MouseClickMsg{X: ansi.StringWidth(line[:x]), Y: y, Button: tea.MouseLeft})
				break
			}
		}
		if m.cfg.Image.UpdateID != secondID || m.ActiveArea() != Image {
			t.Fatalf("%v: displayed source row selected a different record", size)
		}
	}
}
