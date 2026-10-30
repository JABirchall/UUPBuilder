package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
)

// These are structural goldens: collapse spacing/styles and omit empty frame
// cells, while keeping navigation, source identity, choice state and keys.
func structuralView(view string) string {
	var lines []string
	for _, line := range strings.Split(ansi.Strip(view), "\n") {
		line = strings.Join(strings.Fields(line), " ")
		if strings.Trim(line, "-|│─┌┐└┘├┤ ") == "" {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestWorkspaceViews(t *testing.T) {
	for _, size := range []struct {
		name          string
		width, height int
	}{{"normal", 120, 32}, {"compact", 68, 24}} {
		for _, area := range []Area{Builds, Image} {
			t.Run(area.String()+"_"+size.name, func(t *testing.T) {
				m := browse(t)
				if area == Image {
					m = chosen(t)
					m.image.focus = 2
				}
				checked := time.Date(2026, 10, 27, 12, 30, 0, 0, time.UTC)
				m.builds.status.checkedAt = checked
				m.image.languageStatus.checkedAt = checked
				m.image.editionStatus.checkedAt = checked
				m = send(m, tea.WindowSizeMsg{Width: size.width, Height: size.height})
				view := m.View().Content
				lines := strings.Split(view, "\n")
				if len(lines) > size.height {
					t.Fatalf("view is %d rows for %d", len(lines), size.height)
				}
				for i, line := range lines {
					if width := ansi.StringWidth(line); width > size.width {
						t.Errorf("line %d exceeds width: %d > %d", i, width, size.width)
					}
				}
				t.Logf("Actual Charm view (%dx%d):\n%s", size.width, size.height, ansi.Strip(view))
				path := filepath.Join("testdata", fmt.Sprintf("workspace_%s_%s.golden", strings.ToLower(area.String()), size.name))
				got := structuralView(view)
				if os.Getenv("UPDATE_TUI_GOLDENS") == "1" {
					if err := os.MkdirAll("testdata", 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(got), 0644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				wantStructure := structuralView(string(want))
				if got != wantStructure {
					t.Errorf("structural view mismatch\ngot:\n%s\nwant:\n%s", got, wantStructure)
				}
			})
		}
	}
}

func TestArchitectureFocusedChoiceVisibleInCompactView(t *testing.T) {
	m := chosen(t)
	for i := 0; i < 20; i++ {
		m.builds.records = append(m.builds.records, catalog.Build{UpdateID: fmt.Sprintf("extra-%d", i), Title: "Windows example", Build: "26100.1", Architecture: model.Architecture(fmt.Sprintf("target-%02d", i))})
	}
	m.builds.records = append(m.builds.records, catalog.Build{UpdateID: "extra-x86", Title: "Windows example", Build: "26100.1", Architecture: "x86"})
	m = send(m, tea.WindowSizeMsg{Width: 68, Height: 24})
	for i := 0; i < 24; i++ {
		m = send(m, key(tea.KeyDown, ""))
	}
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, ">x86") {
		t.Fatalf("focused target scrolled out of view: %s", view)
	}
}

func TestWorkspaceFocusedInputAndSmallBounds(t *testing.T) {
	for _, size := range [][2]int{{80, 24}, {68, 24}, {40, 16}, {1, 1}} {
		m := browse(t)
		m = send(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m = send(m, key('/', "/"))
		m = send(m, tea.PasteMsg{Content: "Windows 11"})
		view := m.View().Content
		lines := strings.Split(view, "\n")
		if len(lines) > size[1] {
			t.Fatalf("%v overflows height", size)
		}
		for _, line := range lines {
			if ansi.StringWidth(line) > size[0] {
				t.Fatalf("%v overflows width: %q", size, line)
			}
		}
		if size[0] >= 68 && !strings.Contains(ansi.Strip(view), "Windows 11") {
			t.Fatal("focused input not visible")
		}
	}
}

func TestWorkspaceMouseNavigationSelectionAndResize(t *testing.T) {
	for _, width := range []int{120, 68} {
		m := browse(t)
		m.builds.archFilter = "arm64"
		m = send(m, tea.WindowSizeMsg{Width: width, Height: 30})
		click := func(match func(tea.Msg) bool) {
			t.Helper()
			_, hits := m.layout()
			for _, hit := range hits {
				if match(hit.msg) {
					var cmd tea.Cmd
					m, cmd = step(m, tea.MouseClickMsg{X: hit.x, Y: hit.y, Button: tea.MouseLeft})
					for _, msg := range runCommands(cmd) {
						m = send(m, msg)
					}
					return
				}
			}
			t.Fatal("visible action has no hit region")
		}
		click(func(msg tea.Msg) bool { choice, ok := msg.(SelectBuildMsg); return ok && choice.UpdateID == secondID })
		if m.ActiveArea() != Image || m.cfg.Image.UpdateID != secondID {
			t.Fatal("mouse chose the wrong source")
		}
		click(func(msg tea.Msg) bool { field, ok := msg.(imageFocusMsg); return ok && field.field == 1 })
		click(func(msg tea.Msg) bool { choice, ok := msg.(SelectLanguageMsg); return ok && choice.Language == "en-us" })
		if m.cfg.Image.Language != "en-us" {
			t.Fatal("mouse did not select the displayed language")
		}
		click(func(msg tea.Msg) bool { edition, ok := msg.(editionClickMsg); return ok && edition.edition == "core" })
		if !m.Snapshot().ImageReady {
			t.Fatal("mouse edition selection did not complete image choices")
		}
		if m.image.focus != 2 {
			t.Fatal("mouse edition selection did not move keyboard focus")
		}
		click(func(msg tea.Msg) bool { nav, ok := msg.(NavigateMsg); return ok && nav.Area == Progress })
		if m.ActiveArea() != Progress {
			t.Fatal("mouse navigation failed after layout change")
		}
	}
}

func TestWorkspaceScrolledFocusAndUntrustedTextStayInsideViewport(t *testing.T) {
	for _, area := range []Area{Builds, Image, Conversion} {
		for _, size := range [][2]int{{120, 32}, {68, 24}, {40, 16}, {28, 12}, {1, 1}} {
			t.Run(fmt.Sprintf("%s_%dx%d", area, size[0], size[1]), func(t *testing.T) {
				m := chosen(t)
				m = send(m, NavigateMsg{Area: area})
				m = send(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
				m.notice = strings.Repeat("更新 ", 100) + "\x1b]0;unsafe\x07"
				for i := 0; i < 30; i++ {
					m.builds.records = append(m.builds.records, catalog.Build{UpdateID: fmt.Sprintf("scroll-%d", i), Title: strings.Repeat("世界é ", 30) + "\x1b]0;unsafe\x07", Build: fmt.Sprint(i), Architecture: "arm64"})
					m.image.editions = append(m.image.editions, catalog.Edition{ID: fmt.Sprintf("edition-%d", i), Name: strings.Repeat("世界é ", 30) + "\x1b]0;unsafe\x07"})
				}
				if area == Image {
					m.image.focus = 2
				}
				for i := 0; i < 100; i++ {
					m.move(1)
				}
				view, hits := m.layout()
				lines := strings.Split(view, "\n")
				if len(lines) > size[1] {
					t.Fatalf("height overflow: %d", len(lines))
				}
				for _, line := range lines {
					if ansi.StringWidth(line) > size[0] || strings.Contains(ansi.Strip(line), "unsafe") {
						t.Fatalf("unsafe or overflowing line: %q", line)
					}
				}
				for _, target := range hits {
					if target.y < 0 || target.y >= len(lines) || target.x < 0 || target.x+target.width > size[0] {
						t.Fatalf("hit outside viewport: %+v", target)
					}
				}
				if size[0] >= 40 && !strings.Contains(ansi.Strip(view), "> ") {
					t.Fatalf("scrolled keyboard focus is hidden:\n%s", ansi.Strip(view))
				}
			})
		}
	}
}
