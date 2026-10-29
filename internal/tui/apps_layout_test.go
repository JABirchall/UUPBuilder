package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestAppsViews(t *testing.T) {
	for _, size := range []struct {
		name          string
		width, height int
	}{{"normal", 120, 32}, {"compact", 68, 24}} {
		t.Run(size.name, func(t *testing.T) {
			m := appsChosen(t)
			m, cmd := step(m, NavigateMsg{Area: Apps})
			m = send(m, cmd())
			m = send(m, key(' ', " "))
			m = send(m, tea.WindowSizeMsg{Width: size.width, Height: size.height})
			view := m.View().Content
			if len(strings.Split(view, "\n")) > size.height {
				t.Fatal("Apps view overflows height")
			}
			for _, line := range strings.Split(view, "\n") {
				if ansi.StringWidth(line) > size.width {
					t.Fatal("Apps view overflows width")
				}
			}
			path := filepath.Join("testdata", fmt.Sprintf("workspace_apps_%s.golden", size.name))
			got := structuralView(view)
			if os.Getenv("UPDATE_TUI_GOLDENS") == "1" {
				if err := os.WriteFile(path, []byte(got), 0644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if structuralView(string(want)) != got {
				t.Fatalf("Apps structure mismatch\n%s", got)
			}
		})
	}
}
