package tui

import (
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
)

// Representative titles with the evidenced UUID/architecture pairs exercise
// stable upstream order without equating feature and Preview variants.
func versionRecords() []catalog.Build {
	return []catalog.Build{
		{UpdateID: "e8706433-04f4-4a00-b58f-df8ed1bab586", Title: "Windows 11 feature", Build: "28000.3365", Architecture: "arm64"},
		{UpdateID: "e3914fec-814a-46d8-9a94-a3f2d67ee9bf", Title: "Windows 11 Preview Update", Build: "28000.3365", Architecture: "amd64"},
		{UpdateID: "8f550c54-da87-45d3-89e3-0c03a6f16ae8", Title: "Windows 11 feature", Build: "28000.3365", Architecture: "amd64"},
		{UpdateID: "ab3c5f86-25bc-43a2-993e-e1b2ddf3b872", Title: "Windows 11 Preview Update", Build: "28000.3365", Architecture: "arm64"},
		{UpdateID: "different-build", Title: "Windows 11 feature", Build: "28000.3366", Architecture: "future"},
	}
}

func buildRowIDs(rows []row) []string {
	var ids []string
	for _, r := range rows {
		if msg, ok := r.msg.(SelectBuildMsg); ok && (len(ids) == 0 || ids[len(ids)-1] != msg.UpdateID) {
			ids = append(ids, msg.UpdateID)
		}
	}
	return ids
}

func rowText(rows []row) string {
	var text []string
	for _, r := range rows {
		text = append(text, ansi.Strip(r.text))
	}
	return strings.Join(text, "\n")
}

func TestBuildVersionRowsGroupOnlyExactTitleAndBuild(t *testing.T) {
	m := browse(t)
	defer m.Close()
	m.builds.records = versionRecords()
	rows := m.buildRows(110, 26)
	wantIDs := []string{"8f550c54-da87-45d3-89e3-0c03a6f16ae8", "e3914fec-814a-46d8-9a94-a3f2d67ee9bf", "different-build"}
	if got := buildRowIDs(rows); !reflect.DeepEqual(got, wantIDs) {
		t.Fatalf("version rows did not preserve title/build variants and upstream order: %v", got)
	}
	text := rowText(rows)
	if strings.Count(text, "amd64 / arm64") != 2 || !strings.Contains(text, "3 of 3 versions") || !strings.Contains(text, "5 of 5 sources") {
		t.Fatalf("group targets/counts are inaccurate:\n%s", text)
	}
	if !reflect.DeepEqual(m.builds.records, versionRecords()) {
		t.Fatal("presentation grouping changed upstream identities")
	}
	// A target filter narrows eligible sources while still showing every actual
	// architecture of each version, rather than hiding its siblings.
	m.builds.archFilter = "arm64"
	rows = m.buildRows(110, 26)
	if got := buildRowIDs(rows); !reflect.DeepEqual(got, []string{"e8706433-04f4-4a00-b58f-df8ed1bab586", "ab3c5f86-25bc-43a2-993e-e1b2ddf3b872"}) {
		t.Fatalf("target filter selected wrong exact sources: %v", got)
	}
	if text := rowText(rows); strings.Count(text, "amd64 / arm64") != 2 || !strings.Contains(text, "2 of 3 versions") || !strings.Contains(text, "2 of 5 sources") {
		t.Fatalf("filtered group targets/counts are inaccurate:\n%s", text)
	}
}

func TestBuildGroupKeyboardUsesOneCursorPositionPerVersion(t *testing.T) {
	m := browse(t)
	defer m.Close()
	m = send(m, key(tea.KeyDown, ""))
	m, cmd := step(m, key(tea.KeyEnter, ""))
	if m.cfg.Image.UpdateID != "33333333-3333-3333-3333-333333333333" || cmd == nil {
		t.Fatalf("second version cursor selected an architecture duplicate: %+v", m.cfg.Image)
	}
	result := cmd().(languagesResultMsg)
	if result.updateID != "33333333-3333-3333-3333-333333333333" {
		t.Fatalf("version selection requested a different source: %+v", result)
	}
}

func TestImageGroupTargetSwitchKeepsExactSourceAndRejectsOldDiscovery(t *testing.T) {
	m := chosen(t)
	defer m.Close()
	m.cfg.Apps.Include = []string{"Requested.Family"}
	oldLanguageGeneration, oldEditionGeneration := m.image.sourceGeneration, m.image.editionGeneration
	if text := rowText(m.imageRows(100, 24)); !strings.Contains(text, "amd64  arm64") || strings.Contains(text, "future") || strings.Contains(text, "x86") {
		t.Fatalf("Image targets escaped the selected version:\n%s", text)
	}
	m = send(m, key(tea.KeyDown, ""))
	m, cmd := step(m, key(' ', " "))
	if m.area != Image || m.cfg.Image.UpdateID != secondID || m.cfg.Image.Architecture != "arm64" || cmd == nil || !m.image.languageStatus.loading {
		t.Fatalf("target did not resolve the actual version member in Image: %+v", m.Snapshot())
	}
	if m.cfg.Image.Language != "" || len(m.cfg.Image.Editions) != 0 || len(m.image.languages) != 0 || len(m.image.editions) != 0 || m.Snapshot().ImageReady || m.Snapshot().AppsNotice == "" || !reflect.DeepEqual(m.cfg.Apps.Include, []string{"Requested.Family"}) {
		t.Fatal("version target change retained dependent choices or lost app intent")
	}
	m = send(m, languagesResultMsg{generation: oldLanguageGeneration, updateID: firstID, languages: []catalog.Language{{ID: "old"}}})
	m = send(m, editionsResultMsg{generation: oldEditionGeneration, updateID: firstID, language: "en-us", editions: []catalog.Edition{{ID: "old"}}})
	if len(m.image.languages) != 0 || len(m.image.editions) != 0 || !m.image.languageStatus.loading {
		t.Fatal("old exact source discovery validated the new version target")
	}
	result := cmd().(languagesResultMsg)
	if result.updateID != secondID || result.generation != m.image.sourceGeneration {
		t.Fatalf("target discovery requested wrong UUID/generation: %+v", result)
	}
	m = send(m, result)
	if len(m.image.languages) != 2 || m.image.languageStatus.loading || !strings.Contains(m.View().Content, secondID) {
		t.Fatal("new exact source discovery/summary did not become available")
	}
	if toml := strings.Join(m.tomlLines(100), "\n"); !strings.Contains(toml, secondID) || !strings.Contains(toml, "architecture = 'arm64'") {
		t.Fatalf("draft TOML lost the exact group target source:\n%s", toml)
	}
	if got := m.Architectures(); !reflect.DeepEqual(got, []model.Architecture{"amd64", "arm64", "future", "x86"}) {
		t.Fatalf("version target choices lost global target availability: %v", got)
	}
}

func TestBuildGroupExactUUIDFilterRetainsDuplicateRevisions(t *testing.T) {
	m := browse(t)
	defer m.Close()
	older := m.builds.records[0]
	older.UpdateID = "11111111-1111-1111-1111-111111111111_rev.1"
	m.builds.records = append(m.builds.records, older)
	for _, id := range []string{firstID, older.UpdateID, secondID} {
		m = send(m, NavigateMsg{Area: Builds})
		m.builds.filter.SetValue(id)
		if got := buildRowIDs(m.buildRows(110, 26)); !reflect.DeepEqual(got, []string{id}) {
			t.Fatalf("exact UUID filter hid revision %s: %v", id, got)
		}
		m, cmd := step(m, key(tea.KeyEnter, ""))
		if m.cfg.Image.UpdateID != id || cmd == nil {
			t.Fatalf("exact UUID filter selected another revision: %+v", m.cfg.Image)
		}
	}
	// With no exact-ID filter, selecting a version preserves the current UUID
	// when it is one of several revisions for the requested architecture.
	m = send(m, SelectBuildMsg{UpdateID: older.UpdateID})
	m = send(m, NavigateMsg{Area: Builds})
	m.builds.filter.SetValue("")
	m, cmd := step(m, key(tea.KeyEnter, ""))
	if m.cfg.Image.UpdateID != older.UpdateID || cmd != nil {
		t.Fatalf("version reselect silently replaced the exact requested revision: %+v", m.cfg.Image)
	}
}

func TestBuildGroupMouseChoosesExactArchitectureAfterResize(t *testing.T) {
	for _, width := range []int{120, 68, 40} {
		m := browse(t)
		defer m.Close()
		m = send(m, tea.WindowSizeMsg{Width: width, Height: 30})
		click := func(match func(tea.Msg) bool) tea.Cmd {
			t.Helper()
			_, hits := m.layout()
			for _, target := range hits {
				if match(target.msg) {
					var cmd tea.Cmd
					m, cmd = step(m, tea.MouseClickMsg{X: target.x, Y: target.y, Button: tea.MouseLeft})
					return cmd
				}
			}
			t.Fatalf("%d-column view has no matching current mouse target", width)
			return nil
		}
		cmd := click(func(msg tea.Msg) bool { b, ok := msg.(SelectBuildMsg); return ok && b.UpdateID == firstID })
		if m.cfg.Image.UpdateID != firstID || cmd == nil {
			t.Fatal("mouse did not choose the version's exact requested target")
		}
		m = send(m, cmd())
		m = send(m, tea.WindowSizeMsg{Width: width, Height: 24})
		clicked := false
		for y, line := range strings.Split(ansi.Strip(m.View().Content), "\n") {
			if x := strings.Index(line, "arm64"); x >= 0 {
				m, cmd = step(m, tea.MouseClickMsg{X: ansi.StringWidth(line[:x]), Y: y, Button: tea.MouseLeft})
				clicked = true
				break
			}
		}
		if !clicked {
			t.Fatalf("%d-column view hid the group's available architecture", width)
		}
		if m.area != Image || m.cfg.Image.UpdateID != secondID || m.image.archCursor != 1 || cmd == nil {
			t.Fatalf("mouse chose wrong version member after resize: %+v", m.cfg.Image)
		}
		if result := cmd().(languagesResultMsg); result.updateID != secondID {
			t.Fatalf("mouse requested language discovery for another UUID: %+v", result)
		}
	}
}

func TestBuildGroupRefreshKeepsFocusedVersionAndLoadedExactRevision(t *testing.T) {
	m := browse(t)
	defer m.Close()
	m.builds.cursor = 1 // Other source, rather than the second architecture.
	updated := records()
	updated = append(updated[2:], updated[:2]...)
	m = send(m, searchResultMsg{generation: m.builds.generation, query: m.builds.query, builds: updated})
	m, _ = step(m, key(tea.KeyEnter, ""))
	if m.cfg.Image.UpdateID != "33333333-3333-3333-3333-333333333333" || m.builds.cursor != 0 {
		t.Fatalf("refresh moved focus to a different version: %+v", m.cfg.Image)
	}
	// An initial/loaded exact UUID places focus on its version without choosing
	// another revision or losing the retained target and dependent requests.
	m = send(m, NavigateMsg{Area: Builds})
	m.builds.records = nil
	m.cfg.Image = model.Selection{UpdateID: secondID, Architecture: "arm64", Language: "en-us", Editions: []string{"core"}}
	m = send(m, searchResultMsg{generation: m.builds.generation, query: m.builds.query, builds: updated})
	if m.builds.cursor != 2 || m.source == nil || m.source.UpdateID != secondID || m.cfg.Image.Language != "en-us" || !reflect.DeepEqual(m.cfg.Image.Editions, []string{"core"}) {
		t.Fatalf("loaded exact selection/cursor changed during grouping: %+v", m.Snapshot())
	}
}

func TestBuildGroupMissingSourceRequiresExactReselection(t *testing.T) {
	for _, state := range []string{"missing source", "pending query", "different title"} {
		t.Run(state, func(t *testing.T) {
			m := chosen(t)
			defer m.Close()
			switch state {
			case "missing source":
				m.builds.records = m.builds.records[1:]
			case "pending query":
				m = send(m, SearchChangedMsg{Query: "other"})
				m = send(m, searchResultMsg{generation: m.builds.generation, query: "other", builds: records()[1:]})
			case "different title":
				m.builds.records[1].Title = "A different product"
			}
			m, cmd := step(m, ChangeArchitectureMsg{Architecture: "arm64"})
			if m.area != Builds || m.cfg.Image.UpdateID != "" || m.cfg.Image.Architecture != "arm64" || m.cfg.Image.Language != "" || len(m.cfg.Image.Editions) != 0 || m.source != nil || cmd != nil {
				t.Fatalf("target change invented a source instead of requiring reselection: %+v", m.Snapshot())
			}
		})
	}
}

func TestBuildGroupSelectionUsesRequestedTargetThenUpstreamOrder(t *testing.T) {
	for _, tc := range []struct {
		name, filter, wantID string
		requested, target    model.Architecture
	}{
		{name: "requested", requested: "amd64", wantID: "8f550c54-da87-45d3-89e3-0c03a6f16ae8"},
		{name: "target filter", requested: "amd64", target: "arm64", wantID: "e8706433-04f4-4a00-b58f-df8ed1bab586"},
		{name: "missing requested target", requested: "x86", wantID: "e8706433-04f4-4a00-b58f-df8ed1bab586"},
		{name: "no requested target", wantID: "e8706433-04f4-4a00-b58f-df8ed1bab586"},
		{name: "exact ID", requested: "amd64", filter: "e8706433-04f4-4a00-b58f-df8ed1bab586", wantID: "e8706433-04f4-4a00-b58f-df8ed1bab586"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := browse(t)
			defer m.Close()
			m.builds.records = versionRecords()
			m.builds.archFilter = tc.target
			m.builds.filter.SetValue(tc.filter)
			m.cfg.Image.Architecture = tc.requested
			m, cmd := step(m, key(tea.KeyEnter, ""))
			if m.cfg.Image.UpdateID != tc.wantID || cmd == nil || cmd().(languagesResultMsg).updateID != tc.wantID {
				t.Fatalf("group selection did not use the exact eligible source: %+v", m.cfg.Image)
			}
		})
	}
}

func TestBuildGroupUnknownTargetRemainsSelectable(t *testing.T) {
	m := browse(t)
	defer m.Close()
	future := m.builds.records[0]
	future.UpdateID, future.Architecture = "unknown-target-source", "future"
	m.builds.records = append(m.builds.records, future)
	m = send(m, key(tea.KeyEnter, ""))
	m = send(m, key(tea.KeyDown, ""))
	m = send(m, key(tea.KeyDown, ""))
	m, cmd := step(m, key(tea.KeyEnter, ""))
	if m.cfg.Image.UpdateID != "unknown-target-source" || m.cfg.Image.Architecture != "future" || m.area != Image || cmd == nil || cmd().(languagesResultMsg).updateID != "unknown-target-source" {
		t.Fatalf("unknown actual target was filtered or synthesized: %+v", m.cfg.Image)
	}
}
