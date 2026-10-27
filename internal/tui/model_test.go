package tui

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
)

const firstID = "11111111-1111-1111-1111-111111111111_rev.2"
const secondID = "22222222-2222-2222-2222-222222222222_rev.9"

func records() []catalog.Build {
	return []catalog.Build{
		{UpdateID: firstID, Title: "Windows example", Build: "26100.1", Architecture: "amd64", CreatedAt: time.Unix(100, 0)},
		{UpdateID: secondID, Title: "Windows example", Build: "26100.1", Architecture: "arm64", CreatedAt: time.Unix(100, 0)},
		{UpdateID: "33333333-3333-3333-3333-333333333333", Title: "Other source", Build: "19045.1", Architecture: "x86", CreatedAt: time.Unix(90, 0)},
		{UpdateID: "44444444-4444-4444-4444-444444444444", Title: "Future source", Build: "1", Architecture: "future", CreatedAt: time.Unix(80, 0)},
	}
}

// Only network discovery is replaced. The real root model, commands, selection
// validation and Charm rendering are exercised by every workflow test.
type testCatalog struct {
	search    func(context.Context, string) ([]catalog.Build, error)
	languages func(context.Context, string) ([]catalog.Language, error)
	editions  func(context.Context, string, string) ([]catalog.Edition, error)
}

func (f testCatalog) Search(ctx context.Context, q string) ([]catalog.Build, error) {
	if f.search != nil {
		return f.search(ctx, q)
	}
	return records(), nil
}
func (f testCatalog) Languages(ctx context.Context, id string) ([]catalog.Language, error) {
	if f.languages != nil {
		return f.languages(ctx, id)
	}
	return []catalog.Language{{ID: "en-us", Name: "English"}, {ID: "de-de", Name: "German"}}, nil
}
func (f testCatalog) Editions(ctx context.Context, id, lang string) ([]catalog.Edition, error) {
	if f.editions != nil {
		return f.editions(ctx, id, lang)
	}
	return []catalog.Edition{{ID: "professional", Name: "Pro"}, {ID: "core", Name: "Home"}}, nil
}
func step(m Model, msg tea.Msg) (Model, tea.Cmd) {
	updated, cmd := m.Update(msg)
	return updated.(Model), cmd
}
func send(m Model, msg tea.Msg) Model            { updated, _ := step(m, msg); return updated }
func key(code rune, text string) tea.KeyPressMsg { return tea.KeyPressMsg{Code: code, Text: text} }
func browse(t *testing.T) Model {
	t.Helper()
	m := New(Dependencies{Catalog: testCatalog{}}, config.Defaults())
	m, cmd := step(m, m.Init()())
	m = send(m, cmd())
	return m
}
func chosen(t *testing.T) Model {
	t.Helper()
	m := browse(t)
	m, cmd := step(m, SelectBuildMsg{UpdateID: firstID})
	m = send(m, cmd())
	m, cmd = step(m, SelectLanguageMsg{Language: "en-us"})
	m = send(m, cmd())
	return send(m, ToggleEditionMsg{Edition: "professional"})
}

func TestWorkspaceHasSixPersistentAreas(t *testing.T) {
	m := browse(t)
	for _, area := range []Area{Builds, Image, Apps, Conversion, Review, Progress} {
		m = send(m, NavigateMsg{Area: area})
		view := m.View().Content
		for _, name := range []string{"Builds", "Image", "Apps", "Conversion", "Review", "Progress"} {
			if !strings.Contains(view, name) {
				t.Errorf("%v view lacks persistent %s navigation", area, name)
			}
		}
		if !strings.Contains(view, "Source:") || !strings.Contains(view, "esc") {
			t.Errorf("missing summary/footer: %s", view)
		}
	}
}

func TestSearchDebouncesAndIgnoresStaleResponse(t *testing.T) {
	m := browse(t)
	m, oldTick := step(m, SearchChangedMsg{Query: "old"})
	oldGeneration := m.builds.generation
	m, newTick := step(m, SearchChangedMsg{Query: "new"})
	if !m.builds.pending {
		t.Fatal("query was not debounced")
	}
	_, cmd := step(m, oldTick())
	if cmd != nil {
		t.Fatal("obsolete debounce initiated network IO")
	}
	m, cmd = step(m, newTick())
	if cmd == nil {
		t.Fatal("latest debounce did not search")
	}
	m = send(m, cmd())
	m = send(m, searchResultMsg{generation: oldGeneration, query: "old", builds: []catalog.Build{{UpdateID: "old"}}})
	if m.builds.query != "new" || len(m.builds.records) != 4 || m.builds.records[0].UpdateID != firstID {
		t.Fatalf("stale result replaced current query/results: %+v", m.builds)
	}
	// A result already queued before a new debounce is stale immediately.
	m = send(m, SearchChangedMsg{Query: "newer"})
	m = send(m, searchResultMsg{generation: oldGeneration + 1, query: "new", builds: records()})
	if len(m.builds.records) != 0 {
		t.Fatal("old rows selectable while a newer query is pending")
	}
}

func TestArchitectureChoicesIndependentOfHost(t *testing.T) {
	for _, host := range []model.Architecture{"x86", "amd64", "arm64"} {
		m := New(Dependencies{Catalog: testCatalog{}, Host: model.Host{NativeArchitecture: host}}, config.Defaults())
		m, cmd := step(m, m.Init()())
		m = send(m, cmd())
		if got := m.Architectures(); !reflect.DeepEqual(got, []model.Architecture{"amd64", "arm64", "future", "x86"}) {
			t.Errorf("host %s filtered targets: %v", host, got)
		}
	}
}

func TestSameBuildNumberDoesNotInventGrouping(t *testing.T) {
	m := browse(t)
	if len(m.builds.visible()) != 4 {
		t.Fatal("distinct records were grouped by build number")
	}
	m = send(m, SelectBuildMsg{UpdateID: secondID})
	if got := m.Snapshot().Config.Image; got.UpdateID != secondID || got.Architecture != "arm64" {
		t.Fatalf("wrong exact record: %+v", got)
	}
}

func TestArchitectureChangeUsesProvenSiblingOrRequiresReselect(t *testing.T) {
	m := chosen(t)
	revision := m.Snapshot().Revision
	m = send(m, ChangeArchitectureMsg{Architecture: "arm64"})
	s := m.Snapshot()
	if s.Config.Image.UpdateID != "" || s.Config.Image.Language != "" || len(s.Config.Image.Editions) != 0 {
		t.Fatalf("architecture guessed a sibling or retained dependent selection: %+v", s)
	}
	if s.Revision <= revision || !strings.Contains(strings.ToLower(s.Notice), "exact") {
		t.Fatalf("missing explicit invalidation: %+v", s)
	}
	m = send(m, SelectBuildMsg{UpdateID: secondID})
	if m.Snapshot().Config.Image.UpdateID != secondID {
		t.Fatal("exact record selection lost revision")
	}
}

func TestSelectionChangeInvalidatesEditionsAndApps(t *testing.T) {
	m := chosen(t)
	m.cfg.Apps.Mode = model.AppsCustom
	m.cfg.Apps.Include = []string{"Requested.Family"}
	rev := m.Snapshot().Revision
	m = send(m, SelectLanguageMsg{Language: "de-de"})
	s := m.Snapshot()
	if s.Config.Image.Language != "de-de" || len(s.Config.Image.Editions) != 0 || s.AppsApplicable || s.Revision <= rev {
		t.Fatalf("language did not invalidate dependencies: %+v", s)
	}
	if !reflect.DeepEqual(s.Config.Apps.Include, []string{"Requested.Family"}) {
		t.Fatal("explicit app requests were silently dropped")
	}
	m = send(m, SelectBuildMsg{UpdateID: secondID})
	if got := m.Snapshot().Config.Image; got.Language != "" || len(got.Editions) != 0 {
		t.Fatalf("new source retained dependencies: %+v", got)
	}
}

func TestKeyboardSearchSpaceEnterEscapeHelp(t *testing.T) {
	m := browse(t)
	m = send(m, key('/', "/"))
	if !m.builds.search.Focused() {
		t.Fatal("/ did not focus upstream search")
	}
	m = send(m, key('w', "w"))
	if m.builds.query != "w" {
		t.Fatal("search typing lost")
	}
	m = send(m, key(tea.KeyEsc, ""))
	if m.builds.search.Focused() {
		t.Fatal("esc did not leave search")
	}
	m = browse(t)
	m, cmd := step(m, key(tea.KeyEnter, ""))
	m = send(m, cmd())
	if m.ActiveArea() != Image || m.Snapshot().Config.Image.UpdateID != firstID {
		t.Fatal("enter did not select current build")
	}
	// Image focus begins with architecture; tab moves to language, enter chooses.
	m = send(m, key(tea.KeyTab, ""))
	m, cmd = step(m, key(tea.KeyEnter, ""))
	m = send(m, cmd())
	m = send(m, key(tea.KeyTab, ""))
	m = send(m, key(' ', " "))
	if !reflect.DeepEqual(m.Snapshot().Config.Image.Editions, []string{"professional"}) {
		t.Fatal("space did not toggle edition")
	}
	m = send(m, key('?', "?"))
	if !strings.Contains(m.View().Content, "Keyboard help") {
		t.Fatal("help not visible")
	}
	m = send(m, key(tea.KeyEsc, ""))
	if m.showHelp {
		t.Fatal("esc did not dismiss help")
	}
	m = send(m, key(tea.KeyEsc, ""))
	if m.ActiveArea() != Builds {
		t.Fatal("esc did not go back")
	}
}

func TestNavigationDoesNotChangeJobState(t *testing.T) {
	m := chosen(t)
	before := m.Snapshot()
	// Job events have a separate future owner. Browsing cannot turn an observed
	// event into a lifecycle action or fabricate a controller/progress state.
	event := model.Event{JobID: "independent-job", StageID: "download", Kind: model.EventStage, Message: "downloading"}
	m = send(m, event)
	for _, area := range []Area{Progress, Builds, Review, Apps, Conversion, Image} {
		var cmd tea.Cmd
		m, cmd = step(m, NavigateMsg{Area: area})
		if cmd != nil {
			t.Fatal("navigation emitted work/job command")
		}
	}
	if !reflect.DeepEqual(before, m.Snapshot()) {
		t.Fatal("navigation changed the draft")
	}
	if strings.Contains(m.View().Content, "%") {
		t.Fatal("invented progress")
	}
}

func TestKeyboardPastedSearchUsesDebounceAndLocalFilter(t *testing.T) {
	m := browse(t)
	m = send(m, key('/', "/"))
	m = send(m, tea.PasteMsg{Content: "Windows 11"})
	if m.builds.query != "Windows 11" || !m.builds.pending {
		t.Fatal("bracketed paste did not update/debounce search")
	}
	m = browse(t)
	m = send(m, key('f', "f"))
	m = send(m, tea.PasteMsg{Content: "Future"})
	if visible := m.builds.visible(); len(visible) != 1 || visible[0].Architecture != "future" {
		t.Fatalf("local paste filter lost: %+v", visible)
	}
}

func TestSelectionAppInvalidationRemainsVisibleAfterValidationNotice(t *testing.T) {
	m := chosen(t)
	m.cfg.Apps.Mode = model.AppsCustom
	m.cfg.Apps.Include = []string{"Requested.Family"}
	m = send(m, SelectLanguageMsg{Language: "de-de"})
	m.image.focus = 2
	m = send(m, key(tea.KeyEnter, ""))
	if !strings.Contains(strings.ToLower(m.View().Content), "apps: unchecked") {
		t.Fatalf("app invalidation disappeared behind another notice: %s", m.View().Content)
	}
}

func TestSelectionUnavailableSavedEditionStaysVisibleAndBlocksContinuation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Image.UpdateID = firstID
	cfg.Image.Editions = []string{"unavailable"}
	m := New(Dependencies{Catalog: testCatalog{}}, cfg)
	m, cmd := step(m, m.Init()())
	for _, msg := range runCommands(cmd) {
		var next tea.Cmd
		m, next = step(m, msg)
		for _, result := range runCommands(next) {
			m = send(m, result)
		}
	}
	m = send(m, NavigateMsg{Area: Image})
	m.image.focus = 2
	if m.Snapshot().ImageReady || !reflect.DeepEqual(m.cfg.Image.Editions, []string{"unavailable"}) || !strings.Contains(m.View().Content, "! unavailable") {
		t.Fatalf("unavailable edition silently lost or accepted: %s", m.View().Content)
	}
	m = send(m, key(tea.KeyEnter, ""))
	if m.ActiveArea() != Image {
		t.Fatal("unavailable selection continued")
	}
	m = send(m, ToggleEditionMsg{Edition: "unavailable"})
	m = send(m, ToggleEditionMsg{Edition: "core"})
	if !m.Snapshot().ImageReady {
		t.Fatal("corrected available selection not ready")
	}
}
