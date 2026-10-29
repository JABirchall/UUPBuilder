package tui

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"uupbuilder/internal/config"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/source"
)

type testAppCatalog struct {
	load func(context.Context, model.Selection) (source.AppCatalogSnapshot, error)
}

func (f testAppCatalog) Load(ctx context.Context, s model.Selection) (source.AppCatalogSnapshot, error) {
	return f.load(ctx, s)
}
func appSnapshot(s model.Selection) source.AppCatalogSnapshot {
	return source.AppCatalogSnapshot{Selection: s, State: source.AppCatalogAvailable, Entries: []source.AppCatalogEntry{{FeatureID: "Example.App_pub", Type: "MSIXBundle", Editions: []source.AppEditionReference{{Edition: "professional", Type: "MediaCreationRequired"}}}, {FeatureID: "Example.Other_pub", Type: "MSIX", Editions: []source.AppEditionReference{{Edition: "professional", Type: "Optional"}}}, {FeatureID: "Example.Framework_pub", Type: "MSIXFramework"}}, Gaps: []string{"Manifest and provisioning applicability pending."}}
}
func appsChosen(t *testing.T) Model {
	t.Helper()
	m := chosen(t)
	m.deps.AppCatalog = testAppCatalog{func(_ context.Context, s model.Selection) (source.AppCatalogSnapshot, error) {
		return appSnapshot(s), nil
	}}
	return m
}

func TestAppsMultiEditionLoadSurvivesPacing(t *testing.T) {
	m := appsChosen(t)
	defer m.Close()
	m.deps.AppCatalog = testAppCatalog{func(ctx context.Context, s model.Selection) (source.AppCatalogSnapshot, error) {
		if deadline, ok := ctx.Deadline(); ok {
			t.Fatalf("whole-load deadline %v can expire during valid multi-edition pacing", time.Until(deadline))
		}
		return appSnapshot(s), nil
	}}
	m, cmd := step(m, NavigateMsg{Area: Apps})
	if cmd == nil {
		t.Fatal("app load absent")
	}
	m = send(m, cmd())
	if m.apps.status.err != nil || len(m.appChoices()) != 2 {
		t.Fatalf("app load failed: %v", m.apps.status.err)
	}
}

func TestAppsCommandToggleTOMLSaveLoadRoundTrip(t *testing.T) {
	m := appsChosen(t)
	m.configActions.path = filepath.Join(t.TempDir(), "apps.toml")
	before := m.revision
	m, cmd := step(m, NavigateMsg{Area: Apps})
	if cmd == nil {
		t.Fatal("entering Apps did not load actual source rows")
	}
	m = send(m, cmd())
	if len(m.appChoices()) != 2 || m.revision != before || m.Snapshot().AppsApplicable {
		t.Fatalf("metadata was treated as app edit/applicability: %+v", m.Snapshot())
	}
	m.apps.focus = 2
	m = send(m, key(' ', " "))
	if m.cfg.Apps.Mode != model.AppsCustom || !reflect.DeepEqual(m.cfg.Apps.Include, []string{"Example.App_pub"}) || m.revision != before+1 {
		t.Fatalf("Space did not persist exact FeatureID: %+v", m.cfg.Apps)
	}
	m = send(m, viewTOMLMsg{})
	if !strings.Contains(m.View().Content, "Read-only draft TOML") {
		t.Fatal("TOML preview unavailable")
	}
	m = send(m, viewTOMLMsg{})
	m = finishConfigAction(t, m, SaveConfigMsg{})
	saved, err := config.Load(m.configActions.path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved.Apps, m.cfg.Apps) {
		t.Fatalf("saved requests changed: %+v", saved.Apps)
	}
	m = send(m, appModeMsg{mode: model.AppsNone})
	m = finishConfigAction(t, m, LoadConfigMsg{})
	if m.cfg.Apps.Mode != model.AppsCustom || !reflect.DeepEqual(m.cfg.Apps.Include, []string{"Example.App_pub"}) {
		t.Fatalf("load lost request: %+v", m.cfg.Apps)
	}
}

func TestAppsPendingLoadPreservesEditsAndRejectsObsoleteSelection(t *testing.T) {
	m := appsChosen(t)
	m, old := step(m, NavigateMsg{Area: Apps})
	if old == nil {
		t.Fatal("load absent")
	}
	m = send(m, appModeMsg{mode: model.AppsNone})
	revision := m.revision
	m = send(m, old())
	if m.cfg.Apps.Mode != model.AppsNone || m.revision != revision || m.apps.status.loading {
		t.Fatal("metadata completion overwrote request edit or stuck loading")
	}
	m, old = step(m, RefreshMsg{})
	m = send(m, SelectLanguageMsg{Language: "de-de"})
	m = send(m, old())
	if len(m.apps.snapshot.Entries) != 0 || m.apps.status.loading {
		t.Fatal("late old source result survived language invalidation")
	}
	// Requests absent from a new source remain visible and removable.
	m.cfg.Apps.Mode = model.AppsCustom
	m.cfg.Apps.Include = []string{"Unavailable.Family_pub"}
	m = send(m, appToggleMsg{featureID: "Unavailable.Family_pub"})
	if len(m.cfg.Apps.Include) != 0 {
		t.Fatal("unresolved request cannot be removed")
	}
}

func TestAppsSearchMouseResizeAndPreferenceControls(t *testing.T) {
	m := appsChosen(t)
	m, cmd := step(m, NavigateMsg{Area: Apps})
	m = send(m, cmd())
	m.apps.focus = 2
	m = send(m, key('/', "/"))
	m = send(m, tea.PasteMsg{Content: "Other"})
	m = send(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if len(m.appChoices()) != 1 || m.appChoices()[0].featureID != "Example.Other_pub" {
		t.Fatalf("search did not filter: %+v", m.appChoices())
	}
	for _, size := range []tea.WindowSizeMsg{{Width: 110, Height: 30}, {Width: 74, Height: 22}, {Width: 49, Height: 18}} {
		m = send(m, size)
		_, hits := m.layout()
		found := false
		for _, h := range hits {
			if msg, ok := h.msg.(appToggleMsg); ok && msg.featureID == "Example.Other_pub" {
				m = send(m, tea.MouseClickMsg{Button: tea.MouseLeft, X: h.x, Y: h.y})
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("actual app checkbox missing at %dx%d: %s", size.Width, size.Height, ansi.Strip(m.View().Content))
		}
	}
	before := m.revision
	m = send(m, appModeMsg{mode: m.cfg.Apps.Mode})
	if m.revision != before {
		t.Fatal("no-op mode increments draft")
	}
	m = send(m, appModeMsg{mode: model.AppsDefault})
	m = send(m, appStubMsg{policy: model.AppFull})
	if m.cfg.Apps.Mode != model.AppsDefault || m.cfg.Apps.StubPolicy != model.AppFull {
		t.Fatal("preference controls disconnected")
	}
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, "pending") && !strings.Contains(view, "unchecked") {
		t.Fatal("short screen lost applicability gap")
	}
}

func TestAppsFocusedSearchSurvivesShortViewport(t *testing.T) {
	m := appsChosen(t)
	m, cmd := step(m, NavigateMsg{Area: Apps})
	m = send(m, cmd())
	m = send(m, tea.WindowSizeMsg{Width: 40, Height: 14})
	m = send(m, key('/', "/"))
	m = send(m, tea.PasteMsg{Content: "Other"})
	_, hits := m.layout()
	visible := false
	for _, h := range hits {
		if _, ok := h.msg.(appSearchMsg); ok {
			visible = true
		}
	}
	if !visible || !strings.Contains(ansi.Strip(m.View().Content), "Other") {
		t.Fatalf("focused app search hidden in short viewport: %s", ansi.Strip(m.View().Content))
	}
}

func TestAppsCloseCancelsActiveLoadAndNilLoaderIsUseful(t *testing.T) {
	m := chosen(t)
	m = send(m, NavigateMsg{Area: Apps})
	if !strings.Contains(ansi.Strip(m.View().Content), "unavailable") {
		t.Fatal("missing loader hid useful state")
	}
	started, stopped := make(chan struct{}), make(chan struct{})
	m = appsChosen(t)
	m.deps.AppCatalog = testAppCatalog{func(ctx context.Context, s model.Selection) (source.AppCatalogSnapshot, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return source.AppCatalogSnapshot{}, ctx.Err()
	}}
	m, cmd := step(m, NavigateMsg{Area: Apps})
	go cmd()
	<-started
	m.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel app metadata")
	}
}

func TestAppsMouseFocusesClickedFamily(t *testing.T) {
	m := appsChosen(t)
	m, cmd := step(m, NavigateMsg{Area: Apps})
	m = send(m, cmd())
	_, hits := m.layout()
	for _, h := range hits {
		if msg, ok := h.msg.(appToggleMsg); ok && msg.featureID == "Example.Other_pub" {
			m = send(m, tea.MouseClickMsg{Button: tea.MouseLeft, X: h.x, Y: h.y})
			break
		}
	}
	if m.apps.cursor != 1 || !reflect.DeepEqual(m.cfg.Apps.Include, []string{"Example.Other_pub"}) {
		t.Fatalf("mouse did not focus actual clicked family: cursor=%d requests=%v", m.apps.cursor, m.cfg.Apps.Include)
	}
}

func TestAppsClickTransfersSearchFocusToCheckboxOrPreference(t *testing.T) {
	for _, target := range []string{"checkbox", "mode", "stub"} {
		t.Run(target, func(t *testing.T) {
			m := appsChosen(t)
			m, cmd := step(m, NavigateMsg{Area: Apps})
			m = send(m, cmd())
			m = send(m, key('/', "/"))
			m = send(m, tea.PasteMsg{Content: "Example."})
			_, hits := m.layout()
			clicked := false
			for _, h := range hits {
				match := false
				switch msg := h.msg.(type) {
				case appToggleMsg:
					match = target == "checkbox" && msg.featureID == "Example.Other_pub"
				case appControlMsg:
					match = target == "mode" && msg.field == 0 || target == "stub" && msg.field == 1
				}
				if match {
					m = send(m, tea.MouseClickMsg{Button: tea.MouseLeft, X: h.x, Y: h.y})
					clicked = true
					break
				}
			}
			if !clicked {
				t.Fatal("target has no current visible hit region")
			}
			if m.apps.search.Focused() || m.editing() {
				t.Fatalf("clicking %s left search owning keyboard focus", target)
			}
			m = send(m, key(' ', " "))
			if m.apps.search.Value() != "Example." {
				t.Fatal("Space edited search after a control click")
			}
			switch target {
			case "checkbox":
				if len(m.cfg.Apps.Include) != 0 {
					t.Fatal("Space did not toggle clicked family back off")
				}
				m = send(m, tea.KeyPressMsg{Code: tea.KeyEnter})
				if m.area != Conversion {
					t.Fatal("Enter remained in search instead of continuing")
				}
			case "mode":
				if m.cfg.Apps.Mode != model.AppsNone {
					t.Fatalf("Space did not activate focused mode after click: %s", m.cfg.Apps.Mode)
				}
				m = send(m, tea.KeyPressMsg{Code: tea.KeyTab})
				if m.apps.focus != 1 {
					t.Fatal("Tab remained in search instead of next preference")
				}
			case "stub":
				if m.cfg.Apps.StubPolicy != model.AppFull {
					t.Fatalf("Space did not activate focused stub preference: %s", m.cfg.Apps.StubPolicy)
				}
				m = send(m, tea.KeyPressMsg{Code: tea.KeyTab})
				if m.apps.focus != 2 {
					t.Fatal("Tab remained in search instead of family list")
				}
			}
		})
	}
}

func TestAppsDetailsShowSourceDependencyAndLicenseMismatch(t *testing.T) {
	m := appsChosen(t)
	m, cmd := step(m, NavigateMsg{Area: Apps})
	m = send(m, cmd())
	m.apps.snapshot.Entries[0].Dependencies = []metadata.AppFeatureDependency{{FeatureID: "Example.Framework_pub", Type: "Required"}}
	m.apps.snapshot.Entries[0].Licenses = []metadata.AppLicenseObservation{{PFM: "Different.Family_pub", FamilyMatchesIgnoringCase: false}}
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, "Example.Framework_pub") || !strings.Contains(view, "Different.Family_pub") {
		t.Fatalf("source dependency/license mismatch invisible: %s", view)
	}
}

func TestAppsSelectionChangeCancelsQueuedLoad(t *testing.T) {
	m := appsChosen(t)
	m.cfg.Apps.Mode = model.AppsCustom
	m.cfg.Apps.Include = []string{"Unavailable.Family_pub"}
	started, stopped := make(chan struct{}), make(chan struct{})
	m.deps.AppCatalog = testAppCatalog{func(ctx context.Context, s model.Selection) (source.AppCatalogSnapshot, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return appSnapshot(s), nil
	}}
	m, cmd := step(m, NavigateMsg{Area: Apps})
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	<-started
	m = send(m, ToggleEditionMsg{Edition: "professional"})
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("source selection did not cancel metadata")
	}
	m = send(m, <-done)
	if len(m.apps.snapshot.Entries) != 0 || !reflect.DeepEqual(m.cfg.Apps.Include, []string{"Unavailable.Family_pub"}) {
		t.Fatal("late source replaced retained requests")
	}
	rows := m.appChoices()
	if len(rows) != 1 || rows[0].entry != nil {
		t.Fatal("unresolved source request disappeared")
	}
}

func TestConfigEndpointRejectsFixedAppLoaderBeforeDraftReplacement(t *testing.T) {
	m := appsChosen(t)
	path := filepath.Join(t.TempDir(), "other.toml")
	cfg := config.Defaults()
	cfg.Catalog.Endpoint = "https://other.example"
	if _, err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	m.configActions.path = path
	m.deps.CatalogFactory = func(string) Catalog { return testCatalog{} }
	before := m.Snapshot()
	m = finishConfigAction(t, m, LoadConfigMsg{})
	if !reflect.DeepEqual(before.Config, m.cfg) || m.revision != before.Revision || !strings.Contains(m.notice, "app") {
		t.Fatalf("fixed loader silently retained on endpoint change: %+v", m.Snapshot())
	}
}
