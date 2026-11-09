package tui

import (
	"context"
	"errors"
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

func TestAppsHideSavedSelectionsUntilCatalogLoads(t *testing.T) {
	m := appsChosen(t)
	defer m.Close()
	m.cfg.Apps.Mode = model.AppsCustom
	m.cfg.Apps.Include = []string{"Example.App_pub"}
	m, cmd := step(m, NavigateMsg{Area: Apps})
	if view := ansi.Strip(m.View().Content); strings.Contains(view, "Example.App_pub") {
		t.Fatalf("loading picker exposed a saved selection:\n%s", view)
	}
	m = finishAppsLoad(t, m, cmd)
	if view := ansi.Strip(m.View().Content); !strings.Contains(view, "[x] Example.App_pub") {
		t.Fatalf("offered app did not recover its checkmark:\n%s", view)
	}
}

func TestAppsPruneSavedSelectionsAgainstCurrentOffers(t *testing.T) {
	m := appsChosen(t)
	defer m.Close()
	m.configActions.path = filepath.Join(t.TempDir(), "apps.toml")
	m.cfg.Apps.Mode = model.AppsCustom
	m.cfg.Apps.Include = []string{"Missing.App_pub", "Example.App_pub", "Example.Other_pub", "Example.Framework_pub", "Core.App_pub"}
	m.deps.AppCatalog = testAppCatalog{func(_ context.Context, s model.Selection) (source.AppCatalogSnapshot, error) {
		snapshot := appSnapshot(s)
		snapshot.Entries = append(snapshot.Entries, source.AppCatalogEntry{FeatureID: "Core.App_pub", Type: "MSIX", Editions: []source.AppEditionReference{{Edition: "core"}}})
		return snapshot, nil
	}}
	// The search hides an offered app, but must not remove its selection.
	m.apps.search.SetValue("Other")
	before := m.revision
	m, cmd := step(m, NavigateMsg{Area: Apps})
	m = finishAppsLoad(t, m, cmd)
	want := []string{"Example.App_pub", "Example.Other_pub"}
	if !reflect.DeepEqual(m.cfg.Apps.Include, want) || m.revision != before+1 {
		t.Fatalf("saved selections were not reconciled in the draft: %v (revision %d)", m.cfg.Apps.Include, m.revision)
	}
	m.apps.search.SetValue("")
	if choices := m.appChoices(); len(choices) != 2 {
		t.Fatalf("unavailable families remained selectable: %+v", choices)
	}
	m = finishConfigAction(t, m, SaveConfigMsg{})
	saved, err := config.Load(m.configActions.path)
	if err != nil || !reflect.DeepEqual(saved.Apps.Include, want) {
		t.Fatalf("saved selections = %v, err = %v", saved.Apps.Include, err)
	}
}

func TestAppsFailedLoadKeepsRequestsUntilEmptyCatalogIsConfirmed(t *testing.T) {
	m := appsChosen(t)
	defer m.Close()
	m.cfg.Apps.Mode = model.AppsCustom
	m.cfg.Apps.Include = []string{"Example.App_pub"}
	m.deps.AppCatalog = testAppCatalog{func(_ context.Context, s model.Selection) (source.AppCatalogSnapshot, error) {
		return appSnapshot(s), errors.New("catalog offline")
	}}
	before := m.revision
	m, cmd := step(m, NavigateMsg{Area: Apps})
	m = finishAppsLoad(t, m, cmd)
	if !reflect.DeepEqual(m.cfg.Apps.Include, []string{"Example.App_pub"}) || m.revision != before {
		t.Fatal("failed fetch changed the saved requests")
	}
	if view := ansi.Strip(m.View().Content); strings.Contains(view, "Example.App_pub") || !strings.Contains(view, "catalog offline") {
		t.Fatalf("failed fetch did not show just the error state:\n%s", view)
	}
	m.deps.AppCatalog = testAppCatalog{func(_ context.Context, s model.Selection) (source.AppCatalogSnapshot, error) {
		return source.AppCatalogSnapshot{Selection: s, State: source.AppCatalogAvailable}, nil
	}}
	m, cmd = step(m, RefreshMsg{})
	m = finishAppsLoad(t, m, cmd)
	if len(m.cfg.Apps.Include) != 0 || m.revision != before+1 {
		t.Fatal("confirmed empty catalog did not remove unavailable requests")
	}
}

func TestAppsCatalogCompletionDuringEditionRefreshReconcilesSelections(t *testing.T) {
	m := appsChosen(t)
	defer m.Close()
	m.cfg.Apps.Mode = model.AppsCustom
	m.cfg.Apps.Include = []string{"Missing.App_pub"}
	m, appsCmd := step(m, NavigateMsg{Area: Apps})
	m = send(m, NavigateMsg{Area: Image})
	m.image.focus = 2
	m, editionsCmd := step(m, RefreshMsg{})
	if m.imageReady() {
		t.Fatal("edition refresh did not start")
	}
	m = finishAppsLoad(t, m, appsCmd)
	m = send(m, editionsCmd())
	m = send(m, NavigateMsg{Area: Apps})
	if len(m.appChoices()) != 2 || len(m.cfg.Apps.Include) != 0 {
		t.Fatalf("catalog and saved requests diverged during edition refresh: %v", m.cfg.Apps.Include)
	}
}

func TestAppsLoadingBarAnimatesAndStops(t *testing.T) {
	m := appsChosen(t)
	defer m.Close()
	m = send(m, tea.WindowSizeMsg{Width: 40, Height: 14})
	m, cmd := step(m, NavigateMsg{Area: Apps})
	before := ansi.Strip(m.View().Content)
	batch := appLoadCommands(t, cmd)
	tick := batch[1]()
	m, next := step(m, tick)
	if after := ansi.Strip(m.View().Content); after == before || next == nil {
		t.Fatalf("loading animation did not advance in the short viewport:\n%s", after)
	}
	m, retry := step(m, RefreshMsg{})
	if _, next := step(m, tick); next != nil {
		t.Fatal("a superseded fetch tick continued animating")
	}
	batch = appLoadCommands(t, retry)
	m = send(m, batch[0]())
	if _, next := step(m, batch[1]()); next != nil || strings.Contains(ansi.Strip(m.View().Content), "Loading app metadata") {
		t.Fatal("animation survived catalog completion")
	}
}

func finishAppsLoad(t *testing.T, m Model, cmd tea.Cmd) Model {
	t.Helper()
	return send(m, appLoadCommands(t, cmd)[0]())
}

func appLoadCommands(t *testing.T, cmd tea.Cmd) tea.BatchMsg {
	t.Helper()
	if cmd == nil {
		t.Fatal("app load command missing")
	}
	batch, ok := cmd().(tea.BatchMsg)
	if !ok || len(batch) != 2 {
		t.Fatal("catalog fetch did not schedule a loading animation alongside the request")
	}
	return batch
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
	m = finishAppsLoad(t, m, cmd)
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
	m = finishAppsLoad(t, m, cmd)
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
	m = finishAppsLoad(t, m, old)
	if m.cfg.Apps.Mode != model.AppsNone || m.revision != revision || m.apps.status.loading {
		t.Fatal("metadata completion overwrote request edit or stuck loading")
	}
	m, old = step(m, RefreshMsg{})
	m = send(m, SelectLanguageMsg{Language: "de-de"})
	m = finishAppsLoad(t, m, old)
	if len(m.apps.snapshot.Entries) != 0 || m.apps.status.loading {
		t.Fatal("late old source result survived language invalidation")
	}
}

func TestAppsSearchMouseResizeAndPreferenceControls(t *testing.T) {
	m := appsChosen(t)
	m, cmd := step(m, NavigateMsg{Area: Apps})
	m = finishAppsLoad(t, m, cmd)
	m.apps.focus = 2
	m = send(m, key('/', "/"))
	m = send(m, tea.PasteMsg{Content: "Other"})
	m = send(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if len(m.appChoices()) != 1 || m.appChoices()[0].FeatureID != "Example.Other_pub" {
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
	m = finishAppsLoad(t, m, cmd)
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
	load := appLoadCommands(t, cmd)[0]
	go load()
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
	m = finishAppsLoad(t, m, cmd)
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
			m = finishAppsLoad(t, m, cmd)
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
	m = finishAppsLoad(t, m, cmd)
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
	load := appLoadCommands(t, cmd)[0]
	go func() { done <- load() }()
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
	if len(m.appChoices()) != 0 {
		t.Fatal("obsolete source left selectable app rows")
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
