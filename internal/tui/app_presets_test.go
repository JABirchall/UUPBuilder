package tui

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
	"uupbuilder/internal/source"
)

// These regressions exercise real Workspace actions. Ignoring the current
// source/edition binding, reapplying a saved preset, or conflating metadata
// arrival with a draft edit must lose one of the literal assertions below.
func TestAppPresetsUseCurrentSource(t *testing.T) {
	m := appsChosen(t)
	defer m.Close()
	m, cmd := step(m, NavigateMsg{Area: Apps})
	before := m.revision
	m = send(m, key('a', "a"))
	if m.revision != before || m.cfg.Apps.Preset != "" {
		t.Fatal("unexamined metadata allowed All offered")
	}
	m = send(m, cmd())
	m.apps.snapshot.Entries = []source.AppCatalogEntry{
		{FeatureID: "Z.Main_pub", Type: "MSIXBundle", Editions: []source.AppEditionReference{{Edition: "PROFESSIONAL"}}},
		{FeatureID: "A.Main_pub", Type: "MSIX", Editions: []source.AppEditionReference{{Edition: "professional"}, {Edition: "core"}}},
		{FeatureID: "A.Main_pub", Type: "MSIX", Editions: []source.AppEditionReference{{Edition: "professional"}}},
		{FeatureID: "Framework_pub", Type: "MSIXFramework", Editions: []source.AppEditionReference{{Edition: "professional"}}},
		{FeatureID: "Other.Edition_pub", Type: "MSIX", Editions: []source.AppEditionReference{{Edition: "core"}}},
		{FeatureID: "Unreferenced_pub", Type: "MSIX"},
	}
	// Applying All offered covers the full snapshot, regardless of local search.
	m.apps.search.SetValue("Z.Main")
	m = send(m, key('a', "a"))
	want := model.AppSettings{Mode: model.AppsCustom, Preset: "all-offered", StubPolicy: model.AppStubAuto, Edge: model.EdgeDefault, Include: []string{"A.Main_pub", "Z.Main_pub"}}
	if !reflect.DeepEqual(m.cfg.Apps, want) || m.revision != before+1 || m.Snapshot().AppsApplicable {
		t.Fatalf("All offered did not materialize source-only requests once: apps=%+v revision=%d", m.cfg.Apps, m.revision)
	}
	m = send(m, key('a', "a"))
	if m.revision != before+1 {
		t.Fatal("identical preset application increments draft revision")
	}
	m.apps.search.SetValue("")
	if len(m.appChoices()) != 2 {
		t.Fatalf("duplicate or other-edition rows remain selectable: %+v", m.appChoices())
	}
	// A refreshed source supplies a different list; it must not reapply intent.
	m, cmd = step(m, RefreshMsg{})
	m = send(m, cmd())
	if !reflect.DeepEqual(m.cfg.Apps, want) || m.revision != before+1 {
		t.Fatal("source refresh automatically reapplied preset or edited the draft")
	}
	for _, mutate := range []struct {
		name  string
		apply func(*Model)
	}{
		{"deferred", func(m *Model) { m.apps.snapshot.State = source.AppCatalogDeferred }},
		{"stale selection", func(m *Model) { m.apps.snapshot.Selection.Language = "de-de" }},
		{"unchecked source", func(m *Model) { m.image.sourceChecked = false }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			copy := m
			mutate.apply(&copy)
			copy = send(copy, key('a', "a"))
			if !reflect.DeepEqual(copy.cfg.Apps, want) || copy.revision != before+1 {
				t.Fatal("All offered applied without a current examined source")
			}
		})
	}
}

func TestAppRequestsSurviveDeferredInventory(t *testing.T) {
	m := appsChosen(t)
	defer m.Close()
	m.cfg.Apps = model.AppSettings{Mode: model.AppsCustom, Preset: "saved-unknown-preset", StubPolicy: model.AppFull, Edge: model.EdgeDefault, Include: []string{"Unknown.Family_pub"}}
	m, cmd := step(m, NavigateMsg{Area: Apps})
	msg := cmd().(appsResultMsg)
	msg.snapshot.State = source.AppCatalogDeferred
	msg.snapshot.Entries = nil
	msg.snapshot.Gaps = []string{"Legacy source lacks selected-edition app metadata; unexamined."}
	m = send(m, msg)
	want := m.cfg.Apps
	before := m.revision
	view := ansi.Strip(m.View().Content)
	for _, text := range []string{"saved-unknown-preset", "unresolved", "Unknown.Family_pub", "Legacy source"} {
		if !strings.Contains(view, text) {
			t.Errorf("deferred inventory hides %q: %s", text, view)
		}
	}
	m = send(m, key('a', "a"))
	m = send(m, tea.KeyPressMsg{Code: 'a', Mod: tea.ModCtrl})
	if !reflect.DeepEqual(m.cfg.Apps, want) || m.revision != before {
		t.Fatal("unavailable bulk controls replaced retained requests")
	}
	for _, mode := range []model.AppMode{model.AppsNone, model.AppsDefault, model.AppsCustom} {
		m = send(m, appModeMsg{mode: mode})
		before++
		want.Mode = mode
		if !reflect.DeepEqual(m.cfg.Apps, want) || m.revision != before {
			t.Fatal("mode change discarded retained requests/preset or has wrong revision")
		}
	}
	m = send(m, appStubMsg{policy: model.AppStub})
	before++
	want.StubPolicy = model.AppStub
	if !reflect.DeepEqual(m.cfg.Apps, want) || m.revision != before {
		t.Fatal("stub preference changed saved requests")
	}
	// Metadata completion is source observation, never request application.
	msg.snapshot = appSnapshot(m.cfg.Image)
	msg.checkedAt = time.Now()
	m = send(m, msg)
	if !reflect.DeepEqual(m.cfg.Apps, want) || m.revision != before {
		t.Fatal("examined metadata reinterpreted an unknown saved preset")
	}
	m = send(m, appToggleMsg{featureID: "Unknown.Family_pub"})
	if len(m.cfg.Apps.Include) != 0 || m.cfg.Apps.Preset != "" || m.revision != before+1 {
		t.Fatal("individual edit did not remove unresolved request and stale preset")
	}
}

func TestAppSelectAllAndPresetInteractions(t *testing.T) {
	m := appsChosen(t)
	defer m.Close()
	m, cmd := step(m, NavigateMsg{Area: Apps})
	m = send(m, cmd())
	m.cfg.Apps.Include = []string{"Unavailable.Family_pub"}
	before := m.revision
	m = send(m, key('/', "/"))
	m = send(m, tea.PasteMsg{Content: "Other"})
	m = send(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.revision != before {
		t.Fatal("search edited requested values")
	}
	selectAll := tea.KeyPressMsg{Code: 'a', Mod: tea.ModCtrl}
	m = send(m, selectAll)
	if m.cfg.Apps.Mode != model.AppsCustom || !reflect.DeepEqual(m.cfg.Apps.Include, []string{"Unavailable.Family_pub", "Example.Other_pub"}) || m.revision != before+1 {
		t.Fatalf("select all did not preserve hidden requests and select visible rows: %+v", m.cfg.Apps)
	}
	m = send(m, selectAll)
	if !reflect.DeepEqual(m.cfg.Apps.Include, []string{"Unavailable.Family_pub"}) || m.revision != before+2 {
		t.Fatal("second select all did not deselect visible offered rows only")
	}
	m = send(m, key('a', "a"))
	if m.cfg.Apps.Preset != "all-offered" || !reflect.DeepEqual(m.cfg.Apps.Include, []string{"Example.App_pub", "Example.Other_pub"}) || m.revision != before+3 {
		t.Fatal("preset was limited by search or retained an explicitly replaced request")
	}
	m = send(m, selectAll)
	if m.cfg.Apps.Preset != "" || !reflect.DeepEqual(m.cfg.Apps.Include, []string{"Example.App_pub"}) || m.revision != before+4 {
		t.Fatal("bulk edit failed to clear preset or changed hidden request")
	}
	m = send(m, appToggleMsg{featureID: "Example.Other_pub"})
	if m.revision != before+5 || !reflect.DeepEqual(m.cfg.Apps.Include, []string{"Example.App_pub", "Example.Other_pub"}) {
		t.Fatal("individual request did not restore requested family once")
	}
}

func TestAppModesRoundTripTOML(t *testing.T) {
	for _, mode := range []model.AppMode{model.AppsDefault, model.AppsCustom, model.AppsNone} {
		for _, stub := range []model.AppStubPolicy{model.AppStubAuto, model.AppStub, model.AppFull} {
			t.Run(string(mode)+"/"+string(stub), func(t *testing.T) {
				m := appsChosen(t)
				defer m.Close()
				m.configActions.path = filepath.Join(t.TempDir(), "requests.toml")
				m, cmd := step(m, NavigateMsg{Area: Apps})
				m = send(m, cmd())
				m = send(m, key('a', "a"))
				m = send(m, appModeMsg{mode: mode})
				m = send(m, appStubMsg{policy: stub})
				want := model.AppSettings{Mode: mode, Preset: "all-offered", StubPolicy: stub, Edge: model.EdgeDefault, Include: []string{"Example.App_pub", "Example.Other_pub"}}
				m = send(m, tea.KeyPressMsg{Code: tea.KeyEnter})
				if m.area != Conversion {
					t.Fatal("app list did not continue to Conversion")
				}
				m = finishConfigAction(t, m, SaveConfigMsg{})
				saved, err := config.Load(m.configActions.path)
				if err != nil || !reflect.DeepEqual(saved.Apps, want) {
					t.Fatalf("saved requests differ: %+v err=%v", saved.Apps, err)
				}
				m.cfg.Apps.Include = nil
				m = finishConfigAction(t, m, LoadConfigMsg{})
				if !reflect.DeepEqual(m.Snapshot().Config.Apps, want) || m.Snapshot().AppsApplicable || m.Snapshot().ImageReady {
					t.Fatal("reload lost exact requests or invented validation")
				}
			})
		}
	}
}

func TestAppPresetMouseAndKeyboardControls(t *testing.T) {
	for _, size := range []tea.WindowSizeMsg{{Width: 120, Height: 32}, {Width: 68, Height: 24}, {Width: 40, Height: 14}} {
		m := appsChosen(t)
		m, cmd := step(m, NavigateMsg{Area: Apps})
		m = send(m, cmd())
		m = send(m, size)
		// Mode, stub and list retain their focus indices; the preset follows
		// the list and stays visible when focused.
		m = send(m, tea.KeyPressMsg{Code: tea.KeyTab})
		_, focusedHits := m.layout()
		presetVisible := false
		for _, hit := range focusedHits {
			if action, ok := hit.msg.(appControlMsg); ok && action.field == 3 {
				presetVisible = true
			}
		}
		if !presetVisible {
			t.Fatalf("focused preset hidden at %dx%d", size.Width, size.Height)
		}
		before := m.revision
		m = send(m, key(' ', " "))
		if m.cfg.Apps.Preset != "all-offered" || m.revision != before+1 {
			t.Fatalf("keyboard preset control unreachable at %dx%d", size.Width, size.Height)
		}
		m = send(m, tea.KeyPressMsg{Code: tea.KeyTab})
		if m.apps.focus != 0 {
			t.Fatal("preset Tab does not continue to mode")
		}
		m = send(m, key('/', "/"))
		// The mouse applies the same preset and transfers keyboard focus.
		_, hits := m.layout()
		found := false
		for _, hit := range hits {
			if action, ok := hit.msg.(appControlMsg); ok && action.field == 3 {
				m = send(m, tea.MouseClickMsg{Button: tea.MouseLeft, X: hit.x, Y: hit.y})
				found = true
				break
			}
		}
		if size.Height >= 24 && !found {
			t.Fatal("visible preset has no mouse hit region")
		}
		if found && (m.apps.search.Focused() || m.apps.focus != 3 || m.revision != before+1) {
			t.Fatal("mouse preset lost focus or edited an identical request")
		}
		m.Close()
	}
}
