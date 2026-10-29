package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
)

func finishConfigAction(t *testing.T, m Model, msg any) Model {
	t.Helper()
	m, cmd := step(m, msg)
	if cmd == nil {
		t.Fatal("config action did not run")
	}
	return send(m, cmd())
}

func TestConfigLoadEndpointChangeUsesMatchingProducer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new-endpoint.toml")
	cfg := config.Defaults()
	cfg.Catalog.Endpoint = "https://other-catalog.example"
	if _, err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	old := testCatalog{}
	newCalls := 0
	var requestedEndpoint string
	m := New(Dependencies{Catalog: old, ConfigPath: path, CatalogFactory: func(endpoint string) Catalog {
		requestedEndpoint = endpoint
		return testCatalog{search: func(context.Context, string) ([]catalog.Build, error) {
			newCalls++
			return []catalog.Build{{UpdateID: "new-producer", Title: "New source"}}, nil
		}}
	}}, config.Defaults())
	m, initialSearch := step(m, m.Init()())
	oldResult := initialSearch()
	m, load := step(m, LoadConfigMsg{})
	m, newSearch := step(m, load())
	if requestedEndpoint != "https://other-catalog.example" || newSearch == nil {
		t.Fatalf("endpoint not recomposed: %q", requestedEndpoint)
	}
	m = send(m, oldResult)
	if len(m.builds.records) != 0 {
		t.Fatal("old producer response survived load")
	}
	m = send(m, newSearch())
	if newCalls != 1 || len(m.builds.records) != 1 || m.builds.records[0].UpdateID != "new-producer" {
		t.Fatalf("new endpoint producer not used: %d %+v", newCalls, m.builds.records)
	}
}

func TestConfigEndpointChangeRejectsFixedOrMissingProducer(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "new-endpoint.toml")
			cfg := config.Defaults()
			cfg.Catalog.Endpoint = "https://other.example"
			if _, err := config.Save(path, cfg); err != nil {
				t.Fatal(err)
			}
			deps := Dependencies{Catalog: testCatalog{}, ConfigPath: path}
			if missing {
				deps.CatalogFactory = func(string) Catalog { return nil }
			}
			m := New(deps, config.Defaults())
			before := m.Snapshot()
			m = finishConfigAction(t, m, LoadConfigMsg{})
			if !reflect.DeepEqual(before.Config, m.cfg) || m.revision != before.Revision || m.configActions.path != before.ConfigPath || !strings.Contains(m.notice, "catalog.endpoint") {
				t.Fatalf("failed composition changed draft: %+v", m.Snapshot())
			}
		})
	}
}

func TestConfigLoadCancelsObsoleteDiscovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if _, err := config.Save(path, config.Defaults()); err != nil {
		t.Fatal(err)
	}
	started, stopped := make(chan struct{}), make(chan struct{})
	m := New(Dependencies{ConfigPath: path, Catalog: testCatalog{search: func(ctx context.Context, _ string) ([]catalog.Build, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	}}}, config.Defaults())
	t.Cleanup(m.Close)
	m, search := step(m, m.Init()())
	go search()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("search never started")
	}
	m = finishConfigAction(t, m, LoadConfigMsg{})
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("load did not cancel obsolete discovery")
	}
}

func TestConfigPendingLoadCannotOverwriteEditedPathOrSettings(t *testing.T) {
	for _, editPath := range []bool{false, true} {
		t.Run(fmt.Sprint(editPath), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			cfg := config.Defaults()
			cfg.Downloads.Retries = 2
			if _, err := config.Save(path, cfg); err != nil {
				t.Fatal(err)
			}
			m := New(Dependencies{Catalog: testCatalog{}, ConfigPath: path}, config.Defaults())
			m, load := step(m, LoadConfigMsg{})
			if editPath {
				m = send(m, ConfigPathChangedMsg{Path: path + ".new"})
			} else {
				m = send(m, ConversionFieldChangedMsg{Key: "downloads.retries", Value: "8"})
			}
			before := m.Snapshot()
			m = send(m, load())
			if !reflect.DeepEqual(before.Config, m.cfg) || m.revision != before.Revision || m.configActions.path != before.ConfigPath || !strings.Contains(m.notice, "discarded") {
				t.Fatalf("late load changed draft: %+v", m.Snapshot())
			}
		})
	}
}

func TestConfigFilesystemSaveFailureRetainsDraft(t *testing.T) {
	root := t.TempDir()
	blocked := filepath.Join(root, "file")
	if err := os.WriteFile(blocked, []byte("regular file"), 0600); err != nil {
		t.Fatal(err)
	}
	m := New(Dependencies{Catalog: testCatalog{}, ConfigPath: filepath.Join(blocked, "config.toml")}, config.Defaults())
	before := m.Snapshot()
	m = finishConfigAction(t, m, SaveConfigMsg{})
	if !reflect.DeepEqual(before.Config, m.cfg) || m.revision != before.Revision || m.configActions.path != before.ConfigPath || !strings.Contains(m.notice, "Save failed") {
		t.Fatalf("I/O failure changed draft: %+v", m.Snapshot())
	}
}

func TestConfigLoadFailureRetainsDraft(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.toml")
	if err := os.WriteFile(path, []byte("schema_version = 1\n[downloads]\nretries = 'wrong'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := browse(t)
	m = send(m, ConfigPathChangedMsg{Path: path})
	before := m.Snapshot()
	m = finishConfigAction(t, m, LoadConfigMsg{})
	after := m.Snapshot()
	if !reflect.DeepEqual(after.Config, before.Config) || after.Revision != before.Revision || after.ConfigPath != before.ConfigPath {
		t.Fatalf("failed load changed draft: before=%+v after=%+v", before, after)
	}
	if !strings.Contains(m.notice, "bad.toml") || !strings.Contains(m.notice, "retries") {
		t.Fatal(m.notice)
	}
}

func TestSaveReportsBackupAndNormalization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	original := []byte("# keep exact backup\nschema_version = 1\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	m := New(Dependencies{Catalog: testCatalog{}, ConfigPath: path}, config.Defaults())
	m = finishConfigAction(t, m, SaveConfigMsg{})
	if !strings.Contains(m.notice, "Normalized") || !strings.Contains(m.notice, ".bak-") {
		t.Fatalf("save result hidden: %s", m.notice)
	}
	if !m.configActions.lastSave.Normalized || m.configActions.lastSave.BackupPath == "" {
		t.Fatal("missing typed save result")
	}
	backup, err := os.ReadFile(m.configActions.lastSave.BackupPath)
	if err != nil || string(backup) != string(original) {
		t.Fatalf("backup not preserved: %s, %v", backup, err)
	}
	loaded, err := config.Load(path)
	if err != nil || loaded.Downloads.ParallelFiles != 4 || loaded.Downloads.Retries != 5 || loaded.Output.SplitSizeMiB != 3800 {
		t.Fatalf("saved defaults changed: %+v %v", loaded, err)
	}
}

func TestSaveBackupPathVisibleInCompactView(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(path, []byte("schema_version = 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := New(Dependencies{Catalog: testCatalog{}, ConfigPath: path}, config.Defaults())
	m = send(m, NavigateMsg{Area: Conversion})
	m = send(m, tea.WindowSizeMsg{Width: 68, Height: 24})
	m = finishConfigAction(t, m, SaveConfigMsg{})
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, "settings.toml.bak-") {
		t.Fatalf("actual backup path hidden by save notice truncation:\n%s", view)
	}
}

func TestSaveNarrowViewKeepsSelectedActionVisible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(path, []byte("schema_version = 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := New(Dependencies{Catalog: testCatalog{}, ConfigPath: path}, config.Defaults())
	m = send(m, NavigateMsg{Area: Conversion})
	m.conversion.cursor = 2
	m = finishConfigAction(t, m, SaveConfigMsg{})
	m = send(m, tea.WindowSizeMsg{Width: 40, Height: 20})
	if view := ansi.Strip(m.View().Content); !strings.Contains(view, "> TOML | Save") {
		t.Fatalf("save result pushed selected action out of narrow view:\n%s", view)
	}
}

func TestConfigLoadOutcomesRemainVisibleInCompactViews(t *testing.T) {
	for _, outcome := range []string{"failed", "stale"} {
		t.Run(outcome, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.toml")
			if outcome == "stale" {
				if err := os.WriteFile(path, []byte("schema_version = 1\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			m := New(Dependencies{Catalog: testCatalog{}, ConfigPath: path}, config.Defaults())
			m = send(m, NavigateMsg{Area: Conversion})
			m.conversion.cursor = 1
			m, load := step(m, LoadConfigMsg{})
			result := load()
			want := "Load failed:"
			if outcome == "stale" {
				m = send(m, ConversionFieldChangedMsg{Key: "downloads.retries", Value: "8"})
				want = "Load discarded:"
			}
			m = send(m, result)
			if !strings.HasPrefix(m.notice, want) {
				t.Fatalf("test did not produce the expected outcome: %q", m.notice)
			}
			for _, size := range [][2]int{{68, 24}, {40, 16}, {68, 20}} {
				m = send(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
				view := ansi.Strip(m.View().Content)
				if !strings.Contains(view, want) || !strings.Contains(view, "> TOML | Load") {
					t.Fatalf("%v: config outcome or focused action hidden:\n%s", size, view)
				}
				if len(strings.Split(view, "\n")) > size[1] {
					t.Fatal("config feedback overflows the viewport height")
				}
				for _, line := range strings.Split(view, "\n") {
					if ansi.StringWidth(line) > size[0] {
						t.Fatal("config feedback overflows the viewport width")
					}
				}
			}
		})
	}
}

func TestConfigPathChangeInvalidatesReviewedDraft(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "new", "config.toml")
	m := chosen(t)
	before := m.Snapshot().Revision
	m = send(m, ConfigPathChangedMsg{Path: path})
	if m.revision <= before || m.Snapshot().ConfigPath != path {
		t.Fatalf("path did not invalidate draft: %+v", m.Snapshot())
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("path editing created save directory")
	}
	m = finishConfigAction(t, m, SaveConfigMsg{})
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("actual save did not create selected directory: %v", err)
	}
}

func TestConfigSaveFailureRetainsDraftAndDoesNotCreateDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "config.toml")
	m := browse(t)
	m = send(m, ConfigPathChangedMsg{Path: path})
	m = send(m, ConversionFieldChangedMsg{Key: "downloads.retries", Value: "-1"})
	before := m.Snapshot()
	m, cmd := step(m, SaveConfigMsg{})
	if cmd != nil {
		m = send(m, cmd())
	}
	if m.revision != before.Revision || m.Snapshot().ConfigPath != path || !reflect.DeepEqual(m.cfg, before.Config) {
		t.Fatal("failed save changed requested draft")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("validation failure created directory")
	}
	if !strings.Contains(m.notice, "retries") {
		t.Fatal(m.notice)
	}
}

func TestConfigSuccessfulLoadInvalidatesImageAndOldResponses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := config.Defaults()
	cfg.Image.UpdateID = secondID
	cfg.Downloads.ParallelFiles = 7
	if _, err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	m := chosen(t)
	m = send(m, ConfigPathChangedMsg{Path: path})
	before := m.revision
	m, cmd := step(m, LoadConfigMsg{})
	result := cmd()
	m = send(m, result)
	if m.revision <= before || m.cfg.Image.UpdateID != secondID || m.cfg.Downloads.ParallelFiles != 7 || m.Snapshot().ImageReady || m.source != nil {
		t.Fatalf("load did not invalidate browsing state: %+v", m.Snapshot())
	}
	m = send(m, ConversionFieldChangedMsg{Key: "downloads.retries", Value: "8"})
	m = send(m, result)
	if m.cfg.Downloads.Retries != 8 {
		t.Fatal("late load result overwrote newer draft")
	}
}

func TestConfigEndpointReloadRejectsOldSelectorsForSameExactSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint.toml")
	cfg := config.Defaults()
	cfg.Image.UpdateID = firstID
	cfg.Image.Editions = []string{"core", "professional"}
	cfg.Apps.Include = []string{"Requested.Family"}
	cfg.Catalog.Endpoint = "https://new-catalog.example"
	if _, err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	old := testCatalog{}
	current := testCatalog{
		languages: func(context.Context, string) ([]catalog.Language, error) {
			return []catalog.Language{{ID: "en-us", Name: "Current English"}}, nil
		},
		editions: func(context.Context, string, string) ([]catalog.Edition, error) {
			return []catalog.Edition{{ID: "core", Name: "Current Home"}, {ID: "professional", Name: "Current Pro"}}, nil
		},
	}
	m := New(Dependencies{ConfigPath: path, Catalog: old, CatalogFactory: func(string) Catalog { return current }}, config.Defaults())
	defer m.Close()
	m, cmd := step(m, m.Init()())
	oldSearch := cmd()
	m = send(m, oldSearch)
	m, cmd = step(m, SelectBuildMsg{UpdateID: firstID})
	oldLanguages := cmd()
	m = send(m, oldLanguages)
	m, cmd = step(m, SelectLanguageMsg{Language: "en-us"})
	oldEditions := cmd()
	m = send(m, oldEditions)
	m = send(m, ToggleEditionMsg{Edition: "professional"})
	before := m.Snapshot().Revision
	m, cmd = step(m, LoadConfigMsg{})
	m, cmd = step(m, cmd())
	currentResults := runCommands(cmd)
	if snapshot := m.Snapshot(); snapshot.ImageReady || snapshot.HasCatalogRecord || snapshot.Revision <= before || snapshot.Config.Image.UpdateID != firstID {
		t.Fatalf("endpoint reload did not invalidate the same UUID's old validation: %+v", snapshot)
	}
	for _, result := range []tea.Msg{oldSearch, oldLanguages, oldEditions} {
		m = send(m, result)
	}
	if m.source != nil || len(m.builds.records) != 0 || len(m.image.languages) != 0 || len(m.image.editions) != 0 || m.Snapshot().ImageReady {
		t.Fatal("old endpoint results restored selectors before replacement discovery")
	}
	// The loaded language/editions are still requests. Receiving their lists
	// before the new build list must not validate the old endpoint's record.
	for _, result := range currentResults {
		if _, ok := result.(languagesResultMsg); !ok {
			continue
		}
		m, cmd = step(m, result)
		for _, edition := range runCommands(cmd) {
			m = send(m, edition)
		}
	}
	if m.Snapshot().ImageReady {
		t.Error("new endpoint choices reused the old endpoint's source validation")
	}
	for _, result := range currentResults {
		if _, ok := result.(searchResultMsg); ok {
			m = send(m, result)
		}
	}
	for _, result := range []tea.Msg{oldSearch, oldLanguages, oldEditions} {
		m = send(m, result)
	}
	snapshot := m.Snapshot()
	if !snapshot.ImageReady || !snapshot.HasCatalogRecord || snapshot.Source.UpdateID != firstID || snapshot.Source.Architecture != model.ArchitectureAMD64 || snapshot.Source.Language != "en-us" {
		t.Fatalf("new endpoint's exact selection was not validated: %+v", snapshot)
	}
	if m.image.languages[0].Name != "Current English" || m.image.editions[0].Name != "Current Home" || !reflect.DeepEqual(snapshot.Config.Image.Editions, []string{"core", "professional"}) {
		t.Fatal("late old endpoint selectors replaced the current lists or changed edition intent")
	}
	if snapshot.AppsApplicable || snapshot.AppsNotice == "" || !reflect.DeepEqual(snapshot.Config.Apps.Include, []string{"Requested.Family"}) {
		t.Fatal("endpoint reload lost requested app intent or its applicability invalidation")
	}
}
