package tui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
)

func TestSelectionRejectsStaleLanguageAndEditionGenerations(t *testing.T) {
	m := browse(t)
	m, oldLanguage := step(m, SelectBuildMsg{UpdateID: firstID})
	m, currentLanguage := step(m, SelectBuildMsg{UpdateID: secondID})
	m = send(m, currentLanguage())
	m = send(m, oldLanguage())
	if m.cfg.Image.UpdateID != secondID || m.image.languageStatus.loading {
		t.Fatal("old source overwrote language state")
	}
	m, oldEdition := step(m, SelectLanguageMsg{Language: "en-us"})
	m, currentEdition := step(m, SelectLanguageMsg{Language: "de-de"})
	m = send(m, currentEdition())
	m = send(m, oldEdition())
	if m.cfg.Image.UpdateID != secondID || m.cfg.Image.Language != "de-de" || m.image.editionStatus.loading {
		t.Fatal("old language overwrote edition state")
	}
	m = send(m, ToggleEditionMsg{Edition: "core"})
	if !reflect.DeepEqual(m.cfg.Image.Editions, []string{"core"}) {
		t.Fatalf("new edition choices unavailable: %+v", m.cfg.Image)
	}
}

func TestSearchCommandIsBoundedAndCancelledOnQueryChange(t *testing.T) {
	started := make(chan context.Context, 1)
	finished := make(chan tea.Msg, 1)
	f := testCatalog{search: func(ctx context.Context, q string) ([]catalog.Build, error) {
		started <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	m := New(Dependencies{Catalog: f}, config.Defaults())
	m, cmd := step(m, m.Init()())
	go func() { finished <- cmd() }()
	var ctx context.Context
	select {
	case ctx = <-started:
	case <-time.After(time.Second):
		t.Fatal("search did not start")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 46*time.Second {
		t.Fatal("unbounded discovery command")
	}
	m = send(m, SearchChangedMsg{Query: "replacement"})
	select {
	case result := <-finished:
		m = send(m, result)
	case <-time.After(time.Second):
		t.Fatal("superseded search was not cancelled")
	}
	if m.builds.query != "replacement" || !m.builds.pending {
		t.Fatal("cancelled result replaced pending query")
	}
}

func TestWorkspaceRefreshBypassesRealCatalogCache(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprintf(w, `{"response":{"builds":[{"uuid":%q,"title":"Windows","build":"26100.1","arch":"amd64","created":100}]}}`, firstID)
	}))
	defer server.Close()
	m := New(Dependencies{Catalog: catalog.New(server.Client(), server.URL)}, config.Defaults())
	m, cmd := step(m, m.Init()())
	m = send(m, cmd())
	if len(m.builds.records) != 1 {
		t.Fatalf("real catalogue response not displayed: %s", m.View().Content)
	}
	m, cmd = step(m, RefreshMsg{})
	m = send(m, cmd())
	if requests.Load() != 2 {
		t.Fatalf("explicit refresh served cache; requests=%d", requests.Load())
	}
}

func TestWorkspaceStaleRetryAndSafeExternalText(t *testing.T) {
	bad := records()
	bad[0].Title = "Bad\x1b[2J\x1b]52;c;c2VjcmV0\x07title\r\nnew\u202etext"
	m := New(Dependencies{Catalog: testCatalog{search: func(context.Context, string) ([]catalog.Build, error) {
		return bad, &catalog.StaleError{FetchedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Err: errors.New("offline\x1b[2J\r\nretry")}
	}}}, config.Defaults())
	m, cmd := step(m, m.Init()())
	m = send(m, cmd())
	view := m.View().Content
	if strings.Contains(view, "\x1b[2J") || strings.Contains(view, "\x1b]52") || strings.Contains(view, "\u202e") {
		t.Fatal("external terminal controls were rendered")
	}
	if !strings.Contains(view, "Stale") || !strings.Contains(view, "2026-01-02") || !strings.Contains(view, "retry") {
		t.Fatalf("missing stale warning/retry: %s", view)
	}
	m, cmd = step(m, RefreshMsg{})
	if cmd == nil || !m.builds.status.loading {
		t.Fatal("retry did not request refresh")
	}
}

func TestSelectionLoadedRequestsAreCheckedAndSnapshotIsIndependent(t *testing.T) {
	cfg := config.Defaults()
	cfg.Image.UpdateID = firstID
	cfg.Image.Language = "missing"
	cfg.Apps.Include = []string{"Requested.Family"}
	m := New(Dependencies{Catalog: testCatalog{}}, cfg)
	m, cmd := step(m, m.Init()())
	// Initial source metadata is loaded without changing its UUID/revision.
	for _, msg := range runCommands(cmd) {
		m = send(m, msg)
	}
	if m.cfg.Image.UpdateID != firstID || m.cfg.Image.Language != "" || len(m.cfg.Image.Editions) != 0 || !strings.Contains(m.notice, "unavailable") {
		t.Fatalf("unavailable loaded language was retained silently: %+v", m.Snapshot())
	}
	snapshot := m.Snapshot()
	snapshot.Config.Apps.Include[0] = "changed"
	if m.cfg.Apps.Include[0] != "Requested.Family" || cfg.Apps.Include[0] != "Requested.Family" {
		t.Fatal("snapshot aliases caller/model settings")
	}
}

func runCommands(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		var out []tea.Msg
		for _, child := range batch {
			out = append(out, runCommands(child)...)
		}
		return out
	}
	return []tea.Msg{msg}
}

func TestSelectionFailedRefreshDoesNotClaimImageChoicesReady(t *testing.T) {
	m := chosen(t)
	m.deps.Catalog = testCatalog{languages: func(context.Context, string) ([]catalog.Language, error) {
		return nil, errors.New("service unavailable")
	}}
	m, cmd := step(m, RefreshMsg{})
	m = send(m, cmd())
	if m.Snapshot().ImageReady {
		t.Fatal("failed language refresh still claimed catalogue choices ready")
	}
	if !strings.Contains(m.View().Content, "Failed") {
		t.Fatal("failed refresh was hidden")
	}
}

func TestSelectionSavedSourceTargetMismatchInvalidatesSelectors(t *testing.T) {
	for _, order := range []string{"search-first", "language-first", "editions-first"} {
		t.Run(order, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Image.UpdateID = firstID
			cfg.Image.Architecture = model.ArchitectureARM64 // This exact UUID is amd64.
			cfg.Apps.Mode = model.AppsCustom
			cfg.Apps.Include = []string{"Requested.Family"}
			m := New(Dependencies{Catalog: testCatalog{}}, cfg)
			defer m.Close()
			m, cmd := step(m, m.Init()())
			var search searchResultMsg
			var language languagesResultMsg
			for _, result := range runCommands(cmd) {
				switch result := result.(type) {
				case searchResultMsg:
					search = result
				case languagesResultMsg:
					language = result
				}
			}
			var oldEdition tea.Msg
			if order != "search-first" {
				m, cmd = step(m, language)
				if cmd == nil {
					t.Fatal("saved language did not request editions")
				}
				oldEdition = cmd()
				if order == "editions-first" {
					m = send(m, oldEdition)
				}
			}
			revision := m.Snapshot().Revision
			m = send(m, search)
			snapshot := m.Snapshot()
			if snapshot.Config.Image.UpdateID != "" || snapshot.Config.Image.Language != "" || len(snapshot.Config.Image.Editions) != 0 || snapshot.ImageReady {
				t.Fatalf("known source/target mismatch retained a usable selection: %+v", snapshot.Config.Image)
			}
			if snapshot.Config.Image.Architecture != "arm64" || snapshot.HasCatalogRecord || snapshot.Revision <= revision {
				t.Fatalf("mismatch silently changed target/source or failed to revise the draft: %+v", snapshot)
			}
			if m.image.languageChecked || m.image.editionsChecked || len(m.image.languages) != 0 || len(m.image.editions) != 0 {
				t.Fatal("mismatch retained dependent selector data/validation")
			}
			for _, detail := range []string{firstID, "amd64", "arm64", "exact"} {
				if !strings.Contains(snapshot.Notice, detail) || !strings.Contains(m.View().Content, detail) {
					t.Errorf("mismatch notice lacks %q: %s", detail, snapshot.Notice)
				}
			}
			if snapshot.AppsApplicable || snapshot.AppsNotice == "" || !reflect.DeepEqual(snapshot.Config.Apps.Include, []string{"Requested.Family"}) {
				t.Fatal("mismatch lost app intent or its applicability invalidation")
			}
			m = send(m, NavigateMsg{Area: Image})
			m.image.focus = 2
			m = send(m, key(tea.KeyEnter, ""))
			if m.ActiveArea() != Image {
				t.Fatal("mismatched saved selection continued from Image")
			}

			// Reselect the same exact record, never the apparent arm64 sibling.
			m, cmd = step(m, SelectBuildMsg{UpdateID: firstID})
			currentLanguage := cmd()
			if order == "search-first" {
				var next tea.Cmd
				m, next = step(m, language)
				if next != nil || !m.image.languageStatus.loading || len(m.image.languages) != 0 {
					t.Fatal("late old language response validated the reselected UUID")
				}
			}
			m = send(m, currentLanguage)
			m, cmd = step(m, SelectLanguageMsg{Language: "en-us"})
			if cmd == nil {
				t.Fatal("reselected source did not request current editions")
			}
			if order == "language-first" {
				m = send(m, oldEdition)
				if !m.image.editionStatus.loading || m.image.editionsChecked || len(m.image.editions) != 0 {
					t.Fatal("late old edition response validated the reselected UUID/language")
				}
			}
			m = send(m, cmd())
			m = send(m, ToggleEditionMsg{Edition: "professional"})
			if got := m.Snapshot(); !got.ImageReady || got.Config.Image.UpdateID != firstID || got.Config.Image.Architecture != "amd64" {
				t.Fatalf("explicit exact-record reselection did not recover: %+v", got.Config.Image)
			}
		})
	}
}

func TestSelectionLoadedChoicesWaitForExactSourceTargetValidation(t *testing.T) {
	for _, arch := range []model.Architecture{"amd64", "arm64"} {
		t.Run(string(arch), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Image.UpdateID, cfg.Image.Architecture = firstID, arch
			m := New(Dependencies{Catalog: testCatalog{}}, cfg)
			defer m.Close()
			m, cmd := step(m, m.Init()())
			var search tea.Msg
			for _, msg := range runCommands(cmd) {
				if _, ok := msg.(searchResultMsg); ok {
					search = msg
					continue
				}
				m, cmd = step(m, msg)
				for _, edition := range runCommands(cmd) {
					m = send(m, edition)
				}
			}
			if !m.image.languageChecked || !m.image.editionsChecked {
				t.Fatal("fixture did not receive saved language and edition validation before Search")
			}
			if snapshot := m.Snapshot(); snapshot.ImageReady || snapshot.HasCatalogRecord {
				t.Errorf("loaded choices became ready before exact source/target validation: %+v", snapshot)
			}
			m = send(m, NavigateMsg{Area: Image})
			m.image.focus = 2
			m, cmd = step(m, key(tea.KeyEnter, ""))
			if m.ActiveArea() != Image || cmd != nil {
				t.Error("Enter continued before the saved source target was checked")
			}
			m = send(m, search)
			if arch == "amd64" {
				if snapshot := m.Snapshot(); !snapshot.ImageReady || !snapshot.HasCatalogRecord || snapshot.Source.UpdateID != firstID || snapshot.Source.Architecture != arch {
					t.Fatalf("matching exact record did not validate the saved choices: %+v", snapshot)
				}
			} else if snapshot := m.Snapshot(); snapshot.ImageReady || snapshot.HasCatalogRecord || snapshot.Config.Image.UpdateID != "" {
				t.Fatalf("source/target mismatch restored the invalid selection: %+v", snapshot)
			}
		})
	}
}
