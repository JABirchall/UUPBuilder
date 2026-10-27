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
