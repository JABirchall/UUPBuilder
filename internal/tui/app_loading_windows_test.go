package tui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"uupbuilder/internal/source"
)

func TestAppsForceRefreshRechecksNeutralEditions(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/listeditions.php" {
			t.Errorf("unexpected metadata request: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		calls++
		fmt.Fprint(w, `{"response":{"editionList":["PROFESSIONAL"]}}`)
	}))
	defer server.Close()
	m := appsChosen(t)
	defer m.Close()
	m.deps.AppCatalog = source.NewAppCatalog(server.URL)
	m, cmd := step(m, NavigateMsg{Area: Apps})
	m = send(m, cmd())
	m, cmd = step(m, RefreshMsg{})
	m = send(m, cmd())
	if calls != 2 || m.apps.status.err != nil {
		t.Fatalf("explicit refresh reused stale selector cache: calls=%d err=%v", calls, m.apps.status.err)
	}
}
