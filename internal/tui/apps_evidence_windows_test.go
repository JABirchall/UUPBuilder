package tui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/config"
	"uupbuilder/internal/source"
)

func TestAppsAuthenticMetadataCommandToggleSaveLoad(t *testing.T) {
	root := os.Getenv("UUPBUILDER_APP_RESEARCH_DIR")
	if root == "" {
		t.Skip("opt-in retained evidence, never a product resource")
	}
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cab := read("latest-aggregated-metadata.cab")
	app := read("latest-neutral-app-nolinks.json")
	selected := read("latest-en-gb-professional-nolinks.json")
	editions := read("latest-neutral-listeditions.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cab":
			w.Write(cab)
		case r.URL.Path == "/listeditions.php":
			w.Write(editions)
		case r.URL.Query().Get("lang") == "neutral":
			w.Write(app)
		case r.URL.Query().Get("noLinks") == "1":
			w.Write(selected)
		default:
			var envelope map[string]any
			if json.Unmarshal(selected, &envelope) != nil {
				t.Error("invalid evidence")
				return
			}
			files := envelope["response"].(map[string]any)["files"].(map[string]any)
			for name, file := range files {
				if strings.Contains(strings.ToLower(name), "aggregatedmetadata") {
					file.(map[string]any)["url"] = "http://" + r.Host + "/cab"
					file.(map[string]any)["expire"] = 0
				}
			}
			json.NewEncoder(w).Encode(envelope)
		}
	}))
	defer server.Close()
	const id = "8f550c54-da87-45d3-89e3-0c03a6f16ae8"
	cfg := config.Defaults()
	cfg.Catalog.Endpoint = server.URL
	m := New(Dependencies{ConfigPath: filepath.Join(t.TempDir(), "actual-app-requests.toml"), AppCatalog: source.NewAppCatalog(server.URL), Catalog: testCatalog{
		search: func(context.Context, string) ([]catalog.Build, error) {
			return []catalog.Build{{UpdateID: id, Title: "Windows 11, version 26H1", Build: "28000.3365", Architecture: "amd64"}}, nil
		},
		languages: func(context.Context, string) ([]catalog.Language, error) {
			return []catalog.Language{{ID: "en-gb", Name: "English UK"}}, nil
		},
		editions: func(context.Context, string, string) ([]catalog.Edition, error) {
			return []catalog.Edition{{ID: "PROFESSIONAL", Name: "Pro"}}, nil
		},
	}}, cfg)
	defer m.Close()
	m, cmd := step(m, m.Init()())
	m = send(m, cmd())
	m, cmd = step(m, SelectBuildMsg{UpdateID: id})
	m = send(m, cmd())
	m, cmd = step(m, SelectLanguageMsg{Language: "en-gb"})
	m = send(m, cmd())
	m = send(m, ToggleEditionMsg{Edition: "PROFESSIONAL"})
	m, cmd = step(m, NavigateMsg{Area: Apps})
	if cmd == nil {
		t.Fatal("missing real app catalogue command")
	}
	m = send(m, cmd())
	if len(m.appChoices()) != 50 {
		t.Fatalf("actual edition choices=%d state=%+v", len(m.appChoices()), m.apps.status)
	}
	const requested = "Microsoft.WindowsNotepad_8wekyb3d8bbwe"
	m = send(m, key('/', "/"))
	m = send(m, tea.PasteMsg{Content: "WindowsNotepad"})
	m = send(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = send(m, key(' ', " "))
	if !reflect.DeepEqual(m.cfg.Apps.Include, []string{requested}) {
		t.Fatalf("raw source FeatureID lost: %v", m.cfg.Apps.Include)
	}
	m = finishConfigAction(t, m, SaveConfigMsg{})
	saved, err := config.Load(m.configActions.path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved.Apps, m.cfg.Apps) {
		t.Fatal("actual source app request failed TOML round-trip")
	}
	m = send(m, appModeMsg{mode: "none"})
	m = finishConfigAction(t, m, LoadConfigMsg{})
	if !reflect.DeepEqual(m.cfg.Apps.Include, []string{requested}) || m.cfg.Apps.Mode != "custom" {
		t.Fatal("load lost actual app request")
	}
	t.Logf("actual model command → 50 choices → Space %s → TOML/save/load; app applicability remains %v", requested, m.Snapshot().AppsApplicable)
}
