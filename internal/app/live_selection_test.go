//go:build liveapi

package app

import (
	"context"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
	"uupbuilder/internal/tui"
)

// This opt-in acceptance test runs the real startup/config boundary, Workspace
// commands, catalogue client, keys, mouse hit testing and Charm rendering.
// Requests and cases are sequential. It never requests files or signed links.
func TestLiveLaunchBuildsImageSelection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	t.Setenv("LOCALAPPDATA", t.TempDir())
	client := catalog.New(nil, "")
	client.RequestTimeout = 15 * time.Second
	discovery := &selectionCatalog{Client: client}
	var startup Options
	if err := run(ctx, nil, func(_ context.Context, opts Options) error {
		startup = opts
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	newWorkspace := func(host model.Architecture, arch model.Architecture) tui.Model {
		cfg := startup.Config
		cfg.Image.Architecture = arch
		m := tui.New(tui.Dependencies{Context: ctx, ConfigPath: startup.ConfigPath, Catalog: discovery, Host: model.Host{NativeArchitecture: host}}, cfg)
		t.Cleanup(m.Close)
		return selectionStep(m, m.Init()())
	}
	initial := newWorkspace(model.ArchitectureFromGo(runtime.GOARCH), model.ArchitectureAMD64)
	if len(discovery.builds) == 0 {
		t.Fatalf("live launch returned no build records: %s", ansi.Strip(initial.View().Content))
	}
	groups := make(map[string][]catalog.Build)
	var ordered []string
	for _, b := range discovery.builds {
		key := b.Title + "\x00" + b.Build
		if _, ok := groups[key]; !ok {
			ordered = append(ordered, key)
		}
		groups[key] = append(groups[key], b)
	}
	var targets []catalog.Build
	for _, key := range ordered {
		group := groups[key]
		amd64 := slices.IndexFunc(group, func(b catalog.Build) bool { return b.Architecture == "amd64" })
		arm64 := slices.IndexFunc(group, func(b catalog.Build) bool { return b.Architecture == "arm64" })
		if amd64 >= 0 && arm64 >= 0 {
			targets = append(targets, group[amd64], group[arm64])
			break
		}
	}
	for _, b := range discovery.builds {
		if b.Architecture == "x86" {
			targets = append(targets, b)
			break
		}
	}
	if len(targets) != 3 {
		t.Fatal("live catalogue lacks an amd64/arm64 version pair or an x86 source; acceptance unverified")
	}
	t.Logf("UTC=%s origin=%s process=%s/%s builds=%d grouped_versions=%d; discovery only, no get.php", time.Now().UTC().Format(time.RFC3339), catalog.DefaultBaseURL, runtime.GOOS, runtime.GOARCH, len(discovery.builds), len(groups))
	for _, target := range targets {
		group := groups[target.Title+"\x00"+target.Build]
		start := target
		for _, b := range group {
			if b.Architecture != target.Architecture {
				start = b
				break
			}
		}
		for _, host := range []model.Architecture{"x86", "amd64", "arm64"} {
			for _, input := range []string{"enter", "space", "mouse"} {
				t.Run(string(host)+"_to_"+string(target.Architecture)+"_"+input, func(t *testing.T) {
					m := newWorkspace(host, start.Architecture)
					available := m.Architectures()
					for _, advertised := range discovery.builds {
						if !slices.Contains(available, advertised.Architecture) {
							t.Fatalf("host %s hid advertised target %s", host, advertised.Architecture)
						}
					}
					m = selectionStep(m, tea.WindowSizeMsg{Width: 120, Height: 32})
					m = selectionStep(m, selectionKey('f', "f"))
					m = selectionStep(m, tea.PasteMsg{Content: start.UpdateID})
					m = selectionStep(m, selectionKey(tea.KeyEsc, ""))
					if input == "mouse" {
						m = selectionClick(t, m, start.UpdateID)
					} else {
						m = selectionStep(m, selectionKey(tea.KeyEnter, ""))
					}
					if got := m.Snapshot().Config.Image; got.UpdateID != start.UpdateID || got.Architecture != start.Architecture || m.ActiveArea() != tui.Image {
						t.Fatalf("grouped Builds selected a different exact source: %+v", got)
					}
					var arches []model.Architecture
					for _, b := range group {
						if !slices.Contains(arches, b.Architecture) {
							arches = append(arches, b.Architecture)
						}
					}
					if !strings.Contains(ansi.Strip(m.View().Content), string(target.Architecture)) {
						t.Fatal("Image hid the actual version's target")
					}
					slices.Sort(arches)
					m = selectionMove(m, slices.Index(arches, target.Architecture)-slices.Index(arches, start.Architecture))
					m = selectionChoose(t, m, input, string(target.Architecture))
					if got := m.Snapshot(); got.Source.UpdateID != target.UpdateID || got.Source.Architecture != target.Architecture || got.Source.BuildLabel != target.Title || got.ImageReady {
						t.Fatalf("Image target did not retain its exact UUID/revision: %+v", got)
					}
					language := slices.IndexFunc(discovery.languages, func(l catalog.Language) bool { return l.ID == "en-us" })
					if language < 0 {
						t.Fatal("live en-us language unavailable; acceptance unverified")
					}
					m = selectionStep(m, selectionKey(tea.KeyTab, ""))
					m = selectionMove(m, language)
					m = selectionChoose(t, m, input, "en-us")
					if len(discovery.editions) < 2 {
						t.Fatal("live source lacks multiple editions; acceptance unverified")
					}
					m = selectionStep(m, selectionKey(tea.KeyTab, ""))
					var editions []string
					for index := 0; index < 2; index++ {
						if index > 0 {
							m = selectionMove(m, 1)
						}
						edition := discovery.editions[index].ID
						editions = append(editions, edition)
						if input == "mouse" {
							m = selectionClick(t, m, "("+edition+")")
						} else {
							m = selectionStep(m, selectionKey(' ', " "))
						}
					}
					snapshot := m.Snapshot()
					if !snapshot.ImageReady || !snapshot.HasCatalogRecord || snapshot.Revision <= 1 || snapshot.Source.UpdateID != target.UpdateID || snapshot.Source.Architecture != target.Architecture || snapshot.Source.Language != "en-us" || !slices.Equal(snapshot.Config.Image.Editions, editions) || snapshot.AppsApplicable {
						t.Fatalf("source-bound multi-edition draft is invalid: %+v", snapshot)
					}
					if host == "amd64" && input == "mouse" {
						t.Logf("revision=%d uuid=%s title=%q build=%s target=%s language=en-us editions=%v ImageReady=%t (catalogue choices only)", snapshot.Revision, snapshot.Source.UpdateID, snapshot.Source.BuildLabel, target.Build, target.Architecture, editions, snapshot.ImageReady)
						for _, size := range [][2]int{{120, 32}, {68, 24}} {
							m = selectionStep(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
							view := ansi.Strip(m.View().Content)
							if !strings.Contains(view, "Source:") || !strings.Contains(view, "Language: en-us") || !strings.Contains(view, editions[0]+", "+editions[1]) || size[0] == 120 && !strings.Contains(view, target.UpdateID) {
								t.Fatalf("selected source summary hidden at %v:\n%s", size, view)
							}
							t.Logf("actual Charm view %dx%d:\n%s", size[0], size[1], view)
						}
					}
				})
			}
		}
	}
	if _, err := os.Stat(startup.ConfigPath); !os.IsNotExist(err) {
		t.Fatalf("first-run browsing wrote a config: %v", err)
	}
}

type selectionCatalog struct {
	*catalog.Client
	builds    []catalog.Build
	languages []catalog.Language
	editions  []catalog.Edition
}

func (c *selectionCatalog) Search(ctx context.Context, query string) ([]catalog.Build, error) {
	rows, err := c.Client.Search(ctx, query)
	c.builds = rows
	return rows, err
}
func (c *selectionCatalog) Languages(ctx context.Context, id string) ([]catalog.Language, error) {
	rows, err := c.Client.Languages(ctx, id)
	c.languages = rows
	return rows, err
}
func (c *selectionCatalog) Editions(ctx context.Context, id, language string) ([]catalog.Edition, error) {
	rows, err := c.Client.Editions(ctx, id, language)
	c.editions = rows
	return rows, err
}

func selectionStep(m tui.Model, msg tea.Msg) tui.Model {
	updated, cmd := m.Update(msg)
	m = updated.(tui.Model)
	if cmd == nil {
		return m
	}
	result := cmd()
	if batch, ok := result.(tea.BatchMsg); ok {
		for _, child := range batch {
			m = selectionStep(m, child())
		}
		return m
	}
	return selectionStep(m, result)
}
func selectionKey(code rune, text string) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: code, Text: text}
}
func selectionMove(m tui.Model, delta int) tui.Model {
	code := tea.KeyDown
	if delta < 0 {
		code, delta = tea.KeyUp, -delta
	}
	for range delta {
		m = selectionStep(m, selectionKey(code, ""))
	}
	return m
}
func selectionChoose(t *testing.T, m tui.Model, input, label string) tui.Model {
	t.Helper()
	if input == "mouse" {
		return selectionClick(t, m, label)
	}
	if input == "space" {
		return selectionStep(m, selectionKey(' ', " "))
	}
	return selectionStep(m, selectionKey(tea.KeyEnter, ""))
}
func selectionClick(t *testing.T, m tui.Model, label string) tui.Model {
	t.Helper()
	for y, line := range strings.Split(ansi.Strip(m.View().Content), "\n") {
		if x := strings.Index(line, label); x >= 0 {
			return selectionStep(m, tea.MouseClickMsg{X: ansi.StringWidth(line[:x]), Y: y, Button: tea.MouseLeft})
		}
	}
	t.Fatalf("visible mouse control %q was not found:\n%s", label, ansi.Strip(m.View().Content))
	return m
}
