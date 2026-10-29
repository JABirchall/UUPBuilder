package tui

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
)

// A missing or misbound editor field, a save that drops a policy, or an output
// control that offers excluded deliverables must break this complete journey.
func TestISOWorkflowRetainsRequestedSettings(t *testing.T) {
	root := t.TempDir()
	m := appsChosen(t)
	defer m.Close()
	m = send(m, ToggleEditionMsg{Edition: "core"})
	m, cmd := step(m, NavigateMsg{Area: Apps})
	m = send(m, cmd())
	m = send(m, appToggleMsg{featureID: "Example.App_pub"})
	m = send(m, appStubMsg{policy: model.AppFull})
	m = send(m, NavigateMsg{Area: Conversion})
	m = send(m, ConfigPathChangedMsg{Path: filepath.Join(root, "settings", "complete-iso.toml")})
	for _, edit := range []ConversionFieldChangedMsg{
		{Key: "conversion.updates", Value: "external"},
		{Key: "conversion.servicing_strategy", Value: "shared-base"},
		{Key: "conversion.cumulative_update_policy", Value: "expand"},
		{Key: "conversion.checkpoint_updates", Value: "preserve"},
		{Key: "conversion.enablement_packages", Value: "include"},
		{Key: "conversion.cleanup", Value: "false"},
		{Key: "conversion.reset_base", Value: "on"},
		{Key: "conversion.reference_images", Value: "export"},
		{Key: "conversion.cumulative_msu", Value: "keep"},
		{Key: "conversion.keep_reference_esds", Value: "true"},
		{Key: "conversion.editions.derived", Value: "enterprise"},
		{Key: "conversion.editions.strategy", Value: "per-edition"},
		{Key: "conversion.editions.preserve_required_bases", Value: "false"},
		{Key: "conversion.netfx3", Value: "true"},
		{Key: "conversion.update_boot_files", Value: "true"},
		{Key: "conversion.boot_wim_engine", Value: "wimlib"},
		{Key: "conversion.drivers.source", Value: filepath.Join(root, "drivers")},
		{Key: "conversion.drivers.targets", Value: "os, winpe, shared"},
		{Key: "conversion.drivers.enabled", Value: "true"},
		{Key: "output.image_format", Value: "swm"},
		{Key: "output.split_size_mib", Value: "3800"},
		{Key: "output.directory", Value: filepath.Join(root, "iso-output")},
		{Key: "output.filename", Value: "Requested-Windows.iso"},
		{Key: "output.label", Value: "REQUESTED_WINDOWS"},
		{Key: "output.edition_order", Value: "enterprise, professional, core"},
		{Key: "downloads.proxy.mode", Value: "explicit"},
		{Key: "downloads.proxy.url", Value: "https://proxy.example:8080"},
		{Key: "downloads.parallel_files", Value: "7"},
		{Key: "downloads.retries", Value: "2"},
		{Key: "storage.workspace", Value: filepath.Join(root, "workspace")},
		{Key: "storage.cache", Value: filepath.Join(root, "cache")},
		{Key: "storage.keep_downloads", Value: "false"},
		{Key: "storage.keep_intermediates", Value: "true"},
	} {
		m = send(m, edit)
	}
	before := m.Snapshot().Config
	wantSelection := model.Selection{UpdateID: firstID, Architecture: "amd64", Language: "en-us", Editions: []string{"professional", "core"}}
	wantSettings := model.ResolvedSettings{
		Conversion: model.ConversionSettings{
			Updates: "external", ServicingStrategy: "shared-base", CumulativeUpdates: "expand", CheckpointUpdates: "preserve", EnablementPackages: "include",
			Cleanup: false, ResetBase: "on", NetFX3: true, IncludeWinRE: false, WinREUpdates: "omit", UpdateBootFiles: true, BootWIMEngine: "wimlib",
			ReferenceImages: "export", CumulativeMSU: "keep", KeepReferenceESDs: true,
			Drivers:  model.DriverSettings{Enabled: true, Source: filepath.Join(root, "drivers"), Targets: []model.DriverTarget{"os", "winpe", "shared"}},
			Editions: model.EditionSettings{Derived: []string{"enterprise"}, Strategy: "per-edition", PreserveRequiredBases: false},
		},
		Apps:      model.AppSettings{Mode: "custom", StubPolicy: "full", Include: []string{"Example.App_pub"}, Edge: "default"},
		Output:    model.OutputSettings{Kind: "iso", ImageFormat: "swm", SplitSizeMiB: 3800, Directory: filepath.Join(root, "iso-output"), Filename: "Requested-Windows.iso", Label: "REQUESTED_WINDOWS", EditionOrder: []string{"enterprise", "professional", "core"}},
		Downloads: model.DownloadSettings{ParallelFiles: 7, Retries: 2, Proxy: model.ProxySettings{Mode: "explicit", URL: "https://proxy.example:8080"}},
		Storage:   model.StorageSettings{Workspace: filepath.Join(root, "workspace"), Cache: filepath.Join(root, "cache"), KeepDownloads: false, KeepIntermediates: true},
	}
	m = send(m, viewTOMLMsg{})
	if !strings.Contains(m.View().Content, "Read-only draft TOML") {
		t.Fatal("TOML preview unavailable for the complete draft")
	}
	m = send(m, viewTOMLMsg{})
	m = finishConfigAction(t, m, SaveConfigMsg{})
	if !strings.HasPrefix(m.notice, "Saved TOML:") {
		t.Fatal(m.notice)
	}
	saved, err := config.Load(m.configActions.path)
	if err != nil || !reflect.DeepEqual(saved, before) {
		t.Fatalf("complete draft changed on disk: %v\ngot=%+v\nwant=%+v", err, saved, before)
	}
	m = send(m, ConversionFieldChangedMsg{Key: "output.filename", Value: "changed.iso"})
	m = send(m, appModeMsg{mode: model.AppsNone})
	m = finishConfigAction(t, m, LoadConfigMsg{})
	if !reflect.DeepEqual(m.cfg, before) || m.Snapshot().ImageReady || m.Snapshot().AppsApplicable {
		t.Fatalf("reload lost request or claimed execution readiness: %+v", m.Snapshot())
	}
	selection, settings, err := m.cfg.Request()
	if err != nil || !reflect.DeepEqual(selection, wantSelection) || !reflect.DeepEqual(settings, wantSettings) {
		t.Fatalf("reloaded ISO request differs: %v %+v %+v", err, selection, settings)
	}
	data, err := os.ReadFile(m.configActions.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Actual complete draft saved and reloaded at %s; source/app applicability remain unchecked after reload.\n%s", m.configActions.path, data)
	for i, field := range m.conversion.fields {
		if field.key == "output.kind" {
			m.conversion.cursor = i + configControlCount
		}
	}
	for range 3 {
		m = send(m, key(tea.KeyEnter, ""))
		if m.cfg.Output.Kind != model.OutputISO {
			t.Fatalf("ISO output control offered an excluded deliverable: %s", m.cfg.Output.Kind)
		}
	}
}

func TestLegacyConversionRequestsRemainUnchangedUntilEdited(t *testing.T) {
	for _, kind := range []model.OutputKind{model.OutputImage, model.OutputDirectory} {
		t.Run(string(kind), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Image.UpdateID = firstID
			cfg.Output.Kind = kind
			cfg.Conversion.IncludeWinRE = true
			cfg.Conversion.WinREUpdates = model.InclusionInclude
			cfg.Conversion.Drivers.Targets = []model.DriverTarget{model.DriverWinRE}
			m := New(Dependencies{Catalog: testCatalog{}, ConfigPath: filepath.Join(t.TempDir(), "legacy.toml")}, cfg)
			defer m.Close()
			m = send(m, NavigateMsg{Area: Conversion})
			m = finishConfigAction(t, m, SaveConfigMsg{})
			if !strings.HasPrefix(m.notice, "Saved TOML:") {
				t.Fatal(m.notice)
			}
			m = finishConfigAction(t, m, LoadConfigMsg{})
			if m.cfg.Output.Kind != kind || !m.cfg.Conversion.IncludeWinRE || m.cfg.Conversion.WinREUpdates != "include" || !reflect.DeepEqual(m.cfg.Conversion.Drivers.Targets, []model.DriverTarget{"winre"}) {
				t.Fatalf("loading legacy draft silently changed its requests: %+v", m.cfg)
			}
			for i, field := range m.conversion.fields {
				if field.key == "output.kind" {
					m.conversion.cursor = i + configControlCount
				}
			}
			m = send(m, key(tea.KeyEnter, ""))
			if m.cfg.Output.Kind != model.OutputISO || !m.cfg.Conversion.IncludeWinRE || m.cfg.Conversion.WinREUpdates != "include" {
				t.Fatalf("explicit ISO edit failed or changed unrelated legacy intent: %+v", m.cfg)
			}
		})
	}
}

func TestConversionScopeViews(t *testing.T) {
	for _, state := range []struct{ name, key, value, explanation string }{
		{"iso", "output.kind", "iso", "ISO file"},
		{"image-format", "output.image_format", "swm", "inside ISO"},
		{"legacy-output", "output.kind", "directory", "excluded:"},
		{"legacy-recovery", "conversion.include_winre", "true", "excluded:"},
		{"legacy-updates", "conversion.winre_updates", "include", "excluded:"},
		{"legacy-drivers", "conversion.drivers.targets", "os, winre", "excluded:"},
	} {
		for _, size := range []struct {
			name          string
			width, height int
		}{{"normal", 120, 32}, {"compact", 68, 24}} {
			t.Run(size.name+"_"+state.name, func(t *testing.T) {
				cfg := config.Defaults()
				// Simulate a loaded explicit request, including stale resolver claims;
				// excluded scope must never appear executable even with such a claim.
				editor := NewConversionModel(cfg, nil)
				if err := editor.set(state.key, state.value); err != nil {
					t.Fatal(err)
				}
				cfg, issues := editor.Apply(cfg)
				if len(issues) != 0 {
					t.Fatal(issues)
				}
				m := New(Dependencies{Catalog: testCatalog{}}, cfg)
				defer m.Close()
				m.conversion.applicability = []model.SettingApplicability{{Key: state.key, RequestedValue: state.value, EffectiveValue: state.value, Supported: true, Reason: "stale claim"}}
				m = send(m, NavigateMsg{Area: Conversion})
				m = send(m, tea.WindowSizeMsg{Width: size.width, Height: size.height})
				for i, field := range m.conversion.fields {
					if field.key == state.key {
						m.conversion.cursor = i + configControlCount
					}
				}
				view := m.View().Content
				clean := ansi.Strip(view)
				if !strings.Contains(clean, state.explanation) || !strings.Contains(clean, "requested: "+state.value) || !strings.Contains(clean, "> ") {
					t.Fatalf("scope or loaded request hidden:\n%s", clean)
				}
				if state.explanation == "excluded:" && strings.Contains(clean, "| supported") {
					t.Fatalf("excluded request advertised as executable:\n%s", clean)
				}
				if len(strings.Split(view, "\n")) > size.height {
					t.Fatal("height overflow")
				}
				for _, line := range strings.Split(view, "\n") {
					if ansi.StringWidth(line) > size.width {
						t.Fatal("width overflow")
					}
				}
				path := filepath.Join("testdata", "workspace_conversion_"+size.name+"_"+state.name+".golden")
				got := structuralView(view)
				if os.Getenv("UPDATE_TUI_GOLDENS") == "1" {
					if err := os.WriteFile(path, []byte(got), 0644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if got != structuralView(string(want)) {
					t.Fatalf("scope golden mismatch\ngot:\n%s\nwant:\n%s", got, want)
				}
			})
		}
	}
}
