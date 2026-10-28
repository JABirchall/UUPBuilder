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

func TestConversionEditorCoversTypedSettings(t *testing.T) {
	editor := NewConversionModel(config.Defaults(), nil)
	// Omitting any typed setting would make it impossible to edit the loaded
	// request without leaving the Workspace. App inventory belongs to R16.
	keys := []string{
		"conversion.updates", "conversion.servicing_strategy", "conversion.cumulative_update_policy", "conversion.checkpoint_updates", "conversion.enablement_packages", "conversion.cleanup", "conversion.reset_base", "conversion.netfx3", "conversion.include_winre", "conversion.winre_updates", "conversion.update_boot_files", "conversion.boot_wim_engine", "conversion.reference_images", "conversion.cumulative_msu", "conversion.keep_reference_esds",
		"conversion.drivers.enabled", "conversion.drivers.source", "conversion.drivers.targets", "conversion.editions.derived", "conversion.editions.strategy", "conversion.editions.preserve_required_bases",
		"output.kind", "output.image_format", "output.split_size_mib", "output.directory", "output.filename", "output.label", "output.edition_order", "downloads.parallel_files", "downloads.retries", "downloads.proxy.mode", "downloads.proxy.url", "storage.workspace", "storage.cache", "storage.keep_downloads", "storage.keep_intermediates",
	}
	for _, key := range keys {
		found := false
		for _, field := range editor.fields {
			if field.key == key {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing editable setting %s", key)
		}
	}
	if len(editor.fields) != len(keys) {
		t.Fatalf("got %d fields, want %d", len(editor.fields), len(keys))
	}
	for _, change := range []ConversionFieldChangedMsg{
		{Key: "conversion.drivers.source", Value: `C:\drivers`},
		{Key: "conversion.drivers.targets", Value: "os, winpe, winre, shared"},
		{Key: "conversion.drivers.enabled", Value: "true"},
		{Key: "output.image_format", Value: "swm"},
		{Key: "output.edition_order", Value: "professional, core"},
		{Key: "downloads.proxy.mode", Value: "explicit"},
		{Key: "downloads.proxy.url", Value: "https://proxy.example:8080"},
	} {
		if err := editor.set(change.Key, change.Value); err != nil {
			t.Fatal(err)
		}
	}
	cfg, diagnostics := editor.Apply(config.Defaults())
	if len(diagnostics) != 0 {
		t.Fatalf("valid typed settings rejected: %+v", diagnostics)
	}
	if !cfg.Conversion.Drivers.Enabled || !reflect.DeepEqual(cfg.Conversion.Drivers.Targets, []model.DriverTarget{"os", "winpe", "winre", "shared"}) || cfg.Output.ImageFormat != model.ImageSWM || !reflect.DeepEqual(cfg.Output.EditionOrder, []string{"professional", "core"}) || cfg.Downloads.Proxy.URL != "https://proxy.example:8080" {
		t.Fatalf("typed settings not applied: %+v", cfg)
	}
}

func TestExplicitUnsupportedSettingIsNotReset(t *testing.T) {
	cfg := config.Defaults()
	cfg.Conversion.BootWIMEngine = model.BootWIMDISM
	editor := NewConversionModel(cfg, []model.SettingApplicability{{Key: "conversion.boot_wim_engine", RequestedValue: "dism", EffectiveValue: "", Supported: false, Reason: "tool unavailable for this source"}})
	after, diagnostics := editor.Apply(cfg)
	if !reflect.DeepEqual(after, cfg) || len(diagnostics) != 0 {
		t.Fatalf("unsupported explicit request changed: %+v, %+v", after, diagnostics)
	}
	line := editor.detail("conversion.boot_wim_engine")
	if !strings.Contains(line, "unsupported") || !strings.Contains(line, "tool unavailable") || !strings.Contains(line, "requested: dism") {
		t.Fatalf("unsupported request hidden: %s", line)
	}
}

func TestAutoShowsEffectiveValue(t *testing.T) {
	editor := NewConversionModel(config.Defaults(), []model.SettingApplicability{{Key: "conversion.boot_wim_engine", RequestedValue: "auto", EffectiveValue: "wimlib", Supported: true, Automatic: true, Reason: "resolved by source metadata"}})
	line := editor.detail("conversion.boot_wim_engine")
	if !strings.Contains(line, "requested: auto") || !strings.Contains(line, "effective: wimlib") || !strings.Contains(line, "resolved by source metadata") {
		t.Fatal(line)
	}
	if err := editor.set("conversion.boot_wim_engine", "dism"); err != nil {
		t.Fatal(err)
	}
	if line = editor.detail("conversion.boot_wim_engine"); !strings.Contains(line, "unchecked") || strings.Contains(line, "effective: wimlib") {
		t.Fatalf("stale applicability survived edit: %s", line)
	}
}

func TestConversionKeyboardEditsBeforeImageSelection(t *testing.T) {
	m := browse(t)
	m = send(m, NavigateMsg{Area: Conversion})
	before := m.Snapshot().Revision
	m = send(m, ConversionFieldChangedMsg{Key: "downloads.parallel_files", Value: "9"})
	if m.cfg.Downloads.ParallelFiles != 9 || m.Snapshot().Revision <= before || m.Snapshot().ImageReady {
		t.Fatalf("first-run edit failed: %+v", m.Snapshot())
	}
	for i, f := range m.conversion.fields {
		if f.key == "output.filename" {
			m.conversion.cursor = i + configControlCount
		}
	}
	m = send(m, key(tea.KeyEnter, ""))
	m = send(m, key('a', "a"))
	m = send(m, key(tea.KeyEscape, ""))
	if m.cfg.Output.Filename != "auto" || m.editing() {
		t.Fatal("escape committed pending text or retained input focus")
	}
	m = send(m, key(tea.KeyEnter, ""))
	m.conversion.input.SetValue("custom.iso")
	m = send(m, key(tea.KeyEnter, ""))
	if m.cfg.Output.Filename != "custom.iso" || m.editing() {
		t.Fatal("enter did not apply text input")
	}
}

func TestConversionInvalidNumbersRetainTypedDraft(t *testing.T) {
	m := browse(t)
	before := m.Snapshot()
	m = send(m, ConversionFieldChangedMsg{Key: "downloads.parallel_files", Value: "many"})
	if !reflect.DeepEqual(m.Snapshot().Config, before.Config) || m.revision != before.Revision || !strings.Contains(m.notice, "integer") {
		t.Fatalf("invalid input changed draft or lacks error: %+v", m.Snapshot())
	}
	m = send(m, ConversionFieldChangedMsg{Key: "downloads.retries", Value: "-1"})
	if m.cfg.Downloads.Retries != -1 || !strings.Contains(m.notice, "negative") {
		t.Fatal("structural invalid request not retained with diagnostics")
	}
	if strings.Contains(ansi.Strip(m.View().Content), "\x1b") {
		t.Fatal("unsafe view")
	}
}

func TestConversionCompleteTypedRoundTripAndAppRetention(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "config", "testdata", "complete.toml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Decode(data, "complete.toml")
	if err != nil {
		t.Fatal(err)
	}
	got, diagnostics := NewConversionModel(cfg, nil).Apply(cfg)
	if len(diagnostics) != 0 || !reflect.DeepEqual(got, cfg) {
		t.Fatalf("typed fields or app settings lost: %+v %+v", got, diagnostics)
	}
}

func TestConversionCanonicalNoopDoesNotInvalidateDraft(t *testing.T) {
	m := browse(t)
	m = send(m, ConversionFieldChangedMsg{Key: "output.edition_order", Value: "professional,core"})
	before := m.revision
	m = send(m, ConversionFieldChangedMsg{Key: "output.edition_order", Value: " professional , core "})
	if m.revision != before {
		t.Fatalf("equivalent list edit invalidated revision: %d -> %d", before, m.revision)
	}
}

func TestConversionMouseAndNavigationPreserveEdits(t *testing.T) {
	m := browse(t)
	m = send(m, NavigateMsg{Area: Conversion})
	for _, width := range []int{120, 68} {
		m = send(m, tea.WindowSizeMsg{Width: width, Height: 30})
		m.conversion.cursor = configControlCount
		_, hits := m.layout()
		clicked := false
		for _, target := range hits {
			choice, ok := target.msg.(conversionFocusMsg)
			if !ok || choice.index != configControlCount {
				continue
			}
			m = send(m, tea.MouseClickMsg{X: target.x, Y: target.y, Button: tea.MouseLeft})
			clicked = true
			break
		}
		if !clicked {
			t.Fatal("visible conversion choice lacks mouse region")
		}
	}
	if m.cfg.Conversion.Updates != model.UpdatesOmit {
		t.Fatalf("mouse did not cycle requested updates: %s", m.cfg.Conversion.Updates)
	}
	m = send(m, NavigateMsg{Area: Builds})
	m = send(m, key('/', "/"))
	m = send(m, tea.PasteMsg{Content: "query"})
	m = send(m, NavigateMsg{Area: Conversion})
	if m.editing() || m.cfg.Conversion.Updates != model.UpdatesOmit {
		t.Fatal("navigation lost conversion values or retained unrelated focus")
	}
	m = send(m, key(tea.KeyDown, ""))
	if m.conversion.cursor != configControlCount+1 {
		t.Fatal("conversion keyboard focus did not follow mouse")
	}
}

func TestConversionViews(t *testing.T) {
	for _, size := range []struct {
		name          string
		width, height int
	}{{"normal", 120, 32}, {"compact", 68, 24}, {"narrow", 40, 20}} {
		for _, state := range []string{"focused", "invalid", "long"} {
			t.Run(size.name+"_"+state, func(t *testing.T) {
				m := browse(t)
				m = send(m, NavigateMsg{Area: Conversion})
				m = send(m, tea.WindowSizeMsg{Width: size.width, Height: size.height})
				selected := "downloads.parallel_files"
				if state == "long" {
					selected = "output.directory"
					m = send(m, ConversionFieldChangedMsg{Key: selected, Value: `C:\very-long-output-name\` + strings.Repeat("directory", 30) + "\x1b[31m\x1b]0;unsafe\x07"})
				}
				for i, f := range m.conversion.fields {
					if f.key == selected {
						m.conversion.cursor = i + configControlCount
					}
				}
				if state == "focused" {
					m = send(m, key(tea.KeyEnter, ""))
					m.conversion.input.SetValue("12")
				}
				if state == "invalid" {
					m = send(m, ConversionFieldChangedMsg{Key: "downloads.parallel_files", Value: "0"})
				}
				view := m.View().Content
				if len(strings.Split(view, "\n")) > size.height {
					t.Fatal("height overflow")
				}
				for _, line := range strings.Split(view, "\n") {
					if ansi.StringWidth(line) > size.width {
						t.Fatalf("width overflow: %s", line)
					}
				}
				clean := ansi.Strip(view)
				if !strings.Contains(clean, "> ") {
					t.Fatalf("focused control hidden:\n%s", clean)
				}
				if strings.Contains(clean, "unsafe") || strings.Contains(clean, "\x1b") {
					t.Fatalf("terminal controls leaked:\n%s", clean)
				}
				t.Logf("Actual conversion view (%dx%d):\n%s", size.width, size.height, clean)
				if size.name == "narrow" {
					return
				}
				path := filepath.Join("testdata", "workspace_conversion_"+size.name+"_"+state+".golden")
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
					t.Fatalf("conversion golden mismatch\ngot:\n%s\nwant:\n%s", got, want)
				}
			})
		}
	}
}
