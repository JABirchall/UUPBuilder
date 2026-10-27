package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSelectionRetainsRequestedEditions(t *testing.T) {
	selection := Selection{UpdateID: "source_rev.9", Architecture: "future128", Language: "en-us", Editions: []string{"professional", "future-edition"}}
	if err := selection.Validate(); err != nil {
		t.Fatal(err)
	}
	selection.Editions = []string{"professional", "professional"}
	if err := selection.Validate(); err == nil {
		t.Fatal("accepted duplicate editions")
	}
	selection.Editions = nil
	if err := selection.Validate(); err == nil {
		t.Fatal("accepted selection without editions")
	}
}

func TestResolvedSettingsPreserveExplicitPolicies(t *testing.T) {
	settings := validSettings()
	settings.Conversion.BootWIMEngine = BootWIMDISM
	settings.Conversion.NetFX3 = true
	settings.Conversion.Drivers = DriverSettings{Enabled: true, Source: `C:\drivers`, Targets: []DriverTarget{DriverOS, DriverWinPE, DriverWinRE, DriverShared}}
	settings.Apps = AppSettings{Mode: AppsCustom, Preset: "my-preset", StubPolicy: AppFull, Include: []string{"Unavailable.Package_family"}, Edge: EdgeDefault}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	var restored ResolvedSettings
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Conversion.BootWIMEngine != BootWIMDISM || !restored.Conversion.NetFX3 || restored.Apps.Include[0] != "Unavailable.Package_family" || len(restored.Conversion.Drivers.Targets) != 4 {
		t.Fatal("explicit settings were dropped or rewritten")
	}
}

func TestResolvedSettingsRejectInvalidPolicies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ResolvedSettings)
		key    string
	}{
		{"format", func(s *ResolvedSettings) { s.Output.ImageFormat = "zip" }, "output.image_format"},
		{"updates", func(s *ResolvedSettings) { s.Conversion.Updates = "magic" }, "conversion.updates"},
		{"checkpoint", func(s *ResolvedSettings) { s.Conversion.CheckpointUpdates = "magic" }, "conversion.checkpoint_updates"},
		{"split", func(s *ResolvedSettings) { s.Output.ImageFormat = ImageSWM; s.Output.SplitSizeMiB = 0 }, "output.split_size_mib"},
		{"parallel", func(s *ResolvedSettings) { s.Downloads.ParallelFiles = 0 }, "downloads.parallel_files"},
		{"driver", func(s *ResolvedSettings) { s.Conversion.Drivers.Enabled = true }, "conversion.drivers.source"},
		{"proxy-secret", func(s *ResolvedSettings) {
			s.Downloads.Proxy = ProxySettings{Mode: ProxyExplicit, URL: "https://user:password@example.invalid"}
		}, "downloads.proxy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := validSettings()
			tc.change(&settings)
			err := settings.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("expected %s validation error, got %v", tc.key, err)
			}
		})
	}
}

func validSettings() ResolvedSettings {
	return ResolvedSettings{
		Conversion: ConversionSettings{Updates: UpdatesIntegrate, ServicingStrategy: ServicingAuto, CumulativeUpdates: ExpansionAuto, CheckpointUpdates: ExpansionAuto, EnablementPackages: InclusionAuto, ResetBase: ResetBaseOff, IncludeWinRE: true, WinREUpdates: InclusionAuto, BootWIMEngine: BootWIMAuto, ReferenceImages: ReferenceAuto, CumulativeMSU: MSUAuto, Editions: EditionSettings{Strategy: ServicingAuto}},
		Apps:       AppSettings{Mode: AppsDefault, StubPolicy: AppStubAuto, Edge: EdgeDefault},
		Output:     OutputSettings{Kind: OutputISO, ImageFormat: ImageWIM, SplitSizeMiB: 3800, Directory: "output", Filename: "auto", Label: "auto"},
		Storage:    StorageSettings{Workspace: "auto", Cache: "auto", KeepDownloads: true},
		Downloads:  DownloadSettings{ParallelFiles: 4, Retries: 5, Proxy: ProxySettings{Mode: ProxySystem}},
	}
}
