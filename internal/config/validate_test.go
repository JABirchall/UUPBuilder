package config

import (
	"reflect"
	"strings"
	"testing"

	"uupbuilder/internal/model"
)

func TestRequestPreservesExplicitSourceDependentPoliciesAndCopiesSlices(t *testing.T) {
	cfg, err := Decode(fixture(t, "complete"), "complete.toml")
	if err != nil {
		t.Fatal(err)
	}
	selection, settings, err := cfg.Request()
	if err != nil {
		t.Fatal(err)
	}
	want := model.ResolvedSettings{Conversion: cfg.Conversion, Apps: cfg.Apps, Output: cfg.Output, Storage: cfg.Storage, Downloads: cfg.Downloads}
	if !reflect.DeepEqual(selection, cfg.Image) || !reflect.DeepEqual(settings, want) {
		t.Fatal("explicit source-dependent request changed")
	}
	selection.Editions[0] = "changed"
	settings.Conversion.Drivers.Targets[0] = "changed"
	settings.Conversion.Editions.Derived[0] = "changed"
	settings.Apps.Include[0] = "changed"
	settings.Output.EditionOrder[0] = "changed"
	if cfg.Image.Editions[0] != "professional" || cfg.Conversion.Drivers.Targets[0] != "os" || cfg.Conversion.Editions.Derived[0] != "enterprise" || cfg.Apps.Include[0] != "Microsoft.WindowsNotepad_8wekyb3d8bbwe" || cfg.Output.EditionOrder[0] != "enterprise" {
		t.Fatal("Request shares mutable slices with config")
	}
}

func TestValidateRejectsStructuralErrors(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		edit      func(*Config)
	}{
		{"version", "schema_version", func(c *Config) { c.SchemaVersion = 2 }},
		{"endpoint", "catalog.endpoint", func(c *Config) { c.Catalog.Endpoint = "https://user:secret@example.com" }},
		{"architecture", "image.architecture", func(c *Config) { c.Image.Architecture = "bad arch" }},
		{"editions", "image.editions", func(c *Config) { c.Image.Editions = []string{"pro", "pro"} }},
		{"drivers", "conversion.drivers.source", func(c *Config) { c.Conversion.Drivers.Enabled = true }},
		{"targets", "conversion.drivers.targets", func(c *Config) { c.Conversion.Drivers.Targets = []model.DriverTarget{"bios"} }},
		{"swm", "output.split_size_mib", func(c *Config) { c.Output.ImageFormat = "swm"; c.Output.SplitSizeMiB = 0 }},
		{"parallel", "downloads.parallel_files", func(c *Config) { c.Downloads.ParallelFiles = 0 }},
		{"retries", "downloads.retries", func(c *Config) { c.Downloads.Retries = -1 }},
		{"proxy credentials", "downloads.proxy.url", func(c *Config) {
			c.Downloads.Proxy = model.ProxySettings{Mode: "explicit", URL: "http://user:secret@example.com"}
		}},
		{"filename traversal", "output.filename", func(c *Config) { c.Output.Filename = "../bad.iso" }},
		{"directory ADS", "output.directory", func(c *Config) { c.Output.Directory = "out:stream" }},
		{"workspace device", "storage.workspace", func(c *Config) { c.Storage.Workspace = "NUL" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			tc.edit(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("got %v, want %s", err, tc.key)
			}
		})
	}
}

func TestDecodePreservesExplicitZeroFalseEmptyAndInactiveSettings(t *testing.T) {
	cfg, err := Decode([]byte(`schema_version=1
[conversion]
cleanup=false
include_winre=false
winre_updates="include"
boot_wim_engine="wimlib"
[conversion.drivers]
enabled=false
source="drivers"
targets=["winre"]
[apps]
mode="none"
preset="future"
include=["Future.App_family"]
stub_policy="stub"
[downloads]
retries=0
[storage]
keep_downloads=false
`), "explicit.toml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Conversion.Cleanup || cfg.Conversion.IncludeWinRE || cfg.Storage.KeepDownloads || cfg.Downloads.Retries != 0 || cfg.Apps.Mode != "none" || cfg.Apps.Preset != "future" || len(cfg.Apps.Include) != 1 || cfg.Conversion.Drivers.Source != "drivers" || cfg.Conversion.WinREUpdates != "include" {
		t.Fatalf("explicit settings reset: %#v", cfg)
	}
}
