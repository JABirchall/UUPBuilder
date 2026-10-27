package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"uupbuilder/internal/model"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name+".toml"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCompleteConfigRoundTripsEverySetting(t *testing.T) {
	cfg, err := Decode(fixture(t, "complete"), "complete.toml")
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		SchemaVersion: 1, Catalog: CatalogSettings{Endpoint: "https://api.uupdump.net"},
		Image: model.Selection{UpdateID: "source-uuid_rev.2", Architecture: "arm", Language: "en-gb", Editions: []string{"professional", "enterprise"}},
		Conversion: model.ConversionSettings{
			Updates: "external", ServicingStrategy: "shared-base", CumulativeUpdates: "expand", CheckpointUpdates: "preserve", EnablementPackages: "include",
			Cleanup: false, ResetBase: "on", NetFX3: true, IncludeWinRE: false, WinREUpdates: "include", UpdateBootFiles: true, BootWIMEngine: "dism", ReferenceImages: "export", CumulativeMSU: "keep", KeepReferenceESDs: true,
			Drivers:  model.DriverSettings{Enabled: true, Source: "drivers", Targets: []model.DriverTarget{"os", "winpe", "winre", "shared"}},
			Editions: model.EditionSettings{Derived: []string{"enterprise", "future-edition"}, Strategy: "per-edition", PreserveRequiredBases: true},
		},
		Apps:      model.AppSettings{Mode: "custom", Preset: "future-preset", StubPolicy: "full", Include: []string{"Microsoft.WindowsNotepad_8wekyb3d8bbwe", "Future.App_family"}, Edge: "exclude"},
		Output:    model.OutputSettings{Kind: "directory", ImageFormat: "swm", SplitSizeMiB: 3900, Directory: "output", Filename: "custom.iso", Label: "CUSTOM_MEDIA", EditionOrder: []string{"enterprise", "professional"}},
		Downloads: model.DownloadSettings{ParallelFiles: 7, Retries: 2, Proxy: model.ProxySettings{Mode: "explicit", URL: "socks5://proxy.example:1080"}},
		Storage:   model.StorageSettings{Workspace: "scratch", Cache: "cache", KeepDownloads: false, KeepIntermediates: true},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("decoded config differs:\ngot %#v\nwant %#v", cfg, want)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if _, err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := Decode(data, path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roundTrip, want) {
		t.Fatalf("round trip changed settings:\ngot %#v\nwant %#v", roundTrip, want)
	}
}

func TestDecodeRejectsUnknownKeyWithLocation(t *testing.T) {
	_, err := Decode(fixture(t, "unknown-key"), "settings.toml")
	assertDiagnostic(t, err, "settings.toml", "conversion.typo", 3, 1)
}

func TestDecodeRejectsCaseMismatchedKeys(t *testing.T) {
	for _, tc := range []struct {
		text, key    string
		line, column int
	}{
		{"schema_version=1\n[Output]\nkind='iso'\n", "Output", 2, 2},
		{"schema_version=1\n[output]\nImage_Format='esd'\n", "output.Image_Format", 3, 1},
		{"schema_version=1\noutput={ Image_Format='esd' }\n", "output.Image_Format", 2, 10},
	} {
		_, err := Decode([]byte(tc.text), "case.toml")
		assertDiagnostic(t, err, "case.toml", tc.key, tc.line, tc.column)
	}
}

func TestDecodeDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, key    string
		line, column int
	}{
		{"wrong-type", "downloads.parallel_files", 3, 18},
		{"invalid-enum", "output.image_format", 3, 1},
		{"unsupported-version", "schema_version", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(fixture(t, tc.name), tc.name+".toml")
			assertDiagnostic(t, err, tc.name+".toml", tc.key, tc.line, tc.column)
		})
	}
}

func assertDiagnostic(t *testing.T, err error, filename, key string, line, column int) {
	t.Helper()
	if err == nil {
		t.Fatal("expected diagnostic")
	}
	var diagnostic *Error
	if !errors.As(err, &diagnostic) {
		t.Fatalf("expected *config.Error, got %T: %v", err, err)
	}
	if diagnostic.Filename != filename || diagnostic.Key != key || diagnostic.Line != line || diagnostic.Column != column {
		t.Fatalf("diagnostic = %#v, want %s:%d:%d %s", diagnostic, filename, line, column, key)
	}
	for _, value := range []string{filename, key} {
		if !strings.Contains(err.Error(), value) {
			t.Errorf("error %q omits %q", err, value)
		}
	}
}

func TestDecodeRequiresVersionAndRejectsBadTOML(t *testing.T) {
	for _, text := range []string{"", "[output]\nkind='iso'", "schema_version=1\nschema_version=1", "schema_version=1\n[output\n"} {
		if _, err := Decode([]byte(text), "bad.toml"); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
}

func TestDecodeExplicitEmptyValuesDoNotReceiveDefaults(t *testing.T) {
	cfg, err := Decode([]byte("schema_version=1\n[image]\narchitecture=''\nlanguage=''\neditions=[]\n[apps]\ninclude=[]\n"), "empty.toml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Image.Architecture != "" || cfg.Image.Language != "" || len(cfg.Image.Editions) != 0 || len(cfg.Apps.Include) != 0 {
		t.Fatalf("explicit empty settings reset: %#v", cfg)
	}
	if _, _, err := cfg.Request(); err == nil {
		t.Fatal("incomplete selection became build ready")
	}
	_, err = Decode([]byte("schema_version=1\n[output]\ndirectory=''\n"), "empty-path.toml")
	assertDiagnostic(t, err, "empty-path.toml", "output.directory", 3, 1)
}

func TestDecodeSemanticLocationUnderQuotedDottedAndInlineKeys(t *testing.T) {
	for _, tc := range []struct {
		text         string
		line, column int
	}{
		{"schema_version=1\n\"output\".\"image_format\"='zip'\n", 2, 1},
		{"schema_version=1\noutput={ image_format='zip' }\n", 2, 10},
	} {
		_, err := Decode([]byte(tc.text), "advanced.toml")
		assertDiagnostic(t, err, "advanced.toml", "output.image_format", tc.line, tc.column)
	}
}
