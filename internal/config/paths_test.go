package config

import (
	"path/filepath"
	"testing"
)

func TestResolvePathsUsesConfigDirectory(t *testing.T) {
	cfg, err := Decode(fixture(t, "complete"), "complete.toml")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	got, err := ResolvePaths(cfg, filepath.Join(root, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Conversion.Drivers.Source != filepath.Join(root, "drivers") || got.Output.Directory != filepath.Join(root, "output") || got.Storage.Workspace != filepath.Join(root, "scratch") || got.Storage.Cache != filepath.Join(root, "cache") {
		t.Fatalf("resolved paths: %#v", got)
	}
	if cfg.Conversion.Drivers.Source != "drivers" {
		t.Fatal("changed original config")
	}
	defaults, err := ResolvePaths(Defaults(), filepath.Join(root, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Storage.Workspace != "auto" || defaults.Storage.Cache != "auto" || defaults.Conversion.Drivers.Source != "" || defaults.Output.Filename != "auto" || defaults.Output.Label != "auto" {
		t.Fatal("changed policy markers")
	}
	cfg.Storage.Workspace = filepath.Join(root, "absolute")
	cfg.Output.Directory = "../sibling"
	got, err = ResolvePaths(cfg, filepath.Join(root, "nested", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Storage.Workspace != cfg.Storage.Workspace || got.Output.Directory != filepath.Join(root, "sibling") {
		t.Fatalf("wrong absolute/parent paths: %#v", got)
	}
}

func TestResolvePathsRejectsEmptyConfigPath(t *testing.T) {
	if _, err := ResolvePaths(Defaults(), ""); err == nil {
		t.Fatal("empty path accepted")
	}
}
