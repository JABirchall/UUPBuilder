package config

import (
	"path/filepath"
	"testing"
)

func TestUnattendPathRoundTripsAndResolvesRelativeToConfig(t *testing.T) {
	cfg, err := Decode([]byte("schema_version = 1\n[output]\nautounattend = 'answers/setup.xml'\n"), "config.toml")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "config.toml")
	if _, err = Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Output.Autounattend != filepath.Join(root, "answers", "setup.xml") {
		t.Fatalf("resolved path: %q", loaded.Output.Autounattend)
	}
}
