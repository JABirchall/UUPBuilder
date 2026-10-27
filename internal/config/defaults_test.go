package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestDefaultsAllowBrowsingButRequestNeedsSelection(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaVersion != 1 || cfg.Downloads.ParallelFiles != 4 || cfg.Downloads.Retries != 5 || cfg.Output.SplitSizeMiB != 3800 {
		t.Fatalf("wrong required defaults: %#v", cfg)
	}
	if _, _, err := cfg.Request(); err == nil {
		t.Fatal("default request has no update ID")
	}
	decoded, err := Decode([]byte("schema_version=1"), "minimal.toml")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, cfg) {
		t.Fatalf("omitted settings did not receive defaults: %#v", decoded)
	}
}

func TestDefaultPathUsesLocalAppData(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	got, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "UUPBuilder", "config.toml"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	t.Setenv("LOCALAPPDATA", "")
	if _, err := DefaultPath(); err == nil {
		t.Fatal("missing LOCALAPPDATA accepted")
	}
}
