package config

import (
	"os"
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

func TestDefaultPathStaysBesideExecutableWhenWorkingDirectoryAndAppDataChange(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(filepath.Dir(executable), "UUP", "config.toml")
	t.Chdir(t.TempDir())
	for _, appData := range []string{t.TempDir(), ""} {
		t.Setenv("LOCALAPPDATA", appData)
		got, err := DefaultPath()
		if err != nil || got != want {
			t.Fatalf("default path = %q, %v; want %q", got, err, want)
		}
	}
}
