package config

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"uupbuilder/internal/model"
)

func TestISODefaultsDoNotRequestExcludedRecovery(t *testing.T) {
	minimal, err := Decode([]byte("schema_version = 1\n"), "minimal.toml")
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]Config{"fresh": Defaults(), "omitted": minimal} {
		t.Run(name, func(t *testing.T) {
			cfg.Image.UpdateID = "source-uuid_rev.2"
			_, settings, err := cfg.Request()
			if err != nil {
				t.Fatal(err)
			}
			if settings.Output.Kind != model.OutputISO || settings.Conversion.IncludeWinRE || settings.Conversion.WinREUpdates != model.InclusionOmit {
				t.Fatalf("fresh ISO request includes excluded recovery: output=%s include_winre=%v winre_updates=%s", settings.Output.Kind, settings.Conversion.IncludeWinRE, settings.Conversion.WinREUpdates)
			}
		})
	}
}

func TestLegacyExcludedSettingsRemainReadable(t *testing.T) {
	for _, kind := range []string{"image", "directory"} {
		for _, recovery := range []struct {
			include bool
			updates string
		}{{true, "auto"}, {true, "include"}, {true, "omit"}, {false, "auto"}, {false, "include"}, {false, "omit"}} {
			t.Run(fmt.Sprintf("%s/%v/%s", kind, recovery.include, recovery.updates), func(t *testing.T) {
				data := fmt.Sprintf(`schema_version = 1
[image]
update_id = "legacy-source_rev.3"
[conversion]
include_winre = %v
winre_updates = %q
[conversion.drivers]
enabled = true
source = "drivers"
targets = ["winre"]
[output]
kind = %q
`, recovery.include, recovery.updates, kind)
				cfg, err := Decode([]byte(data), "legacy.toml")
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "legacy.toml")
				if _, err := Save(path, cfg); err != nil {
					t.Fatal(err)
				}
				loaded, err := Load(path)
				if err != nil {
					t.Fatal(err)
				}
				_, settings, err := loaded.Request()
				if err != nil {
					t.Fatal(err)
				}
				if string(settings.Output.Kind) != kind || settings.Conversion.IncludeWinRE != recovery.include || string(settings.Conversion.WinREUpdates) != recovery.updates || !reflect.DeepEqual(settings.Conversion.Drivers.Targets, []model.DriverTarget{"winre"}) {
					t.Fatalf("explicit legacy request was coerced: %+v", settings)
				}
			})
		}
	}
}
