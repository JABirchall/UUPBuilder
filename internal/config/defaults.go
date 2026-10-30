package config

import (
	"fmt"
	"os"
	"path/filepath"

	"uupbuilder/internal/model"
)

// Defaults returns a fresh browsing configuration. A source must be chosen
// before Request succeeds. These values do not depend on the host architecture.
func Defaults() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Catalog:       CatalogSettings{Endpoint: "https://api.uupdump.net"},
		Image:         model.Selection{Architecture: model.ArchitectureAMD64, Language: "en-us", Editions: []string{"professional"}},
		Conversion: model.ConversionSettings{
			Updates: model.UpdatesIntegrate, ServicingStrategy: model.ServicingAuto,
			CumulativeUpdates: model.ExpansionAuto, CheckpointUpdates: model.ExpansionAuto,
			EnablementPackages: model.InclusionAuto, Cleanup: true, ResetBase: model.ResetBaseOff,
			IncludeWinRE: false, WinREUpdates: model.InclusionOmit, BootWIMEngine: model.BootWIMAuto,
			ReferenceImages: model.ReferenceAuto, CumulativeMSU: model.MSUAuto,
			Drivers:  model.DriverSettings{Targets: []model.DriverTarget{}},
			Editions: model.EditionSettings{Derived: []string{}, Strategy: model.ServicingAuto, PreserveRequiredBases: true},
		},
		Apps:      model.AppSettings{Mode: model.AppsDefault, StubPolicy: model.AppStubAuto, Include: []string{}, Edge: model.EdgeDefault},
		Output:    model.OutputSettings{Kind: model.OutputISO, ImageFormat: model.ImageWIM, SplitSizeMiB: 3800, Directory: ".", Filename: "auto", Label: "auto", EditionOrder: []string{}},
		Downloads: model.DownloadSettings{ParallelFiles: 4, Retries: 5, Proxy: model.ProxySettings{Mode: model.ProxySystem}},
		Storage:   model.StorageSettings{Workspace: "auto", Cache: "auto", KeepDownloads: true},
	}
}

// DefaultDirectory returns the portable data directory beside the executable.
// Resolving it never creates a directory or depends on the working directory.
func DefaultDirectory() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable for portable UUP directory: %w", err)
	}
	return absoluteConfigPath(filepath.Join(filepath.Dir(executable), "UUP"))
}

// DefaultPath matches the executable's --config default without creating it.
func DefaultPath() (string, error) {
	base, err := DefaultDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "config.toml"), nil
}
