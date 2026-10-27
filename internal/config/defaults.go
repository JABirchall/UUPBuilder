package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

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
			IncludeWinRE: true, WinREUpdates: model.InclusionAuto, BootWIMEngine: model.BootWIMAuto,
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

// DefaultPath matches the executable's --config default. It does not create
// the directory or file, and an unavailable LOCALAPPDATA is an error.
func DefaultPath() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if strings.TrimSpace(base) == "" {
		return "", errors.New("LOCALAPPDATA is unavailable; specify --config PATH")
	}
	return absoluteConfigPath(filepath.Join(base, "UUPBuilder", "config.toml"))
}
