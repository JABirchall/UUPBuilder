// Package config owns the versioned, editable TOML settings boundary. Source
// applicability is resolved later; explicit requests remain intact here.
package config

import (
	"fmt"

	"uupbuilder/internal/model"
)

const SchemaVersion = 1

type CatalogSettings struct {
	Endpoint string `toml:"endpoint"`
}

type Config struct {
	SchemaVersion int                      `toml:"schema_version"`
	Catalog       CatalogSettings          `toml:"catalog"`
	Image         model.Selection          `toml:"image"`
	Conversion    model.ConversionSettings `toml:"conversion"`
	Apps          model.AppSettings        `toml:"apps"`
	Output        model.OutputSettings     `toml:"output"`
	Downloads     model.DownloadSettings   `toml:"downloads"`
	Storage       model.StorageSettings    `toml:"storage"`
}

// Error identifies a TOML source and key. Line and Column are one-based; zero
// means the key was absent or the configuration did not come from a document.
type Error struct {
	Filename string
	Key      string
	Line     int
	Column   int
	Err      error
}

func (e *Error) Error() string {
	location := e.Filename
	if location == "" {
		location = "config"
	}
	if e.Line > 0 {
		location = fmt.Sprintf("%s:%d:%d", location, e.Line, e.Column)
	}
	if e.Key != "" {
		return fmt.Sprintf("%s: %s: %v", location, e.Key, e.Err)
	}
	return fmt.Sprintf("%s: %v", location, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// SaveResult describes the rewrite, including on a failed publication after
// backup creation. Normalized is true only when existing bytes were rewritten.
type SaveResult struct {
	BackupPath string
	Normalized bool
}
