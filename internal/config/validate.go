package config

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"uupbuilder/internal/model"
)

// Validate checks the schema and structural policy syntax. An incomplete image
// selection is valid while browsing; Request additionally requires build inputs.
// Source-dependent combinations are retained for applicability resolution.
func (cfg Config) Validate() error {
	if cfg.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version: unsupported version %d; supported version is %d", cfg.SchemaVersion, SchemaVersion)
	}
	u, err := url.Parse(cfg.Catalog.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return errors.New("catalog.endpoint: expected an HTTP or HTTPS base URL without credentials, query or fragment")
	}
	// Only the private validation copy receives stand-ins for absent selection
	// fields. The public configuration and Request never receive these values.
	draft := cfg.Image
	if draft.UpdateID == "" {
		draft.UpdateID = "draft"
	}
	if draft.Architecture == "" {
		draft.Architecture = "draft"
	}
	if draft.Language == "" {
		draft.Language = "draft"
	}
	if len(draft.Editions) == 0 {
		draft.Editions = []string{"draft"}
	}
	if err := draft.Validate(); err != nil {
		if strings.HasPrefix(err.Error(), "architecture") {
			return fmt.Errorf("image.%w", err)
		}
		return err
	}
	if err := cfg.settings().Validate(); err != nil {
		return err
	}
	for _, field := range []struct {
		key, value     string
		optional, auto bool
	}{
		{"conversion.drivers.source", cfg.Conversion.Drivers.Source, true, false},
		{"output.directory", cfg.Output.Directory, false, false},
		{"storage.workspace", cfg.Storage.Workspace, false, true},
		{"storage.cache", cfg.Storage.Cache, false, true},
	} {
		if field.optional && field.value == "" || field.auto && field.value == "auto" {
			continue
		}
		if err := validateApplicationPath(field.value); err != nil {
			return fmt.Errorf("%s: %w", field.key, err)
		}
	}
	return nil
}

func (cfg Config) settings() model.ResolvedSettings {
	return model.ResolvedSettings{Conversion: cfg.Conversion, Apps: cfg.Apps, Output: cfg.Output, Storage: cfg.Storage, Downloads: cfg.Downloads}
}

// Request returns an independent typed request, requiring a complete selection.
// It does not resolve source applicability or replace any explicit policy.
func (cfg Config) Request() (model.Selection, model.ResolvedSettings, error) {
	if err := cfg.Validate(); err != nil {
		return model.Selection{}, model.ResolvedSettings{}, err
	}
	if err := cfg.Image.Validate(); err != nil {
		return model.Selection{}, model.ResolvedSettings{}, err
	}
	selection := cfg.Image
	selection.Editions = slices.Clone(selection.Editions)
	settings := cfg.settings()
	settings.Conversion.Drivers.Targets = slices.Clone(settings.Conversion.Drivers.Targets)
	settings.Conversion.Editions.Derived = slices.Clone(settings.Conversion.Editions.Derived)
	settings.Apps.Include = slices.Clone(settings.Apps.Include)
	settings.Output.EditionOrder = slices.Clone(settings.Output.EditionOrder)
	return selection, settings, nil
}
