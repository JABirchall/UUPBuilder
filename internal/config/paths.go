package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"uupbuilder/internal/model"
)

func absoluteConfigPath(path string) (string, error) {
	if err := validateApplicationPath(path); err != nil {
		return "", fmt.Errorf("config path: %w", err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve config path: %w", err)
	}
	return absolute, nil
}

// validateApplicationPath validates user-chosen filesystem paths lexically.
// Parent-directory components are valid here; these are not owned payload
// destinations. Actual volume capabilities/reparse checks belong to preflight.
func validateApplicationPath(value string) error {
	if value == "" || !utf8.ValidString(value) || value != strings.TrimSpace(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return errors.New("must be a nonempty path without surrounding whitespace or controls")
	}
	// Device/extended namespaces and drive-relative paths depend on ambient state
	// or bypass ordinary Win32 validation. Accept normal absolute, UNC and relative
	// paths, including . and .. directory navigation.
	slash := strings.ReplaceAll(value, `\`, "/")
	if strings.HasPrefix(slash, "//?/") || strings.HasPrefix(slash, "//./") {
		return errors.New("device and extended path namespaces are not supported")
	}
	if len(slash) >= 2 && slash[1] == ':' {
		if !((slash[0] >= 'A' && slash[0] <= 'Z') || (slash[0] >= 'a' && slash[0] <= 'z')) || len(slash) < 3 || slash[2] != '/' {
			return errors.New("drive paths must be absolute")
		}
		slash = slash[3:]
	} else if strings.HasPrefix(slash, "//") {
		slash = slash[2:]
		parts := strings.Split(slash, "/")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return errors.New("UNC path requires a server and share")
		}
		if _, err := model.ValidateRelativePath(parts[0] + "/" + parts[1]); err != nil {
			return fmt.Errorf("UNC server/share: %w", err)
		}
	} else {
		if filepath.Separator == '\\' && strings.HasPrefix(slash, "/") {
			return errors.New("root-relative Windows paths require an explicit drive or UNC share")
		}
		slash = strings.TrimPrefix(slash, "/")
	}
	for _, part := range strings.Split(slash, "/") {
		if part == "" || part == "." || part == ".." {
			continue
		}
		if _, err := model.ValidateRelativePath(part); err != nil {
			return err
		}
	}
	return nil
}

// ResolvePaths returns a copy with filesystem paths relative to the config
// directory made absolute. Policy markers, output filename and label are not
// filesystem roots and remain unchanged. No filesystem writes are performed.
func ResolvePaths(cfg Config, configPath string) (Config, error) {
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	path, err := absoluteConfigPath(configPath)
	if err != nil {
		return Config{}, err
	}
	root := filepath.Dir(path)
	resolve := func(value string) string {
		if filepath.IsAbs(value) {
			return filepath.Clean(value)
		}
		return filepath.Join(root, value)
	}
	if cfg.Conversion.Drivers.Source != "" {
		cfg.Conversion.Drivers.Source = resolve(cfg.Conversion.Drivers.Source)
	}
	cfg.Output.Directory = resolve(cfg.Output.Directory)
	if cfg.Storage.Workspace != "auto" {
		cfg.Storage.Workspace = resolve(cfg.Storage.Workspace)
	}
	if cfg.Storage.Cache != "auto" {
		cfg.Storage.Cache = resolve(cfg.Storage.Cache)
	}
	return cfg, nil
}
