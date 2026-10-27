package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

type saveFile interface {
	io.Writer
	Sync() error
	Close() error
	Name() string
}

type saveOps struct {
	createTemp func(string, string) (saveFile, error)
	rename     func(string, string, bool) error
}

func diskOps() saveOps {
	return saveOps{createTemp: func(dir, pattern string) (saveFile, error) { return os.CreateTemp(dir, pattern) }, rename: replaceFile}
}

// Save writes canonical TOML. It syncs/closes a same-directory replacement and
// a unique byte-exact backup before publishing the new file with one rename.
// Existing backups are never overwritten. A failed publication returns the
// completed BackupPath, if any. The containing directory must already exist.
func Save(path string, cfg Config) (SaveResult, error) {
	return saveWithOps(path, cfg, diskOps())
}

func saveWithOps(path string, cfg Config, ops saveOps) (result SaveResult, err error) {
	if err := cfg.Validate(); err != nil {
		return result, err
	}
	path, err = absoluteConfigPath(path)
	if err != nil {
		return result, err
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		return result, fmt.Errorf("encode config: %w", err)
	}
	original, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return result, fmt.Errorf("read original config: %w", err)
	}
	if exists && bytes.Equal(original, data) {
		return result, nil
	}
	dir, base := filepath.Dir(path), filepath.Base(path)
	replacement, err := ops.createTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return result, fmt.Errorf("create config replacement: %w", err)
	}
	defer os.Remove(replacement.Name())
	if err := writeSynced(replacement, data); err != nil {
		return result, fmt.Errorf("write config replacement: %w", err)
	}
	if exists {
		backup, err := ops.createTemp(dir, base+".bak-*")
		if err != nil {
			return result, fmt.Errorf("create config backup: %w", err)
		}
		if err := writeSynced(backup, original); err != nil {
			os.Remove(backup.Name())
			return result, fmt.Errorf("write config backup: %w", err)
		}
		result.BackupPath = backup.Name()
	}
	if err := ops.rename(replacement.Name(), path, exists); err != nil {
		return result, fmt.Errorf("publish config: %w", err)
	}
	result.Normalized = exists
	return result, nil
}

func writeSynced(file saveFile, data []byte) error {
	n, err := file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}
