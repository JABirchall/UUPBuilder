package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDoesNotOverwriteMalformedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := []byte("# Keep my settings\nschema_version=1\n[bad\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("malformed file accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("load changed original bytes")
	}
}

func TestLoadResolvesPathsAndMissingFileIsReadOnly(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.toml")
	if _, err := Load(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Load created missing file")
	}
	if err := os.WriteFile(path, fixture(t, "complete"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Output.Directory != filepath.Join(root, "output") {
		t.Fatalf("Load did not resolve paths: %s", cfg.Output.Directory)
	}
}

func TestSaveBacksUpExactOriginalAndReportsNormalization(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.toml")
	original := []byte("# handwritten comment\nschema_version=1\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := Save(path, Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Normalized || result.BackupPath == "" {
		t.Fatalf("missing rewrite information: %#v", result)
	}
	backup, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backup, original) {
		t.Fatal("backup lost original comments/bytes")
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	second, err := Save(path, Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if second.Normalized || second.BackupPath != "" {
		t.Fatalf("unchanged bytes should avoid rewrite: %#v", second)
	}
}

func TestFailedSavePreservesOriginal(t *testing.T) {
	for _, stage := range []string{"write", "sync", "close", "backup", "backup-write", "backup-sync", "backup-close", "rename"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "config.toml")
			oldBackup := path + ".bak"
			original := []byte("# exact original\nschema_version=1\n")
			priorBackup := []byte("previous backup")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(oldBackup, priorBackup, 0600); err != nil {
				t.Fatal(err)
			}
			ops := diskOps()
			failure := errors.New("injected " + stage + " failure")
			create := ops.createTemp
			ops.createTemp = func(dir, pattern string) (saveFile, error) {
				if stage == "backup" && pattern == "config.toml.bak-*" {
					return nil, failure
				}
				f, err := create(dir, pattern)
				if err != nil {
					return nil, err
				}
				if pattern == ".config.toml.tmp-*" {
					return &failingSaveFile{saveFile: f, stage: stage, err: failure}, nil
				}
				if pattern == "config.toml.bak-*" && strings.HasPrefix(stage, "backup-") {
					return &failingSaveFile{saveFile: f, stage: strings.TrimPrefix(stage, "backup-"), err: failure}, nil
				}
				return f, nil
			}
			if stage == "rename" {
				ops.rename = func(string, string, bool) error { return failure }
			}
			result, err := saveWithOps(path, Defaults(), ops)
			if !errors.Is(err, failure) {
				t.Fatalf("got %v, want injected failure", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			backup, err := os.ReadFile(oldBackup)
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(after) != sha256.Sum256(original) || sha256.Sum256(backup) != sha256.Sum256(priorBackup) {
				t.Fatal("failed save changed original or previous backup")
			}
			if stage == "rename" {
				newBackup, err := os.ReadFile(result.BackupPath)
				if err != nil {
					t.Fatal(err)
				}
				if sha256.Sum256(newBackup) != sha256.Sum256(original) {
					t.Fatal("new backup differs from original")
				}
			}
			temps, err := filepath.Glob(filepath.Join(root, ".config.toml.tmp-*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(temps) != 0 {
				t.Fatalf("temporary file leaked: %v", temps)
			}
		})
	}
}

type failingSaveFile struct {
	saveFile
	stage string
	err   error
}

func (f *failingSaveFile) Write(p []byte) (int, error) {
	if f.stage == "write" {
		n, _ := f.saveFile.Write(p[:len(p)/2])
		return n, f.err
	}
	return f.saveFile.Write(p)
}
func (f *failingSaveFile) Sync() error {
	if f.stage == "sync" {
		return f.err
	}
	return f.saveFile.Sync()
}
func (f *failingSaveFile) Close() error {
	err := f.saveFile.Close()
	if f.stage == "close" {
		return f.err
	}
	return err
}

var _ io.Writer = (*failingSaveFile)(nil)

func TestSaveInvalidConfigDoesNotTouchFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := []byte("original")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	cfg.Downloads.ParallelFiles = 0
	if _, err := Save(path, cfg); err == nil {
		t.Fatal("invalid config saved")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, original) {
		t.Fatal("invalid save changed original")
	}
}
