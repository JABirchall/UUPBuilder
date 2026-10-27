//go:build windows

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWindowsRenameCreatesAndReplacesLongUnicodePath(t *testing.T) {
	root := filepath.Join(t.TempDir(), strings.Repeat("a", 160), strings.Repeat("b", 100))
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "日本語.toml")
	if len(path) <= 260 {
		t.Fatal("test path must exceed MAX_PATH")
	}
	cfg := Defaults()
	result, err := Save(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.BackupPath != "" || result.Normalized {
		t.Fatalf("new file result: %#v", result)
	}
	cfg.Downloads.Retries = 8
	result, err = Save(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.BackupPath == "" || !result.Normalized {
		t.Fatalf("replacement result: %#v", result)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Downloads.Retries != 8 {
		t.Fatal("replacement did not publish complete settings")
	}
}

func TestWindowsRenamePreservesFilesOnInitialCollision(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "new.tmp")
	target := filepath.Join(root, "existing.toml")
	if err := os.WriteFile(source, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(source, target, false); err == nil {
		t.Fatal("initial creation overwrote an appearing file")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("original")) {
		t.Fatal("collision changed target")
	}
}

func TestWindowsConfigPathsRejectAmbientDriveAndMalformedUNC(t *testing.T) {
	for _, path := range []string{`C:relative`, `\root-relative`, `\\server\`, `\\server\..\out`, `\\\share\out`} {
		cfg := Defaults()
		cfg.Output.Directory = path
		if err := cfg.Validate(); err == nil {
			t.Errorf("accepted ambiguous/malformed path %q", path)
		}
	}
}

func TestWindowsRenameSharingFailurePreservesOriginalAndBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "日本語 config.toml")
	original := []byte("# original\nschema_version=1\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	result, saveErr := Save(path, Defaults())
	closeErr := syscall.CloseHandle(handle)
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if saveErr == nil {
		t.Fatal("expected native sharing violation")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) || !bytes.Equal(backup, original) {
		t.Fatal("native rename failure changed original or backup")
	}
}
