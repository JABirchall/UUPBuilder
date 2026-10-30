package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// Execute default-path tests from a disposable copy of this test executable.
// Even go test -c users can run these tests without touching a real sibling UUP.
func portableTestProcess(t *testing.T) bool {
	t.Helper()
	if os.Getenv("UUP_BUILDER_PORTABLE_TEST") == t.Name() {
		return false
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), filepath.Base(executable))
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v")
	command.Dir = t.TempDir()
	command.Env = append(os.Environ(), "UUP_BUILDER_PORTABLE_TEST="+t.Name(), "LOCALAPPDATA="+t.TempDir())
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated portable test: %v\n%s", err, out)
	}
	return true
}

func portableDirectory(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(filepath.Dir(executable), "UUP")
}
