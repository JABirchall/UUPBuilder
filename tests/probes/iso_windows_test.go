//go:build windows

package probes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

func TestISOCapsuleBindingRejectsWrongOrderPathsOrHashes(t *testing.T) {
	c := isoSyntheticConfig(t)
	if _, err := validateISOCapsule(c); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*isoCapsuleConfig)
	}{
		{"source-escape", func(c *isoCapsuleConfig) { c.Inputs[0].SourcePath = "../outside.cab" }},
		{"namespace-collision", func(c *isoCapsuleConfig) { c.Inputs[1].File.Path = c.Inputs[0].File.Path }},
		{"unstable-order", func(c *isoCapsuleConfig) { c.Inputs[0].Ordinal = 2 }},
		{"missing-source-digest", func(c *isoCapsuleConfig) { c.Inputs[0].Source.Digest.Value = "" }},
		{"wrong-local-sha256", func(c *isoCapsuleConfig) { c.Inputs[0].File.SHA256 = "" }},
		{"wrong-boot-role", func(c *isoCapsuleConfig) { c.Inputs[46].File.Path = "EFI/BOOT/BOOTAA64.EFI" }},
		{"private-logical-name", func(c *isoCapsuleConfig) { c.Inputs[0].LogicalName = "https://example.invalid/token?x=secret" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := isoSyntheticConfig(t)
			tc.mutate(&c)
			if _, err := validateISOCapsule(c); err == nil {
				t.Fatal("invalid capsule binding accepted")
			}
		})
	}
}

func isoSyntheticConfig(t *testing.T) isoCapsuleConfig {
	t.Helper()
	c := isoCapsuleConfig{FixtureRoot: t.TempDir(), WorkspaceParent: t.TempDir()}
	for i := 0; i < 48; i++ {
		name := fmtISOInputPath(i, ".CAB")
		logical := "source.cab"
		if i == 46 {
			name = "EFI/MICROSOFT/BOOT/EFISYS.BIN"
			logical = "efisys.bin"
		}
		if i == 47 {
			name = "EFI/BOOT/BOOTAA64.EFI"
			logical = "bootaa64.efi"
		}
		c.Inputs = append(c.Inputs, isoSourceBinding{Ordinal: i + 1, LogicalName: logical, SourcePath: strings.ReplaceAll(name, "/", "_"), Source: Artifact{ID: "input-" + strings.ReplaceAll(name, "/", "-"), Role: "payload", Size: 7, Digest: model.Digest{Algorithm: model.DigestSHA1, Value: strings.Repeat("1", 40)}, Provenance: "synthetic original hash declaration"}, File: ISOExpectedFile{name, 7, strings.Repeat("2", 64)}})
	}
	c.Inputs[46].Source.Size = 1720320
	c.Inputs[46].Source.Digest.Value = "afa41ad91e4fa10cfde33e6d7ad3eb99f3513728"
	c.Inputs[46].File.Size = 1720320
	c.Inputs[46].File.SHA256 = "5338212289453b3f14d6baa27fd29caa12cd76df34ba5c764465fd4790c0063d"
	c.Inputs[47].Source.Size = 1745232
	c.Inputs[47].Source.Digest.Value = "c7359b13001376a18d75167a2a03a73f6df4901a"
	c.Inputs[47].File.Size = 1745232
	c.Inputs[47].File.SHA256 = "452d8f3f8dc638a81f2abb9c2759a1075f2750c164db0538b0dcc50e56bce890"
	return c
}

func TestISOCustodyLocksVerifiedSourceAndStagedBytes(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "source.cab"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, locks, err := openISOLocked(root, "source.cab")
	if err != nil {
		t.Fatal(err)
	}
	defer closeISOLocks(locks)
	if err = os.WriteFile(filepath.Join(rootPath, "source.cab"), []byte("changed"), 0600); err == nil {
		t.Fatal("source changed while locked")
	}
	if err = os.Rename(filepath.Join(rootPath, "source.cab"), filepath.Join(rootPath, "other.cab")); err == nil {
		t.Fatal("source replaced while locked")
	}
	workspace, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer workspace.Close()
	s := sha256.Sum256([]byte("payload"))
	want := hex.EncodeToString(s[:])
	a := Artifact{ID: "source", Role: "payload", Size: 7, Digest: model.Digest{Algorithm: model.DigestSHA256, Value: want}, Provenance: "synthetic custody fixture"}
	got, err := retainFile(context.Background(), f, workspace, "retained.cab", a)
	if err != nil || got.SHA256 != want {
		t.Fatalf("retention mismatch: %+v %v", got, err)
	}
}

func TestISOCustodyRejectsReparseAndTraversal(t *testing.T) {
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, path := range []string{"../out", "/absolute", "a/../../out"} {
		if _, locks, err := openISOLocked(root, path); err == nil {
			closeISOLocks(locks)
			t.Fatalf("unsafe path %s accepted", path)
		}
	}
	if err = os.Mkdir(filepath.Join(rootPath, "real"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(rootPath, "real", "data"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(rootPath, "real"), filepath.Join(rootPath, "link")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, locks, err := openISOLocked(root, "link/data"); err == nil {
		closeISOLocks(locks)
		t.Fatal("reparse ancestor accepted")
	}
}

func TestISOCapsuleDescriptorDoesNotFabricateFullProof(t *testing.T) {
	c := isoCapsuleCase(isoSyntheticConfig(t))
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.Expected) != 0 || c.DependencyClosureComplete || c.ValidateReady() == nil {
		t.Fatal("component descriptor fabricated full media proof")
	}
}

func TestISOReviewedScriptAliasRequiresSameHeldObject(t *testing.T) {
	w, err := platform.CreateWorkspace(t.TempDir(), "iso-reviewed-script-alias")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err = w.MkdirAll("components"); err != nil {
		t.Fatal(err)
	}
	f, err := w.OpenFile("components/master_iso.ps1", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("Write-Output 'own-script-path-ok'\r\n")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	root, err := os.OpenRoot(w.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	held, locks, err := openISOLocked(root, "components/master_iso.ps1")
	if err != nil {
		t.Fatal(err)
	}
	defer closeISOLocks(locks)
	alias, err := isoReviewedScriptAlias(w.Path(), held)
	if err != nil || !filepath.IsAbs(alias) || strings.HasPrefix(alias, `\\`) {
		t.Fatalf("ordinary absolute alias missing: %q %v", alias, err)
	}
	other, err := os.CreateTemp(t.TempDir(), "different")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = isoReviewedScriptAlias(w.Path(), other); err == nil {
		t.Fatal("alias to a different file identity accepted")
	}
	for _, bad := range []string{`\\?\UNC\server\share\root`, `\\.\C:\root`, `C:relative`, `\\?\C:\root\..\other`, `\\?\C:\` + strings.Repeat("x", 260)} {
		if _, err = isoReviewedScriptAlias(bad, held); err == nil {
			t.Fatalf("ambiguous/unsupported alias accepted: %q", bad)
		}
	}
}

func TestISOScriptPinRejectsChangesAcrossCheckoutLineEndings(t *testing.T) {
	lf := bytes.ReplaceAll(isoMasterScript, []byte("\r\n"), []byte("\n"))
	for _, source := range [][]byte{lf, bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))} {
		script, err := prepareISOMasterScript(source)
		if err != nil || int64(len(script)) != isoScriptBytes || bytes.Contains(script, []byte("\r\n")) {
			t.Fatalf("canonical executed bytes differ: %d %v", len(script), err)
		}
	}
	changed := append([]byte(nil), isoMasterScript...)
	changed[0] ^= 1
	if _, err := prepareISOMasterScript(changed); err == nil {
		t.Fatal("changed native script passed fixed pin")
	}
}
