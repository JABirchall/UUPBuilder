//go:build windows && providerproof

package probes

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func additionalISOActualConfig(t *testing.T, target string) additionalISOCapsuleConfig {
	t.Helper()
	root := os.Getenv("P1_ADDITIONAL_ISO_PLAN")
	if !filepath.IsAbs(root) {
		t.Fatal("explicit retained plan root required")
	}
	c, err := additionalISOConfig(target, filepath.Clean(root))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = validateAdditionalISOCapsule(c); err != nil {
		t.Fatal(err)
	}
	return c
}

// This test only reads original data and writes a descriptor in the ignored
// observation directory. It cannot stage or invoke the native producer.
func TestAdditionalISOReadRetainedInputs(t *testing.T) {
	for _, target := range []string{"x86", "amd64"} {
		c := additionalISOActualConfig(t, target)
		e, _ := validateAdditionalISOCapsule(c)
		func() {
			root, err := os.OpenRoot(c.FixtureRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			var locks []*os.File
			defer func() { closeISOLocks(locks) }()
			for i, x := range c.Inputs {
				f, held, err := openISOLocked(root, x.SourcePath)
				if err != nil {
					t.Fatal(err)
				}
				locks = append(locks, held...)
				if err = verifyISOLockedFile(f, x.File); err != nil {
					t.Fatal(err)
				}
				if x.Source.Digest.Algorithm == "sha1" {
					h := sha1.New()
					if _, err = io.Copy(h, io.NewSectionReader(f, 0, x.File.Size)); err != nil {
						t.Fatal(err)
					}
					if hex.EncodeToString(h.Sum(nil)) != x.Source.Digest.Value {
						t.Fatal("original source SHA-1 differs")
					}
				}
				if i == 2 {
					if _, err = inspectEFIFAT(f, x.File.Size, e.EmbeddedLoader, e.TargetMachine); err != nil {
						t.Fatal(err)
					}
				}
				if i == 3 {
					if _, err = inspectEFIPE(f, x.File.Size, e.TargetMachine); err != nil {
						t.Fatal(err)
					}
				}
			}
		}()
		descriptor, err := json.MarshalIndent(struct {
			Config       additionalISOCapsuleConfig `json:"config"`
			Expectations ISOExpectations            `json:"expectations"`
			Case         Case                       `json:"case"`
		}{c, e, additionalISOCapsuleCase(c)}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(c.WorkspaceParent, "pre-run-"+target+"-descriptor.json")
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := f.Write(descriptor)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("descriptor write failed: %v %v", writeErr, closeErr)
		}
		t.Logf("%s: five original source tuples verified; embedded/direct PE=%#x; descriptor=%s", target, e.TargetMachine, path)
	}
}

func TestAdditionalISOObserveX86SourceCapsule(t *testing.T) {
	observeAdditionalISOActual(t, "x86")
}

func TestAdditionalISOObserveAMD64SourceCapsule(t *testing.T) {
	observeAdditionalISOActual(t, "amd64")
}

func observeAdditionalISOActual(t *testing.T, target string) {
	t.Helper()
	c := additionalISOActualConfig(t, target)
	e, inspection, runErr := observeAdditionalISOCapsule(context.Background(), c)
	want, _ := validateAdditionalISOCapsule(c)
	t.Logf("actual %s native ISO observation: status=%s kind=%s ISO9660=%d UDF=%d bytes=%d sha256=%s embedded=%#x direct=%#x retained=%s error=%v", target, e.Status, e.ExecutionKind, len(inspection.ISOFiles), len(inspection.UDFFiles), inspection.Size, inspection.SHA256, inspection.EmbeddedMachine, inspection.DirectMachine, e.RetainedWorkspace, runErr)
	if err := additionalISOObservationError(e, inspection, want, runErr); err != nil {
		t.Fatal(err)
	}
	if ValidateEvidence([]Case{additionalISOCapsuleCase(c)}, []Evidence{e}) == nil {
		t.Fatal("component ISO observation opened full feasibility gate")
	}
	public, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{c.FixtureRoot, e.RetainedWorkspace, "localPath", "Token"} {
		if strings.Contains(string(public), private) {
			t.Fatalf("private locator leaked to public Evidence: %s", private)
		}
	}
}
