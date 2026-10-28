//go:build windows

package probes

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	platform "uupbuilder/internal/platform/windows"
)

func TestAdditionalISOCompletionRejectsRetentionErrors(t *testing.T) {
	w, err := platform.CreateWorkspace(t.TempDir(), "additional-iso-retention-failure")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err = w.MkdirAll("reports"); err != nil {
		t.Fatal(err)
	}
	// Fully populated component results must never hide failures which happen
	// after raw inspection. Use real exclusive-create report retention errors.
	e := Evidence{Status: Unverified, ExecutionKind: "component-runtime", Invocations: make([]Invocation, 1), Outputs: make([]Output, 1)}
	inspection := ISOInspection{ISOFiles: make([]ISOExpectedFile, 5), UDFFiles: make([]ISOExpectedFile, 5), EmbeddedMachine: 0x014c, DirectMachine: 0x014c, Size: 2048}
	want := ISOExpectations{TargetMachine: 0x014c}
	for _, path := range []string{"reports/raw-inspection.json", "run.json"} {
		t.Run(path, func(t *testing.T) {
			if _, err := retainJSON(w, path, "report", "verification-report", struct{}{}); err != nil {
				t.Fatal(err)
			}
			_, retentionErr := retainJSON(w, path, "report", "verification-report", struct{}{})
			if !errors.Is(retentionErr, os.ErrExist) {
				t.Fatalf("exclusive-create retention failure not reproduced: %v", retentionErr)
			}
			for _, operationalErr := range []error{retentionErr, errors.Join(errors.New("prior failure"), retentionErr)} {
				if got := additionalISOObservationError(e, inspection, want, operationalErr); got == nil || !errors.Is(got, retentionErr) {
					t.Fatalf("fully populated inspection lost mandatory retention failure: %v", got)
				}
			}
		})
	}
	if err = additionalISOObservationError(e, inspection, want, nil); err != nil {
		t.Fatalf("completed component observation requires nil operational error: %v", err)
	}
	if e.Status != Unverified || e.ExecutionKind != "component-runtime" || len(e.Verifications) != 0 {
		t.Fatal("operational completion promoted component evidence")
	}
}

func TestAdditionalISOClosedRecipeRejectsSubstitutions(t *testing.T) {
	for _, target := range []string{"x86", "amd64"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			c, err := additionalISOConfig(target, root)
			if err != nil {
				t.Fatal(err)
			}
			e, err := validateAdditionalISOCapsule(c)
			if err != nil || len(e.Files) != 5 {
				t.Fatalf("closed five-file capsule rejected: %v", err)
			}
			for _, mutate := range []func(*additionalISOCapsuleConfig){
				func(c *additionalISOCapsuleConfig) { c.Target = "arm64" },
				func(c *additionalISOCapsuleConfig) { c.WorkspaceParent = filepath.Join(root, "other") },
				func(c *additionalISOCapsuleConfig) { c.Inputs[0].SourcePath = "../metadata.esd" },
				func(c *additionalISOCapsuleConfig) { c.Inputs[1].SourcePath = c.Inputs[0].SourcePath },
				func(c *additionalISOCapsuleConfig) { c.Inputs[0].Source.Size++ },
				func(c *additionalISOCapsuleConfig) { c.Inputs[0].File.SHA256 = strings.Repeat("0", 64) },
				func(c *additionalISOCapsuleConfig) { c.Inputs[2].Source.Digest.Value = strings.Repeat("0", 40) },
				func(c *additionalISOCapsuleConfig) { c.Inputs[3].File.Path = "EFI/BOOT/OTHER.EFI" },
				func(c *additionalISOCapsuleConfig) { c.Inputs = c.Inputs[:4] },
			} {
				bad := c
				bad.Inputs = append([]isoSourceBinding(nil), c.Inputs...)
				mutate(&bad)
				if _, err := validateAdditionalISOCapsule(bad); err == nil {
					t.Fatal("substituted closed recipe accepted")
				}
			}
			proof := additionalISOCapsuleCase(c)
			if err := proof.Validate(); err != nil {
				t.Fatal(err)
			}
			if len(proof.Expected) != 0 || proof.DependencyClosureComplete || proof.ValidateReady() == nil || ValidateEvidence([]Case{proof}, []Evidence{{CaseID: proof.ID, Status: Unverified, ExecutionKind: "component-runtime"}}) == nil {
				t.Fatal("source-data recipe fabricated full media/gate proof")
			}
		})
	}
	for _, bad := range []string{"", "arm64", "386", "AMD64", "x86 -File other.ps1"} {
		if _, err := additionalISOConfig(bad, t.TempDir()); err == nil {
			t.Fatalf("open selector accepted: %q", bad)
		}
	}
}

func TestAdditionalISOScriptPinsRejectChangesAndCrossPairing(t *testing.T) {
	for _, target := range []string{"x86", "amd64"} {
		script, err := prepareAdditionalISOScript(target, additionalISOScriptSource(target))
		if err != nil || len(script) == 0 || bytes.Contains(script, []byte("\r\n")) {
			t.Fatalf("reviewed canonical script rejected: %s %v", target, err)
		}
		if _, err = prepareAdditionalISOScript(target, bytes.ReplaceAll(script, []byte("\n"), []byte("\r\n"))); err != nil {
			t.Fatal(err)
		}
		changed := append([]byte(nil), script...)
		changed[0] ^= 1
		if _, err = prepareAdditionalISOScript(target, changed); err == nil {
			t.Fatal("changed executed script bytes accepted")
		}
		other := "x86"
		if target == "x86" {
			other = "amd64"
		}
		if _, err = prepareAdditionalISOScript(other, script); err == nil {
			t.Fatal("cross-paired script accepted")
		}
	}
	if _, err := prepareAdditionalISOScript("arm64", []byte("data")); err == nil {
		t.Fatal("unapproved script selector accepted")
	}
}
