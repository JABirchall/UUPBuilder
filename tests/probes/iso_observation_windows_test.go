//go:build windows && providerproof

package probes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

// Reinspection never reruns the producer or edits the original failed record.
// Exact outer bytes, inspector binary identity and a new result are retained.
func TestISOInspectRetainedARM64Capsule(t *testing.T) {
	path := os.Getenv("P1_ISO_RETAINED_RUN")
	if !filepath.IsAbs(path) {
		t.Fatal("explicit retained W1 run required")
	}
	b, err := os.ReadFile(filepath.Join(path, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	var original struct {
		Case         Case                       `json:"case"`
		Evidence     Evidence                   `json:"evidence"`
		Expectations ISOExpectations            `json:"expectations"`
		Workspace    platform.WorkspaceIdentity `json:"workspace"`
	}
	if err = json.Unmarshal(b, &original); err != nil {
		t.Fatal(err)
	}
	w, err := platform.OpenWorkspace(original.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	root, err := os.OpenRoot(w.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, locks, err := openISOLocked(root, "outputs/p1-arm64-source-capsule.iso")
	if err != nil {
		t.Fatal(err)
	}
	defer closeISOLocks(locks)
	const outer = "f82c4b242f2a3da7dbbb04cbf082e2ae3c96c80f7ecb7882a00327109a9106fe"
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 3241803776 {
		t.Fatal("actual immutable outer size differs")
	}
	digest := func() string {
		h := sha256.New()
		if _, err := io.Copy(h, io.NewSectionReader(f, 0, info.Size())); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	before := digest()
	if before != outer {
		t.Fatal("actual immutable outer digest differs")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	code, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer code.Close()
	codeInfo, err := code.Stat()
	if err != nil {
		t.Fatal(err)
	}
	codeHash := sha256.New()
	if _, err = io.Copy(codeHash, code); err != nil {
		t.Fatal(err)
	}
	codeSHA := hex.EncodeToString(codeHash.Sum(nil))
	if _, err = code.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	codeArtifact := Artifact{"raw-go-inspector", "executable", model.Digest{Algorithm: model.DigestSHA256, Value: codeSHA}, codeInfo.Size(), "actual compiled Go inspector test binary; independent of IMAPI producer"}
	if _, err = retainFile(context.Background(), code, w, "components/raw-inspector-"+codeSHA[:16]+".test.exe", codeArtifact); err != nil {
		t.Fatal(err)
	}
	inspection, inspectErr := InspectISO(f, info.Size(), original.Expectations)
	after := digest()
	report := "reports/reinspection-" + codeSHA[:16] + ".json"
	_, err = retainJSON(w, report, "raw-reinspection", "verification-report", struct {
		Before     string        `json:"outer_before"`
		After      string        `json:"outer_after"`
		Code       Artifact      `json:"inspector"`
		Inspection ISOInspection `json:"inspection"`
		Error      string        `json:"error,omitempty"`
		Scope      string        `json:"scope"`
	}{before, after, codeArtifact, inspection, errorText(inspectErr), "source-capsule format/content/EFI data only; full Windows Setup/servicing/boot/Gate P/S unverified"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("retained raw reinspection: ISO9660=%d UDF=%d bytes=%d sha256=%s embedded=%#x direct=%#x code=%s report=%s error=%v", len(inspection.ISOFiles), len(inspection.UDFFiles), inspection.Size, inspection.SHA256, inspection.EmbeddedMachine, inspection.DirectMachine, codeSHA, report, inspectErr)
	if inspectErr != nil {
		t.Fatal(inspectErr)
	}
	if before != after || inspection.SHA256 != outer || len(inspection.ISOFiles) != 48 || len(inspection.UDFFiles) != 48 || inspection.EmbeddedMachine != 0xaa64 || inspection.DirectMachine != 0xaa64 {
		t.Fatal("raw independent source-capsule inspection incomplete")
	}
	if original.Evidence.Status != Unverified || original.Evidence.ExecutionKind != "component-runtime" || len(original.Evidence.Verifications) != 0 || ValidateEvidence([]Case{original.Case}, []Evidence{original.Evidence}) == nil {
		t.Fatal("reinspection fabricated full gate evidence")
	}
}

func TestISOCharacterizesSingleEFISetter(t *testing.T) {
	plan := os.Getenv("P1_ISO_PLAN_ROOT")
	if !filepath.IsAbs(plan) {
		t.Fatal("explicit own-plan root required")
	}
	w, err := platform.CreateWorkspace(filepath.Join(plan, "p1-iso-observations"), "iso-single-efi-setter")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	t.Logf("retained setter characterization: %s", w.Path())
	if err = w.MkdirAll("components"); err != nil {
		t.Fatal(err)
	}
	if err = w.MkdirAll("scratch"); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(filepath.Join(plan, "p1-image-inputs"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	source, locks, err := openISOLocked(root, "source-members/afa41ad91e4fa10cfde33e6d7ad3eb99f3513728.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer closeISOLocks(locks)
	expected := Artifact{"original-efi", "payload", model.Digest{Algorithm: model.DigestSHA1, Value: "afa41ad91e4fa10cfde33e6d7ad3eb99f3513728"}, 1720320, "original ARM64 WIM EFI image"}
	retained, err := retainFile(context.Background(), source, w, "efisys.bin", expected)
	if err != nil || retained.SHA256 != "5338212289453b3f14d6baa27fd29caa12cd76df34ba5c764465fd4790c0063d" {
		t.Fatalf("source pin failed: %+v %v", retained, err)
	}
	script := []byte(`Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class P1SingleEFI {
 [DllImport("shlwapi.dll",CharSet=CharSet.Unicode,PreserveSig=false)]
 private static extern void SHCreateStreamOnFileEx(string path,uint mode,uint attributes,bool create,IntPtr template,out IStream stream);
 public static object Open(string path) { IStream stream; SHCreateStreamOnFileEx(path,0x20,0x80,false,IntPtr.Zero,out stream); return stream; }
}
'@
$root=[IO.Directory]::GetParent($PSScriptRoot).FullName
$stream=[P1SingleEFI]::Open([IO.Path]::Combine($root,'efisys.bin'))
$image=New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$image.WorkingDirectory=[IO.Path]::Combine($root,'scratch')
$boot=New-Object -ComObject IMAPI2FS.BootOptions
$boot.AssignBootImage($stream)
$boot.Emulation=0
$boot.PlatformId=0xef
$boot.Manufacturer='P1 ARM64 source data'
$image.BootImageOptions=$boot
$readback=$image.BootImageOptions
if($readback.ImageSize -ne 1720320 -or $readback.PlatformId -ne 0xef -or $readback.Emulation -ne 0){throw 'Single EFI setter/readback differs'}
[ordered]@{imageSize=[long]$readback.ImageSize;platform=[int]$readback.PlatformId;emulation=[int]$readback.Emulation;setter='IFileSystemImage.BootImageOptions';isoCreated=$false}|ConvertTo-Json -Compress
`)
	sum := sha256.Sum256(script)
	f, err := w.OpenFile("components/master_iso.ps1", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(script); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	stage, err := os.OpenRoot(w.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	held, stageLocks, err := openISOLocked(stage, "components/master_iso.ps1")
	if err != nil {
		t.Fatal(err)
	}
	defer closeISOLocks(stageLocks)
	_, efiLocks, err := openISOLocked(stage, "efisys.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer closeISOLocks(efiLocks)
	alias, err := isoReviewedScriptAlias(w.Path(), held)
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	systemRoot, err := os.OpenRoot(system)
	if err != nil {
		t.Fatal(err)
	}
	defer systemRoot.Close()
	for _, p := range isoComponentPins() {
		component, held, err := openISOLocked(systemRoot, p.path)
		if err != nil {
			t.Fatal(err)
		}
		defer closeISOLocks(held)
		if _, err = retainFile(context.Background(), component, w, "components/"+filepath.Base(p.path), p.artifact); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, runErr := platform.NewRunner().Run(ctx, platform.Invocation{Executable: filepath.Join(system, "WindowsPowerShell/v1.0/powershell.exe"), Arguments: []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-File", alias}, Workspace: w, JobID: w.Identity().JobID, OperationID: "single-efi-setter", Cancellation: platform.CancelTerminateTree}, nil)
	_, saveErr := retainJSON(w, "setter-result.json", "setter-result", "verification-report", struct {
		ScriptSHA256 string             `json:"script_sha256"`
		Source       RetainedArtifact   `json:"source"`
		Result       platform.RunResult `json:"result"`
		Error        string             `json:"error,omitempty"`
	}{hex.EncodeToString(sum[:]), retained, result, errorText(runErr)})
	if saveErr != nil {
		t.Fatal(saveErr)
	}
	t.Logf("actual setter result: exit=%d stdout=%s stderr=%s error=%v", result.ExitCode, result.Stdout, result.Stderr, runErr)
	if runErr != nil || result.ExitCode != 0 {
		t.Fatal("single EFI setter characterization failed")
	}
	var facts struct {
		ImageSize  int64 `json:"imageSize"`
		Platform   int   `json:"platform"`
		Emulation  int   `json:"emulation"`
		ISOCreated bool  `json:"isoCreated"`
	}
	if err = json.Unmarshal([]byte(result.Stdout), &facts); err != nil || facts.ImageSize != 1720320 || facts.Platform != 0xef || facts.Emulation != 0 || facts.ISOCreated {
		t.Fatalf("readback facts differ: %+v %v", facts, err)
	}
}

// This opt-in characterization executes only a harmless own script, never
// IMAPI/mastering. It does not impose script-policy assumptions on the suite.
func TestISOPowerShellReadsSameOwnedScriptByOrdinaryAbsolutePath(t *testing.T) {
	w, err := platform.CreateWorkspace(t.TempDir(), "iso-script-path-boundary")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	f, err := w.OpenFile("probe.ps1", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("Write-Output 'own-script-path-ok'\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	plain := strings.TrimPrefix(w.Path(), `\\?\`)
	if len(plain) < 3 || plain[1] != ':' || plain[2] != '\\' {
		t.Fatal("ordinary local drive path required")
	}
	for _, path := range []string{"probe.ps1", filepath.Join(plain, "probe.ps1")} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		result, runErr := platform.NewRunner().Run(ctx, platform.Invocation{Executable: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Arguments: []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-File", path}, Workspace: w, JobID: w.Identity().JobID, OperationID: "own-script-path", Cancellation: platform.CancelTerminateTree}, nil)
		cancel()
		t.Logf("absolute=%t exit=%d stdout=%q stderr=%q err=%v", filepath.IsAbs(path), result.ExitCode, result.Stdout, result.Stderr, runErr)
		if filepath.IsAbs(path) && (runErr != nil || result.ExitCode != 0 || strings.TrimSpace(result.Stdout) != "own-script-path-ok") {
			t.Fatal("ordinary absolute owned script did not execute")
		}
	}
}

// This opt-in test performs the specifically reviewed, non-elevated source
// capsule operation. Passing its byte checks deliberately leaves Evidence
// unverified; it is not serviced Windows Setup media or actual boot evidence.
func TestProviderMastersARM64SourceCapsule(t *testing.T) {
	plan := os.Getenv("P1_ISO_PLAN_ROOT")
	if !filepath.IsAbs(plan) {
		t.Fatal("explicit P1_ISO_PLAN_ROOT required")
	}
	config := isoCapsuleConfig{FixtureRoot: filepath.Join(plan, "p1-image-inputs"), WorkspaceParent: filepath.Join(plan, "p1-iso-observations")}
	var acquisition struct {
		ExpectedFiles int   `json:"expectedFiles"`
		ExpectedBytes int64 `json:"expectedBytes"`
		Files         []struct {
			Name          string `json:"name"`
			Ordinal       int    `json:"ordinal"`
			ExpectedBytes int64  `json:"expectedBytes"`
			ExpectedSHA1  string `json:"expectedSha1"`
			Bytes         int64  `json:"bytes"`
			SHA1          string `json:"sha1"`
			SHA256        string `json:"sha256"`
			LocalPath     string `json:"localPath"`
		} `json:"files"`
	}
	b, err := os.ReadFile(filepath.Join(config.FixtureRoot, "22000-arm64-full-selection-acquisition.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &acquisition); err != nil {
		t.Fatal(err)
	}
	if acquisition.ExpectedFiles != 46 || len(acquisition.Files) != 46 || acquisition.ExpectedBytes != 3235249321 {
		t.Fatal("original frozen source selection differs")
	}
	var total int64
	for i, f := range acquisition.Files {
		if f.Ordinal != i+1 || f.ExpectedBytes != f.Bytes || f.ExpectedSHA1 != f.SHA1 {
			t.Fatal("original declared and observed acquisition identities differ")
		}
		relative, err := filepath.Rel(config.FixtureRoot, f.LocalPath)
		if err != nil {
			t.Fatal(err)
		}
		config.Inputs = append(config.Inputs, isoSourceBinding{i + 1, f.Name, filepath.ToSlash(relative), Artifact{fmt.Sprintf("source-%04d", i), "payload", model.Digest{Algorithm: model.DigestSHA1, Value: f.ExpectedSHA1}, f.ExpectedBytes, "Original frozen ARM64 22000.1 resolver file: " + f.Name}, ISOExpectedFile{fmtISOInputPath(i, strings.ToUpper(filepath.Ext(f.Name))), f.ExpectedBytes, f.SHA256}})
		total += f.ExpectedBytes
	}
	if total != acquisition.ExpectedBytes {
		t.Fatal("source selection total differs")
	}
	for i, f := range []struct {
		name, sha1, sha256, path string
		size                     int64
	}{{"efisys.bin", "afa41ad91e4fa10cfde33e6d7ad3eb99f3513728", "5338212289453b3f14d6baa27fd29caa12cd76df34ba5c764465fd4790c0063d", "EFI/MICROSOFT/BOOT/EFISYS.BIN", 1720320}, {"bootaa64.efi", "c7359b13001376a18d75167a2a03a73f6df4901a", "452d8f3f8dc638a81f2abb9c2759a1075f2750c164db0538b0dcc50e56bce890", "EFI/BOOT/BOOTAA64.EFI", 1745232}} {
		config.Inputs = append(config.Inputs, isoSourceBinding{47 + i, f.name, "source-members/" + f.sha1 + ".bin", Artifact{"source-" + f.name, "payload", model.Digest{Algorithm: model.DigestSHA1, Value: f.sha1}, f.size, "Original WIM index1 source ARM64 22000.1 EFI member: " + f.name}, ISOExpectedFile{f.path, f.size, f.sha256}})
	}
	e, inspection, runErr := observeISOCapsule(context.Background(), config)
	t.Logf("actual native ISO observation: status=%s kind=%s ISO9660=%d UDF=%d bytes=%d sha256=%s embedded=%#x direct=%#x retained=%s error=%v", e.Status, e.ExecutionKind, len(inspection.ISOFiles), len(inspection.UDFFiles), inspection.Size, inspection.SHA256, inspection.EmbeddedMachine, inspection.DirectMachine, e.RetainedWorkspace, runErr)
	if runErr == nil || e.Status != Unverified || e.ExecutionKind != "component-runtime" || len(e.Invocations) != 1 || len(e.Outputs) != 1 || len(e.Verifications) != 0 || len(inspection.ISOFiles) != 48 || len(inspection.UDFFiles) != 48 || inspection.EmbeddedMachine != 0xaa64 || inspection.DirectMachine != 0xaa64 {
		t.Fatal("actual capsule native execution/raw inspection incomplete")
	}
	if ValidateEvidence([]Case{isoCapsuleCase(config)}, []Evidence{e}) == nil {
		t.Fatal("component ISO observation opened full feasibility gate")
	}
	public, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{config.FixtureRoot, e.RetainedWorkspace, "localPath", "Token"} {
		if strings.Contains(string(public), private) {
			t.Fatalf("private locator leaked to public evidence: %s", private)
		}
	}
}
