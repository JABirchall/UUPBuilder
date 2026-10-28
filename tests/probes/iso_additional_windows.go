//go:build windows

package probes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/pe"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

// These two no-argument scripts have separate reviewed byte pins. The ARM64
// adapter and its script pin are deliberately independent and unchanged.
//
//go:embed scripts/master_iso_x86.ps1
var additionalISOX86Script []byte

//go:embed scripts/master_iso_amd64.ps1
var additionalISOAMD64Script []byte

type additionalISOCapsuleConfig struct {
	FixtureRoot     string             `json:"-"`
	WorkspaceParent string             `json:"-"`
	Target          string             `json:"target"`
	Inputs          []isoSourceBinding `json:"inputs"`
}

type additionalISORecipe struct {
	expectations ISOExpectations
	scriptHash   string
	scriptSize   int64
	updateID     string
	catalogBuild string
}

func additionalISOScriptSource(target string) []byte {
	switch target {
	case "x86":
		return additionalISOX86Script
	case "amd64":
		return additionalISOAMD64Script
	default:
		return nil
	}
}

func additionalISOClosedRecipe(target string) (additionalISORecipe, []isoSourceBinding, error) {
	var r additionalISORecipe
	type input struct {
		logical, sourcePath, isoPath, sha1, sha256 string
		size                                       int64
	}
	var fixed []input
	switch target {
	case "x86":
		r = additionalISORecipe{
			expectations: ISOExpectations{Volume: "P1X86", TargetMachine: 0x014c, DirectLoaderPath: "EFI/BOOT/BOOTIA32.EFI", BootImagePath: "EFI/MICROSOFT/BOOT/EFISYS.BIN", EmbeddedLoader: ISOExpectedFile{"EFI/BOOT/BOOTIA32.EFI", 985912, "db79e8cd00c252dfdc7a5517dbc09048312aad5514f3372f079041e3787c2828"}},
			scriptHash:   "8fb140f471c26efd95598b946c1336249ba63405813f4ba46f236b2b9c3d59d0", scriptSize: 6059,
			updateID: "3d12aa3e-806a-46c9-900e-bf7613959273", catalogBuild: "19045.7811",
		}
		fixed = []input{
			{"metadata.esd", "p1-image-inputs/additional-win10-x86/metadata.esd", "SOURCE/META.ESD", "747b4b216dc3db281599eabf955e408bf201a961", "edf4967f0d9f8b8703d24489f727786cd314c43a26cfdc111e5d3b8e40d13dc0", 338670400},
			{"winre-x86-19041.1.wim", "p1-additional-exports/run-native-export-pair/win10-x86-19041.1/out/winre-x86-19041.1.wim", "SOURCE/WINRE.WIM", "", "a69934cbb6e222e4b581cddaab5b5ad6928b8b34fc62cc3f8639c8e38744c1ac", 304934622},
			{"efisys.bin", "p1-image-inputs/additional-iso-inputs/4b95f56591606671eddf5562f56853c15b3cc6af.bin", "EFI/MICROSOFT/BOOT/EFISYS.BIN", "4b95f56591606671eddf5562f56853c15b3cc6af", "40e990e1eaf59f3d53c63492a6aa902ce00e03b689878e5e064bc80165fcf44e", 1474560},
			{"bootia32.efi", "p1-image-inputs/additional-iso-inputs/334134d932de92332151a4727330b3c9b58f9995.bin", "EFI/BOOT/BOOTIA32.EFI", "334134d932de92332151a4727330b3c9b58f9995", "e62f717c19abd6616c53f966965e6a8edaa86f44328d007663fc14e55f8b98fa", 1271312},
		}
	case "amd64":
		r = additionalISORecipe{
			expectations: ISOExpectations{Volume: "P1AMD64", TargetMachine: 0x8664, DirectLoaderPath: "EFI/BOOT/BOOTX64.EFI", BootImagePath: "EFI/MICROSOFT/BOOT/EFISYS.BIN", EmbeddedLoader: ISOExpectedFile{"EFI/BOOT/BOOTX64.EFI", 1037120, "7cd32d9c2b3b976b3d4546b18d8f8bbdfc7093d83220729e8b7d624a1fafa2e8"}},
			scriptHash:   "a5764c2343a023d2bcb37f46d70945a38c37e598834284febceb8d6de4e4f32e", scriptSize: 6067,
			updateID: "4ef76f77-dd31-49a8-9bb5-6de3a2115eb3", catalogBuild: "26100.9725",
		}
		fixed = []input{
			{"metadata.esd", "p1-image-inputs/additional-win11-amd64/metadata.esd", "SOURCE/META.ESD", "98014c58afbd29a57aed4f5eb6819f5cc5bce4a4", "12f5944951262ffc5e15657d4e57392c54a4b505ccd2b8917c5a02456ac8e468", 553783259},
			{"winre-amd64-26100.1.wim", "p1-additional-exports/run-native-export-pair/win11-amd64-26100.1/out/winre-amd64-26100.1.wim", "SOURCE/WINRE.WIM", "", "2e15508d1fd54384046286ea52e45ba673533f83e5aea37d031cf2d3c7305576", 486421029},
			{"efisys.bin", "p1-image-inputs/additional-iso-inputs/52c0a391c5b0ee2cbcd635c4a03ec8cca98af87b.bin", "EFI/MICROSOFT/BOOT/EFISYS.BIN", "52c0a391c5b0ee2cbcd635c4a03ec8cca98af87b", "52f407452257e3b9ce5f1ffb55c5c9ad8272532e014c22b7563e9b4a80bac7b0", 1474560},
			{"bootx64.efi", "p1-image-inputs/additional-iso-inputs/6ecab82de61eb12114c75331e79e613ba2b8f554.bin", "EFI/BOOT/BOOTX64.EFI", "6ecab82de61eb12114c75331e79e613ba2b8f554", "34347d4b7e1683f981d7b45ca660d32d9bf1cac3a20f5fdfeff6049f49a5384a", 2756512},
		}
	default:
		return r, nil, errors.New("only the closed x86 and amd64 source-data capsules are supported")
	}
	fixed = append(fixed, input{"etfsboot.com", "p1-image-inputs/source-members/62313ec73f381c052f2513ca6279cfb5107e98c0.bin", "BOOT/ETFSBOOT.COM", "62313ec73f381c052f2513ca6279cfb5107e98c0", "f425e135aac26b55e2bac655e62e2ce0b16255226c583d9ab43b2e93e8a6d932", 4096})
	var bindings []isoSourceBinding
	for i, f := range fixed {
		digest := model.Digest{Algorithm: model.DigestSHA1, Value: f.sha1}
		provenance := "Original source body/member; original SHA-1 and measured SHA-256; data only"
		if f.sha1 == "" {
			digest = model.Digest{Algorithm: model.DigestSHA256, Value: f.sha256}
			provenance = "Exact observed native index2 WinRE export; opaque LZX WIM bytes, no independent semantic decoding"
		}
		file := ISOExpectedFile{f.isoPath, f.size, f.sha256}
		bindings = append(bindings, isoSourceBinding{i + 1, f.logical, f.sourcePath, Artifact{fmt.Sprintf("%s-source-%d", target, i+1), "payload", digest, f.size, provenance}, file})
		r.expectations.Files = append(r.expectations.Files, file)
	}
	return r, bindings, nil
}

func additionalISOConfig(target, root string) (additionalISOCapsuleConfig, error) {
	_, bindings, err := additionalISOClosedRecipe(target)
	return additionalISOCapsuleConfig{root, filepath.Join(root, "p1-iso-additional-observations"), target, bindings}, err
}

func validateAdditionalISOCapsule(c additionalISOCapsuleConfig) (ISOExpectations, error) {
	r, bindings, err := additionalISOClosedRecipe(c.Target)
	if err != nil {
		return r.expectations, err
	}
	if !filepath.IsAbs(c.FixtureRoot) || filepath.Clean(c.FixtureRoot) != c.FixtureRoot || c.WorkspaceParent != filepath.Join(c.FixtureRoot, "p1-iso-additional-observations") || len(c.Inputs) != 5 {
		return r.expectations, errors.New("fixed rooted additional-capsule paths and exactly five bindings required")
	}
	for i, x := range c.Inputs {
		if x != bindings[i] {
			return r.expectations, errors.New("closed original source tuple/order/path differs")
		}
	}
	_, err = validateISOExpectations(r.expectations)
	return r.expectations, err
}

func prepareAdditionalISOScript(target string, source []byte) ([]byte, error) {
	r, _, err := additionalISOClosedRecipe(target)
	if err != nil {
		return nil, err
	}
	source = bytes.ReplaceAll(source, []byte("\r\n"), []byte("\n"))
	sum := sha256.Sum256(source)
	if int64(len(source)) != r.scriptSize || hex.EncodeToString(sum[:]) != r.scriptHash {
		return nil, errors.New("reviewed target-specific script byte pin differs")
	}
	return source, nil
}

func additionalISOCapsuleCase(config additionalISOCapsuleConfig) Case {
	r, _, _ := additionalISOClosedRecipe(config.Target)
	c := Case{ID: "P-windows-amd64-to-" + config.Target, Gate: "P", Host: HostRequirement{"windows", 10240, "amd64", "amd64"}, Target: model.Architecture(config.Target), SourceFamily: "canonical-cab-esd", Source: model.SourceIdentity{UpdateID: r.updateID, BuildLabel: r.catalogBuild, Architecture: model.Architecture(config.Target), Language: "en-us"}, RevisionProvenance: "Original resolver source; default revision 1 not independently echoed. Build label is catalogue context; setup index1 ARCH/version absent. Same-body index2 WinRE build and EFI PE target are separate observations.", Operations: []Operation{Extract, Service, Reconstruct, MasterISO}, Pending: []Blocker{{"source-capsule-only", "Five exact source-data files and target-correct EFI data do not establish full Setup/servicing/CBS/desktop or actual EFI/BIOS boot."}, {"opaque-native-wim", "Native index2 LZX WIM payload is verified as opaque bytes; independent semantic decoding remains unverified."}, {"dependency-closure-unverified", "Previously observed signed native component byte pins do not establish full loaded CLR/OS dependency closure."}, {"full-gate-unverified", "No whole-ISO expected digest or full image/servicing expectation is manufactured."}}}
	for _, x := range config.Inputs {
		c.Inputs = append(c.Inputs, x.Source)
	}
	c.Inputs = append(c.Inputs, Artifact{"iso-master-script", "metadata", model.Digest{Algorithm: model.DigestSHA256, Value: r.scriptHash}, r.scriptSize, "own source closed no-argument target-specific IMAPI2FS/IStream script; canonical LF bytes"})
	for _, p := range isoComponentPins() {
		c.Components = append(c.Components, Component{Artifact: p.artifact, NativeArchitecture: "amd64"})
	}
	return c
}

func observeAdditionalISOCapsule(ctx context.Context, config additionalISOCapsuleConfig) (e Evidence, inspection ISOInspection, runErr error) {
	config.Inputs = append([]isoSourceBinding(nil), config.Inputs...)
	expectations, err := validateAdditionalISOCapsule(config)
	if err != nil {
		return e, inspection, err
	}
	if ctx == nil {
		return e, inspection, errors.New("context required")
	}
	if err = ctx.Err(); err != nil {
		return e, inspection, err
	}
	host, err := observeHost()
	if err != nil {
		return e, inspection, err
	}
	peer, err := platform.CurrentPeerIdentity()
	if err != nil {
		return e, inspection, err
	}
	if host.Host.NativeArchitecture != "amd64" || host.Host.ProcessArchitecture != "amd64" || peer.Elevated {
		return e, inspection, errors.New("non-elevated actual native/process amd64 host required")
	}
	c := additionalISOCapsuleCase(config)
	if err = c.Validate(); err != nil {
		return e, inspection, err
	}
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return e, inspection, err
	}
	systemRoot, err := os.OpenRoot(systemDirectory)
	if err != nil {
		return e, inspection, err
	}
	defer systemRoot.Close()
	w, err := platform.CreateWorkspace(config.WorkspaceParent, c.ID)
	if err != nil {
		return e, inspection, err
	}
	e = Evidence{CaseID: c.ID, Status: Unverified, ExecutionKind: "not-executed", Host: host, RetainedWorkspace: w.Path(), Blockers: append([]Blocker(nil), c.Pending...), CaseDigest: c.Digest(), Components: append([]Component(nil), c.Components...)}
	encoded, _ := json.Marshal(config)
	runtimeSum := sha256.Sum256(encoded)
	e.RuntimeDigest = hex.EncodeToString(runtimeSum[:])
	var locks []*os.File
	var custody []RetainedArtifact
	var inspector Artifact
	defer func() {
		closeISOLocks(locks)
		_, saveErr := retainJSON(w, "run.json", "iso-additional-run", "verification-report", struct {
			Case         Case                       `json:"case"`
			Inputs       []isoSourceBinding         `json:"mapping"`
			Expectations ISOExpectations            `json:"expectations"`
			Evidence     Evidence                   `json:"evidence"`
			Custody      []RetainedArtifact         `json:"custody"`
			Inspector    Artifact                   `json:"inspector"`
			Inspection   ISOInspection              `json:"inspection"`
			Workspace    platform.WorkspaceIdentity `json:"workspace"`
			Error        string                     `json:"error,omitempty"`
		}{c, config.Inputs, expectations, e, custody, inspector, inspection, w.Identity(), errorText(runErr)})
		runErr = errors.Join(runErr, saveErr, w.Close())
	}()
	for _, dir := range []string{"media/SOURCE", "media/BOOT", "media/EFI/BOOT", "media/EFI/MICROSOFT/BOOT", "components", "scratch", "outputs", "logs", "reports"} {
		if err = w.MkdirAll(dir); err != nil {
			return e, inspection, err
		}
	}
	fs, err := platform.InspectFileSystem(w.Path())
	if err != nil {
		return e, inspection, err
	}
	e.Host.Host.FileSystem = fs
	e.Host.Report, err = retainJSON(w, "reports/host.json", "iso-host", "host-report", struct {
		Host     ObservedHost `json:"host"`
		Elevated bool         `json:"elevated"`
	}{host, peer.Elevated})
	if err != nil {
		return e, inspection, err
	}
	for _, p := range isoComponentPins() {
		f, held, err := openISOLocked(systemRoot, p.path)
		if err != nil {
			return e, inspection, err
		}
		locks = append(locks, held...)
		image, err := pe.NewFile(f)
		if err != nil {
			return e, inspection, err
		}
		machine := image.Machine
		image.Close()
		if machine != 0x8664 {
			return e, inspection, errors.New("native component PE machine differs")
		}
		retained, err := retainFile(ctx, f, w, "components/"+filepath.Base(p.path), p.artifact)
		if err != nil {
			return e, inspection, err
		}
		custody = append(custody, retained)
	}
	// Retain the exact executable which performs this independent raw inspection.
	executable, err := os.Executable()
	if err != nil {
		return e, inspection, err
	}
	codeRoot, err := os.OpenRoot(filepath.Dir(executable))
	if err != nil {
		return e, inspection, err
	}
	defer codeRoot.Close()
	code, held, err := openISOLocked(codeRoot, filepath.Base(executable))
	if err != nil {
		return e, inspection, err
	}
	locks = append(locks, held...)
	codeInfo, err := code.Stat()
	if err != nil {
		return e, inspection, err
	}
	codeHash := sha256.New()
	if _, err = io.Copy(codeHash, io.NewSectionReader(code, 0, codeInfo.Size())); err != nil {
		return e, inspection, err
	}
	inspector = Artifact{"raw-go-inspector", "executable", model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(codeHash.Sum(nil))}, codeInfo.Size(), "actual compiled Go raw inspector; independent of native producer"}
	retainedCode, err := retainFile(ctx, code, w, "components/raw-inspector.test.exe", inspector)
	if err != nil {
		return e, inspection, err
	}
	custody = append(custody, retainedCode)
	scriptBytes, err := prepareAdditionalISOScript(config.Target, additionalISOScriptSource(config.Target))
	if err != nil {
		return e, inspection, err
	}
	script, err := w.OpenFile("components/master_iso.ps1", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return e, inspection, err
	}
	_, writeErr := script.Write(scriptBytes)
	if err = errors.Join(writeErr, script.Sync(), script.Close()); err != nil {
		return e, inspection, err
	}
	sourceRoot, err := os.OpenRoot(config.FixtureRoot)
	if err != nil {
		return e, inspection, err
	}
	defer sourceRoot.Close()
	stageRoot, err := os.OpenRoot(w.Path())
	if err != nil {
		return e, inspection, err
	}
	defer stageRoot.Close()
	for _, x := range config.Inputs {
		f, held, err := openISOLocked(sourceRoot, x.SourcePath)
		if err != nil {
			return e, inspection, err
		}
		locks = append(locks, held...)
		retained, err := retainFile(ctx, f, w, "media/"+x.File.Path, x.Source)
		if err != nil {
			return e, inspection, err
		}
		if retained.SHA256 != x.File.SHA256 {
			return e, inspection, errors.New("retained source differs from pre-run measured SHA-256")
		}
		custody = append(custody, retained)
		staged, held, err := openISOLocked(stageRoot, "media/"+x.File.Path)
		if err != nil {
			return e, inspection, err
		}
		locks = append(locks, held...)
		if err = verifyISOLockedFile(staged, x.File); err != nil {
			return e, inspection, err
		}
		e.Inputs = append(e.Inputs, x.Source)
	}
	e.Inputs = append(e.Inputs, c.Inputs[len(c.Inputs)-1])
	heldScript, held, err := openISOLocked(stageRoot, "components/master_iso.ps1")
	if err != nil {
		return e, inspection, err
	}
	locks = append(locks, held...)
	if err = verifyISOLockedFile(heldScript, ISOExpectedFile{"components/master_iso.ps1", int64(len(scriptBytes)), c.Inputs[len(c.Inputs)-1].Digest.Value}); err != nil {
		return e, inspection, err
	}
	scriptAlias, err := isoReviewedScriptAlias(w.Path(), heldScript)
	if err != nil {
		return e, inspection, err
	}
	outer, held, err := openISOLocked(stageRoot, "media/"+expectations.BootImagePath)
	if err != nil {
		return e, inspection, err
	}
	locks = append(locks, held...)
	if _, err = inspectEFIFAT(outer, 1474560, expectations.EmbeddedLoader, expectations.TargetMachine); err != nil {
		return e, inspection, err
	}
	direct, held, err := openISOLocked(stageRoot, "media/"+expectations.DirectLoaderPath)
	if err != nil {
		return e, inspection, err
	}
	locks = append(locks, held...)
	if _, err = inspectEFIPE(direct, config.Inputs[3].File.Size, expectations.TargetMachine); err != nil {
		return e, inspection, err
	}
	if _, err = retainJSON(w, "reports/source-mapping.json", "iso-source-map", "verification-report", config.Inputs); err != nil {
		return e, inspection, err
	}
	if _, err = retainJSON(w, "reports/pre-run-expectations.json", "iso-source-expectations", "verification-report", expectations); err != nil {
		return e, inspection, err
	}
	started := time.Now().UTC()
	e.ExecutionKind = "component-runtime"
	arguments := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-File", scriptAlias}
	producer := filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
	nativeCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	result, nativeErr := platform.NewRunner().Run(nativeCtx, platform.Invocation{Executable: producer, Arguments: arguments, Workspace: w, JobID: w.Identity().JobID, OperationID: "master-source-capsule", Cancellation: platform.CancelTerminateTree}, nil)
	cancel()
	finished := time.Now().UTC()
	log, err := retainJSON(w, "logs/native-invocation.json", "iso-native-log", "log", struct {
		Executable string             `json:"executable"`
		Arguments  []string           `json:"arguments"`
		Result     platform.RunResult `json:"result"`
		Error      string             `json:"error,omitempty"`
	}{producer, arguments, result, errorText(nativeErr)})
	exit := int(result.ExitCode)
	e.Invocations = append(e.Invocations, Invocation{ID: "master-source-capsule", Operation: MasterISO, ComponentID: "iso-powershell", Arguments: []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-File", "$workspace/components/master_iso.ps1"}, StartedAt: started, FinishedAt: finished, ExitCode: &exit, Log: log})
	if err != nil {
		return e, inspection, err
	}
	if nativeErr != nil || result.ExitCode != 0 || result.Cancelled {
		return e, inspection, errors.Join(nativeErr, fmt.Errorf("native ISO result exit=%d cancelled=%t", result.ExitCode, result.Cancelled))
	}
	output, held, err := openISOLocked(stageRoot, "outputs/p1-"+config.Target+"-source-capsule.iso")
	if err != nil {
		return e, inspection, err
	}
	locks = append(locks, held...)
	info, err := output.Stat()
	if err != nil {
		return e, inspection, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 2<<30 || info.Size()%2048 != 0 {
		return e, inspection, errors.New("native output exceeds regular/aligned/2 GiB contract")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, io.NewSectionReader(output, 0, info.Size())); err != nil {
		return e, inspection, err
	}
	artifact := Artifact{config.Target + "-source-capsule", "output", model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(hash.Sum(nil))}, info.Size(), "actual native source-data capsule; content inspected separately"}
	e.Outputs = append(e.Outputs, Output{artifact, "master-source-capsule"})
	inspection, err = InspectISO(output, info.Size(), expectations)
	if err != nil {
		return e, inspection, err
	}
	if inspection.SHA256 != artifact.Digest.Value {
		return e, inspection, errors.New("outer ISO hash changed during independent inspection")
	}
	if _, err = retainJSON(w, "reports/raw-inspection.json", "iso-raw-inspection", "verification-report", struct {
		Inspector  Artifact      `json:"inspector"`
		Inspection ISOInspection `json:"inspection"`
	}{inspector, inspection}); err != nil {
		return e, inspection, err
	}
	// Operational completion is separate from full feasibility: the Evidence
	// remains Unverified and the caller must independently reject the full gate.
	// The deferred receipt/close joins can still make this return fail.
	return e, inspection, nil
}

func additionalISOObservationError(e Evidence, inspection ISOInspection, want ISOExpectations, runErr error) error {
	if runErr != nil {
		return fmt.Errorf("additional ISO observation operational failure: %w", runErr)
	}
	if e.Status != Unverified || e.ExecutionKind != "component-runtime" || len(e.Invocations) != 1 || len(e.Outputs) != 1 || len(e.Verifications) != 0 || len(inspection.ISOFiles) != 5 || len(inspection.UDFFiles) != 5 || inspection.EmbeddedMachine != want.TargetMachine || inspection.DirectMachine != want.TargetMachine || inspection.Size <= 0 || inspection.Size > 2<<30 {
		return errors.New("actual closed source-capsule execution/raw inspection incomplete; stop and preserve retained output")
	}
	return nil
}
