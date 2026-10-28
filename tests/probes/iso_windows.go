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
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

//go:embed scripts/master_iso.ps1
var isoMasterScript []byte

const isoScriptSHA256 = "c808f99cf11708163e0fe20a059d0fc60d3e62298209d7dc09e9d8752511df66"
const isoScriptBytes int64 = 6069

func prepareISOMasterScript(source []byte) ([]byte, error) {
	// Git may check text out as CRLF. Canonicalize only line endings, then
	// enforce the reviewed exact LF byte pin and retain those executed bytes.
	source = bytes.ReplaceAll(source, []byte("\r\n"), []byte("\n"))
	sum := sha256.Sum256(source)
	if hex.EncodeToString(sum[:]) != isoScriptSHA256 {
		return nil, errors.New("reviewed native script pin differs")
	}
	return source, nil
}

type isoSourceBinding struct {
	Ordinal     int             `json:"ordinal"`
	LogicalName string          `json:"logical_name"`
	SourcePath  string          `json:"-"`
	Source      Artifact        `json:"source"`
	File        ISOExpectedFile `json:"file"`
}
type isoCapsuleConfig struct {
	FixtureRoot     string             `json:"-"`
	WorkspaceParent string             `json:"-"`
	Inputs          []isoSourceBinding `json:"inputs"`
}

func fmtISOInputPath(i int, ext string) string { return fmt.Sprintf("UUP/P%04d%s", i, ext) }
func validateISOCapsule(c isoCapsuleConfig) (ISOExpectations, error) {
	e := ISOExpectations{Volume: "P1ARM64", TargetMachine: 0xaa64, DirectLoaderPath: "EFI/BOOT/BOOTAA64.EFI", BootImagePath: "EFI/MICROSOFT/BOOT/EFISYS.BIN", EmbeddedLoader: ISOExpectedFile{"EFI/BOOT/BOOTAA64.EFI", 919352, "6e0cd6daaaea939e89072e5f932d62aada8b248ad0cf6c1a6dd9220db048e1c7"}}
	if !filepath.IsAbs(c.FixtureRoot) || !filepath.IsAbs(c.WorkspaceParent) || len(c.Inputs) != 48 {
		return e, errors.New("explicit roots and exactly 48 frozen source bindings required")
	}
	for i, x := range c.Inputs {
		if _, err := model.ValidateRelativePath(x.SourcePath); err != nil {
			return e, err
		}
		if err := x.Source.validate("payload"); err != nil {
			return e, err
		}
		if x.Ordinal != i+1 || x.Source.Digest.Algorithm != model.DigestSHA1 || x.Source.Size != x.File.Size || x.LogicalName == "" || strings.ContainsAny(x.LogicalName, "\\/:?&#\x00\r\n") || len(x.LogicalName) > 256 {
			return e, errors.New("invalid source order, logical name, size or original SHA-1 binding")
		}
		if i < 46 {
			ext := strings.ToUpper(filepath.Ext(x.LogicalName))
			if !oneOf(ext, ".ESD", ".CAB") || x.File.Path != fmtISOInputPath(i, ext) {
				return e, errors.New("source mapping must use frozen-order 8.3 UUP names")
			}
		}
		if i == 46 && (x.File.Path != e.BootImagePath || x.File.Size != 1720320 || x.File.SHA256 != "5338212289453b3f14d6baa27fd29caa12cd76df34ba5c764465fd4790c0063d" || x.Source.Digest.Value != "afa41ad91e4fa10cfde33e6d7ad3eb99f3513728") {
			return e, errors.New("original ARM64 outer EFI binding differs")
		}
		if i == 47 && (x.File.Path != e.DirectLoaderPath || x.File.Size != 1745232 || x.File.SHA256 != "452d8f3f8dc638a81f2abb9c2759a1075f2750c164db0538b0dcc50e56bce890" || x.Source.Digest.Value != "c7359b13001376a18d75167a2a03a73f6df4901a") {
			return e, errors.New("original ARM64 direct EFI binding differs")
		}
		e.Files = append(e.Files, x.File)
	}
	_, err := validateISOExpectations(e)
	return e, err
}

// NtCreateFile is relative to already opened directory handles and refuses
// every reparse traversal. Retained directory handles deny rename/deletion;
// file handles additionally deny writing through any alias throughout use.
func openISOLocked(root *os.Root, path string) (file *os.File, locks []*os.File, err error) {
	n, err := model.ValidateRelativePath(path)
	if err != nil {
		return nil, nil, err
	}
	parent, err := root.Open(".")
	if err != nil {
		return nil, nil, err
	}
	locks = append(locks, parent)
	defer func() {
		if err != nil {
			closeISOLocks(locks)
			locks = nil
		}
	}()
	parts := strings.Split(n, "/")
	for i, part := range parts {
		name, e := windows.NewNTUnicodeString(part)
		if e != nil {
			err = e
			return nil, locks, err
		}
		attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(parent.Fd()), ObjectName: name, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
		attributes.Length = uint32(unsafe.Sizeof(attributes))
		share := uint32(windows.FILE_SHARE_READ)
		options := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
		if i < len(parts)-1 {
			share |= windows.FILE_SHARE_WRITE
			options |= windows.FILE_DIRECTORY_FILE
		} else {
			options |= windows.FILE_NON_DIRECTORY_FILE
		}
		var h windows.Handle
		err = windows.NtCreateFile(&h, windows.FILE_GENERIC_READ, &attributes, &windows.IO_STATUS_BLOCK{}, nil, windows.FILE_ATTRIBUTE_NORMAL, share, windows.FILE_OPEN, options, 0, 0)
		if status, ok := err.(windows.NTStatus); ok {
			err = status.Errno()
		}
		if err != nil {
			return nil, locks, err
		}
		file = os.NewFile(uintptr(h), part)
		locks = append(locks, file)
		var info windows.ByHandleFileInformation
		if err = windows.GetFileInformationByHandle(h, &info); err != nil {
			return nil, locks, err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			err = errors.New("reparse source/staged object rejected")
			return nil, locks, err
		}
		parent = file
	}
	return file, locks, nil
}
func closeISOLocks(locks []*os.File) {
	for i := len(locks) - 1; i >= 0; i-- {
		locks[i].Close()
	}
}

func isoReviewedScriptAlias(root string, held *os.File) (string, error) {
	// PowerShell's AuthorizationManager rejects a relative -File resolved from
	// the extended-prefix W1 cwd on this host. Only this fixed same-object alias
	// is allowed; this is not a filesystem namespace fallback or policy bypass.
	if held == nil || len(root) < 7 || !strings.HasPrefix(root, `\\?\`) || root[5] != ':' || root[6] != '\\' || !(root[4] >= 'A' && root[4] <= 'Z' || root[4] >= 'a' && root[4] <= 'z') {
		return "", errors.New("ordinary local drive alias required")
	}
	plain := root[4:]
	if filepath.Clean(plain) != plain || strings.ContainsAny(plain, "\x00\r\n\"/*?") || strings.Contains(plain[2:], ":") {
		return "", errors.New("ambiguous local script alias")
	}
	alias := filepath.Join(plain, "components", "master_iso.ps1")
	if len(alias) >= 260 {
		return "", errors.New("PowerShell script alias exceeds reviewed Win32 path limit")
	}
	pointer, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var expected, actual windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(windows.Handle(held.Fd()), &expected); err != nil {
		return "", err
	}
	if err = windows.GetFileInformationByHandle(h, &actual); err != nil {
		return "", err
	}
	if actual.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || actual.VolumeSerialNumber != expected.VolumeSerialNumber || actual.FileIndexHigh != expected.FileIndexHigh || actual.FileIndexLow != expected.FileIndexLow {
		return "", errors.New("script alias differs from rooted held file identity")
	}
	return alias, nil
}

func isoComponentPins() []struct {
	path     string
	artifact Artifact
} {
	return []struct {
		path     string
		artifact Artifact
	}{
		{"WindowsPowerShell/v1.0/powershell.exe", Artifact{"iso-powershell", "executable", model.Digest{Algorithm: model.DigestSHA256, Value: "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3"}, 455680, "current-host native inbox Windows PowerShell adapter"}},
		{"imapi2fs.dll", Artifact{"iso-imapi2fs", "dll", model.Digest{Algorithm: model.DigestSHA256, Value: "9d6142f338128aa9f48b4cb8f86b104ebb8ef6c6d0c4aed27687d309647d3c43"}, 1005568, "current-host native inbox IMAPI2FS producer"}},
		{"shlwapi.dll", Artifact{"iso-shlwapi", "dll", model.Digest{Algorithm: model.DigestSHA256, Value: "60cdefacf1b269e6a120dae805979d6da9954f0dfd4f3102c3a8736f1b30c7a3"}, 382864, "current-host native inbox SHCreateStreamOnFileEx adapter"}},
	}
}

func isoCapsuleCase(config isoCapsuleConfig) Case {
	c := Case{ID: "P-windows-amd64-to-arm64", Gate: "P", Host: HostRequirement{"windows", 10240, "amd64", "amd64"}, Target: "arm64", SourceFamily: "canonical-cab-esd", Source: model.SourceIdentity{UpdateID: "a1b78728-530f-443f-b672-d742e7c14bcb", BuildLabel: "22000.1", Architecture: "arm64", Language: "en-us"}, RevisionProvenance: "Frozen original resolver selection; default revision 1 requested, Microsoft revision not independently echoed.", Operations: []Operation{Extract, Service, Reconstruct, MasterISO}, Pending: []Blocker{{"source-capsule-only", "Actual source capsule bytes/EFI data cannot establish Windows Setup, serviced boot.wim, desktop CBS changes or actual boot execution."}, {"dependency-closure-unverified", "Pinned producer/script bytes do not establish full loaded CLR/OS dependency closure."}, {"full-gate-unverified", "No frozen whole-ISO expected hash or full image/servicing expectation is manufactured for this component observation."}}}
	for _, x := range config.Inputs {
		c.Inputs = append(c.Inputs, x.Source)
	}
	c.Inputs = append(c.Inputs, Artifact{"iso-master-script", "metadata", model.Digest{Algorithm: model.DigestSHA256, Value: isoScriptSHA256}, isoScriptBytes, "own source fixed IMAPI2FS/IStream script; canonical LF bytes"})
	for _, p := range isoComponentPins() {
		c.Components = append(c.Components, Component{Artifact: p.artifact, NativeArchitecture: "amd64"})
	}
	return c
}

func observeISOCapsule(ctx context.Context, config isoCapsuleConfig) (e Evidence, inspection ISOInspection, runErr error) {
	config.Inputs = append([]isoSourceBinding(nil), config.Inputs...)
	expectations, err := validateISOCapsule(config)
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
	if host.Host.NativeArchitecture != "amd64" || host.Host.ProcessArchitecture != "amd64" {
		return e, inspection, errors.New("actual native/process amd64 host required")
	}
	peer, err := platform.CurrentPeerIdentity()
	if err != nil {
		return e, inspection, err
	}
	if peer.Elevated {
		return e, inspection, errors.New("non-elevated native ISO observation required")
	}
	c := isoCapsuleCase(config)
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
	e = Evidence{CaseID: c.ID, Status: Unverified, ExecutionKind: "not-executed", Host: host, RetainedWorkspace: w.Path(), Blockers: append([]Blocker(nil), c.Pending...)}
	var locks []*os.File
	var custody []RetainedArtifact
	defer func() {
		closeISOLocks(locks)
		_, saveErr := retainJSON(w, "run.json", "iso-run", "verification-report", struct {
			Case         Case                       `json:"case"`
			Inputs       []isoSourceBinding         `json:"mapping"`
			Expectations ISOExpectations            `json:"expectations"`
			Evidence     Evidence                   `json:"evidence"`
			Custody      []RetainedArtifact         `json:"custody"`
			Inspection   ISOInspection              `json:"inspection"`
			Workspace    platform.WorkspaceIdentity `json:"workspace"`
			Error        string                     `json:"error,omitempty"`
		}{c, config.Inputs, expectations, e, custody, inspection, w.Identity(), errorText(runErr)})
		runErr = errors.Join(runErr, saveErr, w.Close())
	}()
	for _, dir := range []string{"media/UUP", "media/EFI/BOOT", "media/EFI/MICROSOFT/BOOT", "components", "scratch", "outputs", "logs", "reports"} {
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
	if err = c.Validate(); err != nil {
		return e, inspection, err
	}
	e.CaseDigest = c.Digest()
	e.Components = append([]Component(nil), c.Components...)
	encoded, _ := json.Marshal(config)
	runtimeSum := sha256.Sum256(encoded)
	e.RuntimeDigest = hex.EncodeToString(runtimeSum[:])
	scriptBytes, err := prepareISOMasterScript(isoMasterScript)
	if err != nil {
		return e, inspection, err
	}
	script, err := w.OpenFile("components/master_iso.ps1", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return e, inspection, err
	}
	_, writeErr := script.Write(scriptBytes)
	err = errors.Join(writeErr, script.Sync(), script.Close())
	if err != nil {
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
	scriptAlias, err := isoReviewedScriptAlias(w.Path(), heldScript)
	if err != nil {
		return e, inspection, err
	}
	// Independently inspect source-bound EFI roles before native mastering.
	outer, err := w.OpenFile("media/"+expectations.BootImagePath, os.O_RDONLY, 0)
	if err != nil {
		return e, inspection, err
	}
	_, sourceBootErr := inspectEFIFAT(outer, 1720320, expectations.EmbeddedLoader, 0xaa64)
	closeErr := outer.Close()
	if err = errors.Join(sourceBootErr, closeErr); err != nil {
		return e, inspection, err
	}
	direct, err := w.OpenFile("media/"+expectations.DirectLoaderPath, os.O_RDONLY, 0)
	if err != nil {
		return e, inspection, err
	}
	_, sourcePEErr := inspectEFIPE(direct, 1745232, 0xaa64)
	closeErr = direct.Close()
	if err = errors.Join(sourcePEErr, closeErr); err != nil {
		return e, inspection, err
	}
	_, err = retainJSON(w, "reports/source-mapping.json", "iso-source-map", "verification-report", config.Inputs)
	if err != nil {
		return e, inspection, err
	}
	_, err = retainJSON(w, "reports/pre-run-expectations.json", "iso-source-expectations", "verification-report", expectations)
	if err != nil {
		return e, inspection, err
	}
	started := time.Now().UTC()
	e.ExecutionKind = "component-runtime"
	nativeCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	result, nativeErr := platform.NewRunner().Run(nativeCtx, platform.Invocation{Executable: filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"), Arguments: []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-File", scriptAlias}, Workspace: w, JobID: w.Identity().JobID, OperationID: "master-source-capsule", Cancellation: platform.CancelTerminateTree}, nil)
	cancel()
	finished := time.Now().UTC()
	log, err := retainJSON(w, "logs/native-invocation.json", "iso-native-log", "log", struct {
		Executable string             `json:"executable"`
		Arguments  []string           `json:"arguments"`
		Result     platform.RunResult `json:"result"`
		Error      string             `json:"error,omitempty"`
	}{filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"), []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-File", scriptAlias}, result, errorText(nativeErr)})
	exit := int(result.ExitCode)
	e.Invocations = append(e.Invocations, Invocation{ID: "master-source-capsule", Operation: MasterISO, ComponentID: "iso-powershell", Arguments: []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-File", "$workspace/components/master_iso.ps1"}, StartedAt: started, FinishedAt: finished, ExitCode: &exit, Log: log})
	if err != nil {
		return e, inspection, err
	}
	if nativeErr != nil || result.ExitCode != 0 || result.Cancelled {
		return e, inspection, errors.Join(nativeErr, fmt.Errorf("native ISO result exit=%d cancelled=%t", result.ExitCode, result.Cancelled))
	}
	output, held, err := openISOLocked(stageRoot, "outputs/p1-arm64-source-capsule.iso")
	if err != nil {
		return e, inspection, err
	}
	locks = append(locks, held...)
	info, err := output.Stat()
	if err != nil {
		return e, inspection, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > isoLimit || info.Size()%2048 != 0 {
		return e, inspection, errors.New("native output exceeds regular/aligned/5 GiB contract")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, io.NewSectionReader(output, 0, info.Size())); err != nil {
		return e, inspection, err
	}
	artifact := Artifact{"arm64-source-capsule", "output", model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(hash.Sum(nil))}, info.Size(), "actual native IMAPI2FS source-capsule output; content inspected separately"}
	e.Outputs = append(e.Outputs, Output{artifact, "master-source-capsule"})
	inspection, err = InspectISO(output, info.Size(), expectations)
	if err != nil {
		return e, inspection, err
	}
	if inspection.SHA256 != artifact.Digest.Value {
		return e, inspection, errors.New("outer ISO hash changed during independent inspection")
	}
	_, err = retainJSON(w, "reports/raw-inspection.json", "iso-raw-inspection", "verification-report", inspection)
	if err != nil {
		return e, inspection, err
	}
	return e, inspection, errors.New("specific ISO filesystem/content/EFI-data inspection succeeded; full Windows Setup/servicing/Gate P/S remain unverified")
}
func verifyISOLockedFile(f *os.File, want ISOExpectedFile) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != want.Size {
		return errors.New("locked staged file size/type differs")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(f, 0, want.Size))
	if err != nil {
		return err
	}
	if n != want.Size || hex.EncodeToString(h.Sum(nil)) != want.SHA256 {
		return errors.New("locked staged bytes differ")
	}
	return nil
}
