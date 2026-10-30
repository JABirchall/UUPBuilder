package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/engine/rules"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/tools"
)

// DISM borrows an owned workspace for process lifetime, logs, expansion and
// scratch. It never services the running OS or requests elevation. Close after
// all mounts have been unmounted; the caller retains workspace cleanup custody.
type DISM struct {
	workspace    *platform.Workspace
	runner       platform.ProcessRunner
	session      *platform.SessionRunner
	dism, expand *installedExecutable
	mu           sync.Mutex
	closed       bool
	runtime      *tools.SelectedRuntime
	edgeSource   string
	edgeSamples  map[string]string
}
type installedExecutable struct {
	path, digest string
	file         *os.File
	size         int64
}

// NewManagedDISM borrows the complete pinned runtime lease. It only opens
// executable files; the caller must keep the lease alive through all mounts.
func NewManagedDISM(ctx context.Context, workspace *platform.Workspace, runtime *tools.SelectedRuntime) (*DISM, error) {
	if runtime == nil || runtime.Build() == 0 || runtime.DISM() == "" {
		return nil, ErrProviderUnavailable
	}
	d, err := NewDISM(ctx, workspace)
	if err != nil {
		return nil, err
	}
	exe, err := openExecutable(runtime.DISM())
	if err != nil {
		d.Close()
		return nil, err
	}
	if err = d.dism.file.Close(); err != nil {
		exe.file.Close()
		d.Close()
		return nil, err
	}
	d.dism = exe
	d.runtime = runtime
	return d, nil
}

func NewDISM(ctx context.Context, workspace *platform.Workspace) (*DISM, error) {
	if ctx == nil || workspace == nil {
		return nil, ErrProviderUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dism, err := openInstalledExecutable(ctx, "dism.exe")
	if err != nil {
		return nil, err
	}
	expand, err := openInstalledExecutable(ctx, "expand.exe")
	if err != nil {
		dism.file.Close()
		return nil, err
	}
	session, err := platform.NewSessionRunner(workspace)
	if err != nil {
		dism.file.Close()
		expand.file.Close()
		return nil, err
	}
	for _, dir := range []string{"scratch", "logs", "packages"} {
		if err = workspace.MkdirAll(dir); err != nil {
			session.Close()
			dism.file.Close()
			expand.file.Close()
			return nil, err
		}
	}
	return &DISM{workspace: workspace, runner: session, session: session, dism: dism, expand: expand}, nil
}
func openInstalledExecutable(ctx context.Context, name string) (*installedExecutable, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		return nil, err
	}
	if host.ProcessArchitecture == model.ArchitectureX86 && host.NativeArchitecture != model.ArchitectureX86 {
		root, e := windows.GetWindowsDirectory()
		if e != nil {
			return nil, e
		}
		dir = filepath.Join(root, "Sysnative")
	}
	path := filepath.Join(dir, name)
	return openExecutable(path)
}
func openExecutable(path string) (*installedExecutable, error) {
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(wide, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	exe := &installedExecutable{path: path, file: os.NewFile(uintptr(handle), path)}
	stat, err := exe.file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		exe.file.Close()
		return nil, ErrProviderUnavailable
	}
	exe.size = stat.Size()
	hash := sha256.New()
	if _, err = io.Copy(hash, exe.file); err != nil {
		exe.file.Close()
		return nil, err
	}
	exe.digest = hex.EncodeToString(hash.Sum(nil))
	return exe, nil
}
func (d *DISM) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return errors.Join(d.session.Close(), d.dism.file.Close(), d.expand.file.Close())
}
func (d *DISM) Check(ctx context.Context, req ServiceRequest) error {
	if d == nil || d.workspace == nil || d.dism == nil || d.expand == nil {
		return ErrProviderUnavailable
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		return err
	}
	build := host.WindowsBuild
	if d.runtime != nil {
		build = d.runtime.Build()
		if build == 0 {
			return ErrProviderUnavailable
		}
	}
	if build < req.Plan.Generation.Build {
		return fmt.Errorf("%w: installed DISM host build %d predates target %d; a matching managed ADK provider is required", ErrProviderUnavailable, host.WindowsBuild, req.Plan.Generation.Build)
	}
	return d.checkExecutable(ctx, d.dism)
}
func (d *DISM) checkExecutable(ctx context.Context, exe *installedExecutable) error {
	if exe == nil || exe.file == nil {
		return ErrProviderUnavailable
	}
	if err := verifySHA256(ctx, exe.path, exe.digest); err != nil {
		return fmt.Errorf("%w: installed executable identity: %v", ErrProviderUnavailable, err)
	}
	return nil
}

// Output capture is separate from Runner's 64 KiB tails: normal package lists
// can be larger. The complete observation is bounded at 16 MiB and overflow
// fails verification rather than silently inspecting a truncated list.
func (d *DISM) run(ctx context.Context, exe *installedExecutable, args []string, emit model.Emit) (string, error) {
	return d.runObserved(ctx, exe, args, emit, false)
}

func (d *DISM) runObserved(ctx context.Context, exe *installedExecutable, args []string, emit model.Emit, discardCleanup bool) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return "", os.ErrClosed
	}
	if err := d.checkExecutable(ctx, exe); err != nil {
		return "", err
	}
	var mu sync.Mutex
	var output strings.Builder
	overflow := false
	sink := func(event model.Event) {
		mu.Lock()
		if output.Len()+len(event.Message) > 16<<20 {
			overflow = true
		} else {
			output.WriteString(event.Message)
		}
		mu.Unlock()
		if emit != nil {
			emit(event)
		}
	}
	result, err := d.runner.Run(ctx, platform.Invocation{Executable: exe.path, Arguments: ordinaryDISMArguments(args), Workspace: d.workspace, JobID: d.workspace.Identity().JobID, OperationID: "service-image", Cancellation: platform.CancelWait}, sink)
	if overflow {
		return "", fmt.Errorf("%w: DISM output exceeds observation bound", ErrVerification)
	}
	if err != nil {
		// CancelWait still returns cancellation to every normal caller. A discard
		// cleanup has completed when its natural exit was observed as zero and
		// cancellation is the sole error; retain every other observation failure.
		if discardCleanup && result.ExitObserved && result.ExitCode == 0 && result.Cancelled && onlyContextCancellation(err) {
			return decodeOutput(output.String()), nil
		}
		return "", fmt.Errorf("offline helper (exit %d): %w", result.ExitCode, err)
	}
	return decodeOutput(output.String()), nil
}

func onlyContextCancellation(err error) bool {
	if err == context.Canceled || err == context.DeadlineExceeded {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		errors := joined.Unwrap()
		if len(errors) == 0 {
			return false
		}
		for _, child := range errors {
			if !onlyContextCancellation(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyContextCancellation(wrapped.Unwrap())
	}
	return false
}

func ordinaryDISMArguments(args []string) []string {
	out := append([]string(nil), args...)
	for i, arg := range out {
		arg = strings.ReplaceAll(arg, `\\?\UNC\`, `\\`)
		out[i] = strings.ReplaceAll(arg, `\\?\`, "")
	}
	return out
}
func (d *DISM) args(operation ...string) []string {
	args := []string{"/English", "/NoRestart", "/ScratchDir:" + filepath.Join(d.workspace.Path(), "scratch"), "/LogPath:" + filepath.Join(d.workspace.Path(), "logs", "dism.log")}
	return append(args, operation...)
}
func mountPath(m platform.OwnedMount) (string, error) {
	if (m.OperationID != "service-image" && m.OperationID != "customize-image") || m.Workspace.JobID != m.JobID {
		return "", ErrVerification
	}
	w, err := platform.OpenWorkspace(m.Workspace)
	if err != nil {
		return "", err
	}
	defer w.Close()
	if err = w.RestoreMount(m); err != nil {
		return "", err
	}
	if err = w.ValidateMount(m); err != nil {
		return "", err
	}
	return w.ShortMountPath(m)
}
func (d *DISM) offline(ctx context.Context, m platform.OwnedMount, emit model.Emit, operation ...string) (string, error) {
	path, err := mountPath(m)
	if err != nil {
		return "", err
	}
	if err := checkDISMServicingPaths(path); err != nil {
		return "", err
	}
	args := append([]string{"/Image:" + path}, operation...)
	return d.run(ctx, d.dism, d.args(args...), emit)
}
func (d *DISM) Export(ctx context.Context, src ImageRef, dst string, emit model.Emit) error {
	if src.Index < 1 || !filepath.IsAbs(src.WIMPath) || !filepath.IsAbs(dst) {
		return ErrVerification
	}
	args := []string{"/Export-Image", "/SourceImageFile:" + src.WIMPath, "/SourceIndex:" + strconv.Itoa(src.Index), "/DestinationImageFile:" + dst, "/Compress:max", "/CheckIntegrity"}
	if src.Name != "" {
		args = append(args, "/DestinationName:"+src.Name)
	}
	_, err := d.run(ctx, d.dism, d.args(args...), emit)
	return err
}
func (d *DISM) Mount(ctx context.Context, path string, m platform.OwnedMount, emit model.Emit) error {
	dir, err := mountPath(m)
	if err != nil {
		return err
	}
	_, err = d.run(ctx, d.dism, d.args("/Mount-Image", "/ImageFile:"+path, "/Index:1", "/MountDir:"+dir, "/CheckIntegrity"), emit)
	return err
}
func (d *DISM) Unmount(ctx context.Context, m platform.OwnedMount, commit bool, emit model.Emit) error {
	dir, err := mountPath(m)
	if err != nil {
		return err
	}
	action := "/Discard"
	if commit {
		action = "/Commit"
	}
	_, err = d.runObserved(ctx, d.dism, d.args("/Unmount-Image", "/MountDir:"+dir, action), emit, !commit)
	return err
}

// Package and edition commands are the documented offline operations:
// https://learn.microsoft.com/windows-hardware/manufacture/desktop/add-or-remove-packages-offline-using-dism
// https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism-windows-edition-servicing-command-line-options
func (d *DISM) Inspect(ctx context.Context, m platform.OwnedMount, emit model.Emit) (Inspection, error) {
	text, err := d.offline(ctx, m, emit, "/Get-CurrentEdition")
	if err != nil {
		return Inspection{}, err
	}
	edition := field(text, "Current Edition")
	if edition == "" {
		return Inspection{}, fmt.Errorf("%w: DISM current edition missing", ErrVerification)
	}
	text, err = d.offline(ctx, m, emit, "/Get-Packages", "/Format:List")
	if err != nil {
		return Inspection{}, err
	}
	packages, err := parsePackages(text)
	return Inspection{Edition: edition, Packages: packages}, err
}
func (d *DISM) SetEdition(ctx context.Context, m platform.OwnedMount, edition string, emit model.Emit) error {
	if edition == "" || strings.ContainsAny(edition, "/\\:\r\n\x00") {
		return ErrVerification
	}
	text, err := d.offline(ctx, m, emit, "/Get-TargetEditions")
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(key) == "Target Edition" && strings.EqualFold(strings.TrimSpace(value), edition) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%w: offline image does not offer target edition %s", ErrVerification, edition)
	}
	_, err = d.offline(ctx, m, emit, "/Set-Edition:"+edition)
	return err
}
func (d *DISM) Cleanup(ctx context.Context, m platform.OwnedMount, reset bool, emit model.Emit) error {
	args := []string{"/Cleanup-Image", "/StartComponentCleanup"}
	if reset {
		args = append(args, "/ResetBase")
	}
	_, err := d.offline(ctx, m, emit, args...)
	return err
}
func (d *DISM) Apply(ctx context.Context, m platform.OwnedMount, update rules.UpdatePlan, path string, emit model.Emit) error {
	staged, err := d.stageUpdate(ctx, update, path)
	if err != nil {
		return err
	}
	paths := []string{staged}
	if update.Expand {
		dirName := "packages/expanded-" + update.Resource.Payload.Key()
		if err = d.workspace.MkdirAll(dirName); err != nil {
			return err
		}
		directory := filepath.Join(d.workspace.Path(), filepath.FromSlash(dirName))
		paths = nil
		for _, member := range update.Members {
			clean, e := model.ValidateRelativePath(member)
			if e != nil || strings.Contains(clean, "/") || !strings.EqualFold(filepath.Ext(clean), ".cab") {
				return fmt.Errorf("unsupported MSU member %q", member)
			}
			output := filepath.Join(directory, clean)
			if _, e = os.Stat(output); errors.Is(e, os.ErrNotExist) {
				if _, e = d.run(ctx, d.expand, []string{"-F:" + clean, staged, directory}, emit); e != nil {
					return e
				}
			} else if e != nil {
				return e
			}
			stat, e := os.Stat(output)
			if e != nil || !stat.Mode().IsRegular() || stat.Size() == 0 {
				return fmt.Errorf("%w: expanded CAB missing", ErrVerification)
			}
			paths = append(paths, output)
		}
	}
	for _, pack := range paths {
		if _, err = d.offline(ctx, m, emit, "/Add-Package", "/PackagePath:"+pack); err != nil {
			return err
		}
	}
	return nil
}
func (d *DISM) stageUpdate(ctx context.Context, update rules.UpdatePlan, path string) (string, error) {
	name := "packages/" + update.Resource.Payload.Key() + "." + string(update.Format)
	staged := filepath.Join(d.workspace.Path(), filepath.FromSlash(name))
	dst, err := d.workspace.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		return staged, verifyUpdateFile(ctx, update.Resource.Payload, staged)
	}
	if err != nil {
		return "", err
	}
	src, err := os.Open(path)
	if err != nil {
		dst.Close()
		return "", err
	}
	_, copyErr := io.Copy(dst, &contextReader{ctx, src})
	err = errors.Join(copyErr, src.Close(), dst.Sync(), dst.Close())
	if err != nil {
		return "", err
	}
	return staged, verifyUpdateFile(ctx, update.Resource.Payload, staged)
}

func (d *DISM) InspectWIM(ctx context.Context, path string, emit model.Emit) ([]ImageIdentity, error) {
	text, err := d.run(ctx, d.dism, d.args("/Get-WimInfo", "/WimFile:"+path), emit)
	if err != nil {
		return nil, err
	}
	var indices []int
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(key) == "Index" {
			index, e := strconv.Atoi(strings.TrimSpace(value))
			if e != nil || index != len(indices)+1 {
				return nil, ErrVerification
			}
			indices = append(indices, index)
		}
	}
	if len(indices) == 0 || len(indices) > 256 {
		return nil, fmt.Errorf("%w: WIM image count missing/out of bound", ErrVerification)
	}
	var images []ImageIdentity
	for _, index := range indices {
		text, err = d.run(ctx, d.dism, d.args("/Get-WimInfo", "/WimFile:"+path, "/Index:"+strconv.Itoa(index)), emit)
		if err != nil {
			return nil, err
		}
		image, parseErr := parseImage(text)
		if parseErr != nil {
			return nil, parseErr
		}
		if image.Index != index {
			return nil, ErrVerification
		}
		images = append(images, image)
	}
	return images, nil
}
func field(text, name string) string {
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(key) == name {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
func parsePackages(text string) ([]PackageObservation, error) {
	var out []PackageObservation
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "Package Identity" {
			parts := strings.Split(value, "~")
			if len(parts) != 5 || parts[0] == "" || parts[4] == "" {
				return nil, fmt.Errorf("%w: malformed CBS identity", ErrVerification)
			}
			out = append(out, PackageObservation{Identity: metadata.PackageIdentity{Name: parts[0], PublicKeyToken: parts[1], Architecture: model.Architecture(parts[2]), Language: parts[3], Version: parts[4]}})
		}
		if key == "State" {
			if len(out) == 0 || out[len(out)-1].State != "" {
				return nil, ErrVerification
			}
			out[len(out)-1].State = value
		}
	}
	for _, pack := range out {
		if pack.State == "" {
			return nil, ErrVerification
		}
	}
	return out, nil
}
func parseImage(text string) (ImageIdentity, error) {
	index, err := strconv.Atoi(field(text, "Index"))
	if err != nil || index < 1 {
		return ImageIdentity{}, ErrVerification
	}
	arch := field(text, "Architecture")
	if arch == "x64" {
		arch = "amd64"
	}
	language := ""
	languageSection := false
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "Languages :" {
			languageSection = true
			continue
		}
		if languageSection {
			value := strings.TrimSpace(line)
			if value == "" {
				continue
			}
			parts := strings.Fields(value)
			if len(parts) > 0 && strings.Contains(parts[0], "-") {
				if language == "" || strings.Contains(value, "(Default)") {
					language = parts[0]
				}
			} else {
				break
			}
		}
	}
	image := ImageIdentity{Index: index, Edition: field(text, "Edition"), Architecture: model.Architecture(arch), Language: language}
	if image.Edition == "" || image.Architecture.Validate() != nil || language == "" {
		return image, fmt.Errorf("%w: WIM edition/architecture/language missing", ErrVerification)
	}
	return image, nil
}
func decodeOutput(text string) string {
	b := []byte(text)
	if len(b) >= 2 && (b[0] == 0xff && b[1] == 0xfe || len(b) > 3 && b[1] == 0 && b[3] == 0) {
		if b[0] == 0xff && b[1] == 0xfe {
			b = b[2:]
		}
		units := make([]uint16, len(b)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(b[2*i:])
		}
		return string(utf16.Decode(units))
	}
	return strings.TrimPrefix(text, "\ufeff")
}
