package output

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	native "golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"uupbuilder/internal/engine/isocontent"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

//go:embed master.ps1
var masterScript []byte

// Native borrows the caller's owned workspace and an acquired pinned wimlib
// executable. Acquisition belongs to the production provider composition.
// Commands are fixed; the adapter never elevates or runs target image files.
type Native struct {
	Workspace *platform.Workspace
	WIMLib    string
	Emit      model.Emit
	mu        sync.Mutex
}

func (n *Native) ToolIdentities(ctx context.Context) ([]ToolIdentity, error) {
	var out []ToolIdentity
	if n.WIMLib != "" {
		f, err := fileIdentity(ctx, n.WIMLib)
		if err != nil {
			return nil, err
		}
		out = append(out, ToolIdentity{Name: "wimlib-imagex", Version: "1.14.5", SHA256: f.SHA256})
	}
	system, err := native.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		return nil, err
	}
	if host.ProcessArchitecture == model.ArchitectureX86 && host.NativeArchitecture != model.ArchitectureX86 {
		root, e := native.GetWindowsDirectory()
		if e != nil {
			return nil, e
		}
		system = filepath.Join(root, "Sysnative")
	}
	for _, name := range []string{"imapi2fs.dll", "WindowsPowerShell/v1.0/powershell.exe"} {
		f, err := fileIdentity(ctx, filepath.Join(system, name))
		if err != nil {
			return nil, err
		}
		out = append(out, ToolIdentity{Name: filepath.Base(name), Version: fmt.Sprintf("inbox on Windows build %d", host.WindowsBuild), SHA256: f.SHA256})
	}
	return out, nil
}

func plainPath(path string) string { return strings.TrimPrefix(path, `\\?\`) }
func (n *Native) run(ctx context.Context, exe string, args []string, stage string) error {
	if n == nil || n.Workspace == nil {
		return ErrVerification
	}
	result, err := platform.NewRunner().Run(ctx, platform.Invocation{Executable: exe, Arguments: args, Workspace: n.Workspace, JobID: n.Workspace.Identity().JobID, OperationID: stage, Cancellation: platform.CancelTerminateTree}, n.Emit)
	if err != nil {
		return fmt.Errorf("%s helper exit %d: %w: %s", stage, result.ExitCode, err, result.Stderr)
	}
	return nil
}
func lockFile(path string) (*os.File, error) {
	p, err := native.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := native.CreateFile(p, native.GENERIC_READ, native.FILE_SHARE_READ, nil, native.OPEN_EXISTING, native.FILE_ATTRIBUTE_NORMAL|native.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info native.ByHandleFileInformation
	if err = native.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&(native.FILE_ATTRIBUTE_REPARSE_POINT|native.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		native.CloseHandle(h)
		return nil, ErrVerification
	}
	return os.NewFile(uintptr(h), path), nil
}
func (n *Native) wim(ctx context.Context, args []string) error {
	// Pins are the existing trusted manifest's official wimlib 1.14.5 files.
	pins := map[string]string{"34c0c4165591ad1f592837ed99d08273c58d6ed3fe0ed6360cf34e7b0739b353": "ba853ee1e3fc5f5798581f02e8e066ba07a0a2375f0bf444fe981431fd508495", "597b1e5fe29b92cce7ab6955d4cd629eb2c070fad45aed2bde811b39edbd80af": "a79b428fea9d1bded38a45eab854bd72f0a31fd878c0d3132cfdfd4899498053"}
	f, err := lockFile(n.WIMLib)
	if err != nil {
		return err
	}
	defer f.Close()
	_, h, err := digest(ctx, f)
	if err != nil || pins[h] == "" {
		return ErrVerification
	}
	dll, err := lockFile(filepath.Join(filepath.Dir(n.WIMLib), "libwim-15.dll"))
	if err != nil {
		return err
	}
	defer dll.Close()
	_, dh, err := digest(ctx, dll)
	if err != nil || dh != pins[h] {
		return ErrVerification
	}
	return n.run(ctx, n.WIMLib, args, "export-image")
}
func (n *Native) Export(ctx context.Context, source, destination string, format model.ImageFormat, split int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !filepath.IsAbs(source) || !filepath.IsAbs(destination) {
		return ErrVerification
	}
	sourceLock, err := lockFile(source)
	if err != nil {
		return err
	}
	defer sourceLock.Close()
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return ErrVerification
	}
	args := []string{"export", plainPath(source), "all", plainPath(destination), "--check", "--compress=LZX"}
	switch format {
	case model.ImageWIM:
	case model.ImageESD:
		args[len(args)-1] = "--compress=LZMS"
		args = append(args, "--solid")
	case model.ImageSWM:
		if split < 1 || split > 4095 {
			return ErrVerification
		}
		args = []string{"split", plainPath(source), plainPath(destination), strconv.Itoa(split), "--check"}
	default:
		return ErrVerification
	}
	return n.wim(ctx, args)
}
func (n *Native) VerifyImage(ctx context.Context, path string, format model.ImageFormat) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	args := []string{"verify", plainPath(path)}
	if format == model.ImageSWM {
		args = append(args, "--ref="+filepath.Join(filepath.Dir(plainPath(path)), "install*.swm"))
	}
	return n.wim(ctx, args)
}
func (n *Native) Master(ctx context.Context, media, destination string, e isocontent.ISOExpectations) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Workspace == nil {
		return ErrVerification
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return ErrVerification
	}
	// Hold source files against replacement/writes for the entire COM operation.
	var locks []*os.File
	defer func() {
		for _, f := range locks {
			f.Close()
		}
	}()
	for _, want := range e.Files {
		f, err := lockFile(filepath.Join(media, filepath.FromSlash(want.Path)))
		if err != nil {
			return err
		}
		locks = append(locks, f)
		size, h, err := digest(ctx, f)
		if err != nil || size != want.Size || h != want.SHA256 {
			return ErrVerification
		}
	}
	if err := n.Workspace.MkdirAll("imapi"); err != nil {
		return err
	}
	if err := n.Workspace.MkdirAll("imapi/scratch"); err != nil {
		return err
	}
	type boot struct {
		Path     string `json:"path"`
		Platform int    `json:"platform"`
	}
	var boots []boot
	if e.BIOSBootImagePath != "" {
		boots = append(boots, boot{plainPath(filepath.Join(media, filepath.FromSlash(e.BIOSBootImagePath))), 0})
	}
	boots = append(boots, boot{plainPath(filepath.Join(media, filepath.FromSlash(e.BootImagePath))), 239})
	request := struct {
		Media, Output, Scratch, Label string
		Files                         int
		Boot                          []boot
	}{plainPath(media), plainPath(destination), plainPath(filepath.Join(n.Workspace.Path(), "imapi/scratch")), e.Volume, len(e.Files), boots}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	for name, b := range map[string][]byte{"imapi/master.ps1": masterScript, "imapi/master.json": data} {
		f, err := n.Workspace.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(b)
		if err = errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
			return err
		}
	}
	system, err := native.GetSystemDirectory()
	if err != nil {
		return err
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		return err
	}
	if host.ProcessArchitecture == model.ArchitectureX86 && host.NativeArchitecture != model.ArchitectureX86 {
		root, e := native.GetWindowsDirectory()
		if e != nil {
			return e
		}
		system = filepath.Join(root, "Sysnative")
	}
	exe := filepath.Join(system, "WindowsPowerShell/v1.0/powershell.exe")
	return n.run(ctx, exe, []string{"-NoProfile", "-NonInteractive", "-File", plainPath(filepath.Join(n.Workspace.Path(), "imapi/master.ps1"))}, "master-iso")
}
