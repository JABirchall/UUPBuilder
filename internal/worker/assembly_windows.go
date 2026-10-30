package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	native "golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strings"
	"uupbuilder/internal/engine/output"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
)

func (p *CheckpointPipeline) runAssembly(ctx context.Context, exe string, args ...string) error {
	result, err := platform.NewRunner().Run(ctx, platform.Invocation{Executable: exe, Arguments: args, Workspace: p.Workspace, JobID: p.Workspace.Identity().JobID, OperationID: "assemble-image", Cancellation: platform.CancelTerminateTree}, p.Native.Emit)
	if err != nil {
		return fmt.Errorf("assembly helper exit %d: %w: %s", result.ExitCode, err, result.Stderr)
	}
	return nil
}

// AssemblyHandler reconstructs only the selected immutable source recipe.
// CAB captures provide missing file content references, never target metadata.
func (p *CheckpointPipeline) AssemblyHandler() Handler {
	return Handler{Run: func(ctx context.Context, stage Stage) (Result, error) {
		if stage.Operation.Kind != planner.AssembleImage || p.Native == nil {
			return Result{}, ErrMissingHandler
		}
		manifest := stage.Plan.Manifest()
		if manifest.Source.UpdateID != source.SelectedUpdateID || manifest.Source.BuildLabel != "28000.3365" || manifest.Source.Architecture != "amd64" || manifest.Source.Language != "en-gb" {
			return Result{}, source.ErrImplementationGap
		}
		dir, err := p.directory("assembly")
		if err != nil {
			return Result{}, err
		}
		for _, name := range []string{"inputs", "cab-content", "media"} {
			if err = os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
				return Result{}, err
			}
		}
		var receipt PreparedInputs
		if err = readCheckpoint(ctx, stage, planner.DownloadPayloads, &receipt); err != nil {
			return Result{}, err
		}
		if receipt.PlanDigest != stage.Plan.Digest() || receipt.ManifestDigest != manifest.Digest {
			return Result{}, planner.ErrIdentityChanged
		}
		prepared := map[model.PayloadIdentity]PreparedPayload{}
		for _, f := range receipt.Files {
			prepared[f.Identity] = f
		}
		wanted := map[model.PayloadIdentity]string{}
		for i, payload := range manifest.Payloads {
			ext := strings.ToLower(filepath.Ext(payload.Destination))
			if ext == ".esd" || ext == ".cab" {
				wanted[payload.Identity] = filepath.Join(dir, "inputs", fmt.Sprintf("p%03d%s", i, ext))
			}
		}
		if err = materializePrepared(ctx, stage, receipt, wanted); err != nil {
			return Result{}, err
		}
		var refs []string
		main := ""
		cabs := 0
		system, err := native.GetSystemDirectory()
		if err != nil {
			return Result{}, err
		}
		host, err := platform.DetectHost(ctx)
		if err != nil {
			return Result{}, err
		}
		if host.ProcessArchitecture == "x86" {
			root, e := native.GetWindowsDirectory()
			if e != nil {
				return Result{}, e
			}
			system = filepath.Join(root, "Sysnative")
		}
		for i, payload := range manifest.Payloads {
			ext := strings.ToLower(filepath.Ext(payload.Destination))
			if ext != ".esd" && ext != ".cab" {
				continue
			}
			file, ok := prepared[payload.Identity]
			if !ok || file.Path != "payloads/"+payload.Identity.Key()+".data" {
				return Result{}, planner.ErrIdentityChanged
			}
			path := filepath.Join(dir, "inputs", fmt.Sprintf("p%03d%s", i, ext))
			if ext == ".esd" {
				refs = append(refs, "--ref="+path)
				if payload.Identity.Digest.Value == source.SelectedBaseSHA256 {
					main = path
				}
				continue
			}
			cabDir := filepath.Join(dir, "cab-content", fmt.Sprintf("p%03d", i))
			if err = os.Mkdir(cabDir, 0700); err != nil {
				return Result{}, err
			}
			if err = p.runAssembly(ctx, filepath.Join(system, "expand.exe"), "-F:*", path, cabDir); err != nil {
				return Result{}, err
			}
			cabs++
		}
		if main == "" || len(refs) != 20 || cabs != 73 {
			return Result{}, fmt.Errorf("selected source reference closure changed")
		}
		wim := p.Native.WIMLib
		cabRef := filepath.Join(dir, "cab-references.wim")
		if err = p.runAssembly(ctx, wim, "capture", filepath.Join(dir, "cab-content"), cabRef, "CAB content references", "--no-acls", "--compress=none"); err != nil {
			return Result{}, err
		}
		refs = append(refs, "--ref="+cabRef)
		base := filepath.Join(dir, "base.wim")
		args := append([]string{"export", main, "3", base, "--compress=LZX", "--check"}, refs...)
		if err = p.runAssembly(ctx, wim, args...); err != nil {
			return Result{}, err
		}
		if err = p.runAssembly(ctx, wim, "verify", base); err != nil {
			return Result{}, err
		}
		images, err := output.InspectWIMFile(base)
		if err != nil {
			return Result{}, err
		}
		if len(images) != 1 || !strings.EqualFold(images[0].Edition, "Professional") || images[0].Architecture != manifest.Source.Architecture || !strings.EqualFold(images[0].Language, manifest.Source.Language) {
			return Result{}, planner.ErrIdentityChanged
		}
		media := filepath.Join(dir, "media")
		args = append([]string{"apply", main, "1", media, "--no-acls"}, refs...)
		if err = p.runAssembly(ctx, wim, args...); err != nil {
			return Result{}, err
		}
		// Independently read normal source media and original BIOS/EFI content before
		// using its Setup binaries to build the boot WIM. No target file is executed.
		if _, err = output.MediaExpectations(ctx, media, "UUP_WINDOWS", manifest.Source.Architecture); err != nil {
			return Result{}, err
		}
		boot := filepath.Join(dir, "boot.wim")
		for _, name := range []string{"Microsoft Windows PE (amd64)", "Microsoft Windows Setup (amd64)"} {
			args = append([]string{"export", main, "2", boot, name, "--compress=LZX", "--check"}, refs...)
			if err = p.runAssembly(ctx, wim, args...); err != nil {
				return Result{}, err
			}
		}
		if err = p.runAssembly(ctx, wim, "update", boot, "1", "--command=delete /Windows/System32/winpeshl.ini"); err != nil {
			return Result{}, err
		}
		launcher := filepath.Join(dir, "winpeshl.ini")
		if err = os.WriteFile(launcher, []byte("[LaunchApps]\r\n%SYSTEMDRIVE%\\sources\\setup.exe\r\n"), 0600); err != nil {
			return Result{}, err
		}
		for _, entry := range []struct{ local, target string }{{filepath.Join(media, "sources"), "/sources"}, {filepath.Join(media, "setup.exe"), "/setup.exe"}, {launcher, "/Windows/System32/winpeshl.ini"}} {
			command := fmt.Sprintf("--command=add \"%s\" \"%s\"", entry.local, entry.target)
			if err = p.runAssembly(ctx, wim, "update", boot, "2", command); err != nil {
				return Result{}, err
			}
		}
		if err = p.runAssembly(ctx, wim, "info", boot, "2", "--boot"); err != nil {
			return Result{}, err
		}
		if err = p.runAssembly(ctx, wim, "verify", boot); err != nil {
			return Result{}, err
		}
		bootImages, err := output.InspectWIMFile(boot)
		if err != nil {
			return Result{}, err
		}
		if len(bootImages) != 2 {
			return Result{}, planner.ErrIdentityChanged
		}
		for _, image := range bootImages {
			if image.Edition != "WindowsPE" || image.Architecture != manifest.Source.Architecture {
				return Result{}, planner.ErrIdentityChanged
			}
		}
		// Read back the launcher and source Setup bytes through the producing tool;
		// independent image metadata and final ISO content checks remain separate.
		check := filepath.Join(dir, "boot-check")
		if err = os.Mkdir(check, 0700); err != nil {
			return Result{}, err
		}
		if err = p.runAssembly(ctx, wim, "extract", boot, "2", "Windows/System32/winpeshl.ini", "sources/setup.exe", "--dest-dir="+check, "--no-acls"); err != nil {
			return Result{}, err
		}
		for _, pair := range [][2]string{{launcher, filepath.Join(check, "winpeshl.ini")}, {filepath.Join(media, "sources/setup.exe"), filepath.Join(check, "setup.exe")}} {
			a, e := assemblyFile(ctx, pair[0])
			if e != nil {
				return Result{}, e
			}
			b, e := assemblyFile(ctx, pair[1])
			if e != nil {
				return Result{}, e
			}
			if a.Size != b.Size || a.SHA256 != b.SHA256 {
				return Result{}, fmt.Errorf("Setup boot image content mismatch")
			}
		}
		baseOut, err := commitFile(ctx, stage, "base.wim", base, "assembled-base")
		if err != nil {
			return Result{}, err
		}
		bootOut, err := commitFile(ctx, stage, "boot.wim", boot, "assembled-boot")
		if err != nil {
			return Result{}, err
		}
		archive, entries, err := commitArchive(ctx, stage, "setup-media.tar", media)
		if err != nil {
			return Result{}, err
		}
		result, err := writeStageResult(stage, AssemblyCheckpoint{PlanDigest: stage.Plan.Digest(), ManifestDigest: manifest.Digest, Base: output.File{Path: "base.wim", Size: baseOut.Size, SHA256: baseOut.SHA256}, Boot: output.File{Path: "boot.wim", Size: bootOut.Size, SHA256: bootOut.SHA256}, Images: images, BootImages: bootImages, Media: entries}, "assembled-media")
		return Result{Outputs: []jobstore.OutputIdentity{baseOut, bootOut, archive, result}}, err
	}}
}
func assemblyFile(ctx context.Context, path string) (output.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return output.File{}, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, preparationReader{ctx, f})
	return output.File{Path: path, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))}, err
}
