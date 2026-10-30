package output

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"uupbuilder/internal/engine/isocontent"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
)

func validateExport(plan planner.ReadyPlan, e ExportResult) error {
	if plan.Validate() != nil || e.PlanDigest != plan.Digest() || e.Source != plan.Manifest().Source || e.Format != plan.EffectiveSettings().Output.ImageFormat || len(e.Files) == 0 {
		return ErrVerification
	}
	p := plan.CustomizationPlan()
	if p == nil || e.Customization.PlanDigest != p.Digest || !sameImages(e.Images, e.Customization.Images) {
		return ErrVerification
	}
	return validateCustomized(*p, e.Customization)
}

func validateVolume(plan planner.ReadyPlan, label string) error {
	if label == "" || len(label) > 32 || strings.ContainsAny(label, "\x00\r\n") {
		return ErrVerification
	}
	want := plan.EffectiveSettings().Output.Label
	if want != "auto" && label != want {
		return fmt.Errorf("%w: frozen volume label differs", ErrVerification)
	}
	return nil
}

// Master binds every source-media and exported-image byte before invoking the
// producer. A successful helper still grants no VerifiedArtifact.
func Master(ctx context.Context, req MasterRequest, backend Masterer) (PreparedISO, error) {
	var out PreparedISO
	if ctx == nil || backend == nil {
		return out, ErrVerification
	}
	if err := validateExport(req.Plan, req.Export); err != nil {
		return out, err
	}
	if err := validateVolume(req.Plan, req.Label); err != nil {
		return out, err
	}
	if _, err := os.Lstat(req.ISOPath); !os.IsNotExist(err) {
		return out, fmt.Errorf("ISO path already exists or is inaccessible")
	}
	e, err := MediaExpectations(ctx, req.MediaDirectory, req.Label, req.Export.Source.Architecture)
	if err != nil {
		return out, err
	}
	files := map[string]isocontent.ISOExpectedFile{}
	for _, f := range e.Files {
		files[strings.ToLower(f.Path)] = f
	}
	for _, required := range []string{"setup.exe", "sources/boot.wim"} {
		if files[required].Size <= 0 {
			return out, fmt.Errorf("%w: %s missing", ErrVerification, required)
		}
	}
	boot := files["sources/boot.wim"]
	if req.BootWIM.Size != boot.Size || req.BootWIM.SHA256 != boot.SHA256 || len(req.BootImages) < 1 || len(req.BootImages) > 2 {
		return out, ErrVerification
	}
	for _, image := range req.BootImages {
		if !strings.EqualFold(image.Edition, "WindowsPE") || image.Architecture != req.Export.Source.Architecture {
			return out, ErrVerification
		}
	}
	imageNames := map[string]bool{}
	for _, f := range req.Export.Files {
		if err := checkFile(ctx, f); err != nil {
			return out, err
		}
		name := "sources/" + filepath.Base(f.Path)
		imageNames[name] = true
		got := files[name]
		if got.Size != f.Size || got.SHA256 != f.SHA256 {
			return out, ErrVerification
		}
	}
	for name := range files {
		if strings.HasPrefix(name, "sources/install") && (strings.HasSuffix(name, ".wim") || strings.HasSuffix(name, ".esd") || strings.HasSuffix(name, ".swm")) && !imageNames[name] {
			return out, ErrVerification
		}
	}
	if err = backend.Master(ctx, req.MediaDirectory, req.ISOPath, e); err != nil {
		return out, err
	}
	stat, err := os.Stat(req.ISOPath)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() == 0 {
		return out, fmt.Errorf("%w: mastering produced no ISO", ErrVerification)
	}
	tools := append([]ToolIdentity(nil), req.Export.Tools...)
	if reporter, ok := backend.(ToolReporter); ok {
		observed, err := reporter.ToolIdentities(ctx)
		if err != nil {
			return out, err
		}
		tools = append(tools, observed...)
	}
	return PreparedISO{PlanDigest: req.Plan.Digest(), Source: req.Plan.Manifest().Source, Export: req.Export, Contents: e, Tools: tools, BootWIM: req.BootWIM, BootImages: req.BootImages}, ctx.Err()
}

// MediaExpectations is also used for private native component acceptance. It
// only observes source bytes; it cannot produce a publication capability.
func MediaExpectations(ctx context.Context, root, label string, arch model.Architecture) (isocontent.ISOExpectations, error) {
	e := isocontent.ISOExpectations{Volume: label, TargetMachine: map[model.Architecture]uint16{"x86": 0x14c, "amd64": 0x8664, "arm64": 0xaa64}[arch]}
	loader := map[model.Architecture]string{"x86": "bootia32.efi", "amd64": "bootx64.efi", "arm64": "bootaa64.efi"}[arch]
	if loader == "" {
		return e, ErrVerification
	}
	wantEFI := "efi/microsoft/boot/efisys.bin"
	wantDirect := "efi/boot/" + loader
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return ErrVerification
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		f, err := fileIdentity(ctx, path)
		if err != nil {
			return err
		}
		e.Files = append(e.Files, isocontent.ISOExpectedFile{Path: name, Size: f.Size, SHA256: f.SHA256})
		switch strings.ToLower(name) {
		case wantEFI:
			e.BootImagePath = name
		case wantDirect:
			e.DirectLoaderPath = name
		case "boot/etfsboot.com":
			if arch != "arm64" {
				e.BIOSBootImagePath = name
			}
		}
		return nil
	})
	if err != nil {
		return e, err
	}
	if e.BootImagePath == "" || e.DirectLoaderPath == "" || arch != "arm64" && e.BIOSBootImagePath == "" {
		return e, ErrVerification
	}
	f, err := os.Open(filepath.Join(root, filepath.FromSlash(e.BootImagePath)))
	if err != nil {
		return e, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return e, err
	}
	e.EmbeddedLoader, err = isocontent.ObserveEFILoader(f, s.Size(), e.TargetMachine)
	return e, err
}
