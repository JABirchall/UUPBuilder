package output

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"uupbuilder/internal/engine/isocontent"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
)

type contextReaderAt struct {
	ctx context.Context
	r   io.ReaderAt
}

func (r contextReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.ReadAt(p, off)
}

// Verify alone constructs the private local capability. Every required file is
// read from the actual ISO and the internal install metadata is parsed again.
func Verify(ctx context.Context, plan planner.ReadyPlan, path string, prepared PreparedISO) (VerifiedArtifact, error) {
	if ctx == nil || prepared.PlanDigest != plan.Digest() || prepared.Source != plan.Manifest().Source {
		return VerifiedArtifact{}, ErrVerification
	}
	if err := validateExport(plan, prepared.Export); err != nil {
		return VerifiedArtifact{}, err
	}
	if err := validateVolume(plan, prepared.Contents.Volume); err != nil {
		return VerifiedArtifact{}, err
	}
	files := map[string]isocontent.ISOExpectedFile{}
	for _, f := range prepared.Contents.Files {
		files[strings.ToLower(f.Path)] = f
	}
	for _, required := range []string{"setup.exe", "sources/boot.wim"} {
		if files[required].Size <= 0 {
			return VerifiedArtifact{}, ErrVerification
		}
	}
	boot := files["sources/boot.wim"]
	if prepared.BootWIM.Size != boot.Size || prepared.BootWIM.SHA256 != boot.SHA256 || len(prepared.BootImages) < 1 || len(prepared.BootImages) > 2 {
		return VerifiedArtifact{}, ErrVerification
	}
	for _, image := range prepared.BootImages {
		if !strings.EqualFold(image.Edition, "WindowsPE") || image.Architecture != prepared.Source.Architecture {
			return VerifiedArtifact{}, ErrVerification
		}
	}
	for _, f := range prepared.Export.Files {
		want := files["sources/"+filepath.Base(f.Path)]
		if want.Size != f.Size || want.SHA256 != f.SHA256 {
			return VerifiedArtifact{}, ErrVerification
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return VerifiedArtifact{}, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() {
		return VerifiedArtifact{}, ErrVerification
	}
	contents, err := isocontent.OpenWindowsISO(contextReaderAt{ctx, f}, s.Size(), prepared.Contents)
	if err != nil {
		return VerifiedArtifact{}, fmt.Errorf("%w: %v", ErrVerification, err)
	}
	first := "sources/" + filepath.Base(prepared.Export.Files[0].Path)
	actual := files[first].Path
	r, n, err := contents.File(actual)
	if err != nil {
		return VerifiedArtifact{}, err
	}
	images, err := inspectImage(r, n)
	if err != nil || !sameImages(images, prepared.Export.Images) {
		return VerifiedArtifact{}, ErrVerification
	}
	bootReader, bootSize, err := contents.File(boot.Path)
	if err != nil {
		return VerifiedArtifact{}, err
	}
	bootImages, err := inspectImage(bootReader, bootSize)
	if err != nil || !sameImages(bootImages, prepared.BootImages) {
		return VerifiedArtifact{}, ErrVerification
	}
	if err := verifyBootHeader(bootReader, bootSize, len(bootImages)); err != nil {
		return VerifiedArtifact{}, err
	}
	settings := plan.EffectiveSettings()
	redacted := reportSettings{ImageFormat: settings.Output.ImageFormat, Editions: plan.CustomizationPlan().Editions, Apps: settings.Apps, Updates: settings.Conversion.Updates, Cleanup: settings.Conversion.Cleanup, ResetBase: settings.Conversion.ResetBase, NetFX3: settings.Conversion.NetFX3}
	return VerifiedArtifact{&verifiedState{path: path, planDigest: plan.Digest(), source: plan.Manifest().Source, size: s.Size(), sha256: contents.Inspection.SHA256, settings: redacted, tools: append([]ToolIdentity(nil), prepared.Tools...)}}, ctx.Err()
}

func verifyBootHeader(r io.ReaderAt, size int64, images int) error {
	var h [208]byte
	if _, err := r.ReadAt(h[:], 0); err != nil {
		return err
	}
	index := binary.LittleEndian.Uint32(h[120:])
	n := binary.LittleEndian.Uint64(h[96:]) & 0x00ffffffffffffff
	off := binary.LittleEndian.Uint64(h[104:])
	if index == 0 || index > uint32(images) || n == 0 || off < 208 || off > uint64(size) || n > uint64(size)-off {
		return fmt.Errorf("%w: boot WIM boot index/resource invalid", ErrVerification)
	}
	return nil
}

// PublishVerified returns a private destination capability for the controller.
// A model.Artifact descriptor on its own can never complete a build.
func PublishVerified(ctx context.Context, v VerifiedArtifact, directory, filename string) (PublishedArtifact, error) {
	a, err := Publish(ctx, v, directory, filename)
	if err != nil {
		return PublishedArtifact{}, err
	}
	checksum, err := fileIdentity(ctx, a.VerificationPath)
	if err != nil {
		return PublishedArtifact{}, err
	}
	report, err := fileIdentity(ctx, a.ReportPath)
	if err != nil {
		return PublishedArtifact{}, err
	}
	return PublishedArtifact{&publishedState{a, checksum.SHA256, report.SHA256}}, nil
}
func (p PublishedArtifact) Artifact(ctx context.Context, planDigest string, source model.SourceIdentity) (model.Artifact, error) {
	if p.state == nil || p.state.artifact.PlanDigest != planDigest || p.state.artifact.Source != source {
		return model.Artifact{}, ErrVerification
	}
	a := p.state.artifact
	if err := checkFile(ctx, File{a.Path, a.SHA256, a.Size}); err != nil {
		return model.Artifact{}, err
	}
	for path, want := range map[string]string{a.VerificationPath: p.state.checksum, a.ReportPath: p.state.report} {
		got, err := fileIdentity(ctx, path)
		if err != nil || got.SHA256 != want {
			return model.Artifact{}, ErrVerification
		}
	}
	return a, ctx.Err()
}
