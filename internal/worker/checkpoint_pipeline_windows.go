package worker

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"uupbuilder/internal/engine/output"
	"uupbuilder/internal/engine/service"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/tools"
)

// AssemblyCheckpoint names fixed committed files, never previous scratch paths.
type AssemblyCheckpoint struct {
	PlanDigest, ManifestDigest string
	Base, Boot                 output.File
	Images, BootImages         []service.ImageIdentity
	Media                      []ArchiveEntry
}
type exportCheckpoint struct {
	Export output.ExportResult
	Files  []ArchiveEntry
}

// CheckpointPipeline borrows one fresh short native workspace for an active job.
// Every read below is authorized by the transaction's direct predecessor list.
type CheckpointPipeline struct {
	Workspace *platform.Workspace
	Native    *output.Native
	Runtime   *tools.SelectedRuntime
}

func (p *CheckpointPipeline) directory(stage string) (string, error) {
	if p == nil || p.Workspace == nil {
		return "", ErrMissingHandler
	}
	if err := p.Workspace.MkdirAll(stage); err != nil {
		return "", err
	}
	return strings.TrimPrefix(filepath.Join(p.Workspace.Path(), stage), `\\?\`), nil
}
func predecessorFile(stage Stage, kind planner.OperationKind, name string) (jobstore.PredecessorIdentity, jobstore.OutputIdentity, error) {
	for _, cp := range stage.Predecessors {
		if cp.Intent.StageID != string(kind) {
			continue
		}
		for _, out := range cp.Outputs {
			if strings.HasSuffix(out.Path, "/"+name) {
				return jobstore.PredecessorIdentity{StageID: cp.Intent.StageID, Digest: cp.Digest}, out, nil
			}
		}
	}
	return jobstore.PredecessorIdentity{}, jobstore.OutputIdentity{}, fmt.Errorf("missing direct predecessor %s/%s", kind, name)
}
func readCheckpoint(ctx context.Context, stage Stage, kind planner.OperationKind, target any) error {
	cp, out, err := predecessorFile(stage, kind, "result.json")
	if err != nil {
		return err
	}
	if out.Size > 32<<20 {
		return fmt.Errorf("checkpoint metadata too large")
	}
	r, err := openCheckpoint(ctx, stage, cp, out)
	if err != nil {
		return err
	}
	defer r.Close()
	data, err := io.ReadAll(io.NewSectionReader(r, 0, out.Size))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
func materializeCheckpoint(ctx context.Context, stage Stage, kind planner.OperationKind, name, path string) (jobstore.OutputIdentity, error) {
	cp, out, err := predecessorFile(stage, kind, name)
	if err != nil {
		return out, err
	}
	r, err := openCheckpoint(ctx, stage, cp, out)
	if err != nil {
		return out, err
	}
	defer r.Close()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return out, err
	}
	return out, errors.Join(copyCheckpoint(ctx, f, io.NewSectionReader(r, 0, out.Size), out.Size, out.SHA256), f.Sync(), f.Close())
}
func materializeArchive(ctx context.Context, stage Stage, kind planner.OperationKind, name, directory string, entries []ArchiveEntry) error {
	cp, out, err := predecessorFile(stage, kind, name)
	if err != nil {
		return err
	}
	r, err := openCheckpoint(ctx, stage, cp, out)
	if err != nil {
		return err
	}
	defer r.Close()
	return extractCheckpointArchive(ctx, io.NewSectionReader(r, 0, out.Size), directory, entries)
}
func commitFile(ctx context.Context, stage Stage, name, path, role string) (jobstore.OutputIdentity, error) {
	src, err := os.Open(path)
	if err != nil {
		return jobstore.OutputIdentity{}, err
	}
	defer src.Close()
	dst, err := stage.Transaction.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return jobstore.OutputIdentity{}, err
	}
	h := sha256.New()
	size, e := io.Copy(io.MultiWriter(dst, h), preparationReader{ctx, src})
	err = errors.Join(e, dst.Sync(), dst.Close())
	return jobstore.OutputIdentity{Path: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil)), Role: role}, err
}
func commitArchive(ctx context.Context, stage Stage, name, directory string) (jobstore.OutputIdentity, []ArchiveEntry, error) {
	dst, err := stage.Transaction.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return jobstore.OutputIdentity{}, nil, err
	}
	h := sha256.New()
	counter := &countWriter{w: io.MultiWriter(dst, h)}
	entries, e := archiveDirectory(ctx, counter, directory)
	err = errors.Join(e, dst.Sync(), dst.Close())
	return jobstore.OutputIdentity{Path: name, Size: counter.n, SHA256: hex.EncodeToString(h.Sum(nil)), Role: "checkpoint-archive"}, entries, err
}

type countWriter struct {
	w io.Writer
	n int64
}

func (w *countWriter) Write(b []byte) (int, error) {
	n, e := w.w.Write(b)
	w.n += int64(n)
	return n, e
}

func (p *CheckpointPipeline) ExportHandler() Handler {
	return Handler{Run: func(ctx context.Context, stage Stage) (Result, error) {
		if stage.Operation.Kind != planner.ExportImage || p.Native == nil {
			return Result{}, ErrMissingHandler
		}
		dir, err := p.directory("export")
		if err != nil {
			return Result{}, err
		}
		var customized service.CustomizedImages
		if err = readCheckpoint(ctx, stage, planner.CustomizeImage, &customized); err != nil {
			return Result{}, err
		}
		name := customized.WIMPath
		if name != "customized.wim" {
			return Result{}, planner.ErrIdentityChanged
		}
		customized.WIMPath = filepath.Join(dir, name)
		if _, err = materializeCheckpoint(ctx, stage, planner.CustomizeImage, name, customized.WIMPath); err != nil {
			return Result{}, err
		}
		exported, err := output.Prepare(ctx, output.ExportRequest{Plan: stage.Plan, Customized: customized, Directory: filepath.Join(dir, "images")}, p.Native)
		if err != nil {
			return Result{}, err
		}
		archive, files, err := commitArchive(ctx, stage, "exported-images.tar", filepath.Join(dir, "images"))
		if err != nil {
			return Result{}, err
		}
		for i := range exported.Files {
			exported.Files[i].Path = filepath.Base(exported.Files[i].Path)
		}
		result, err := writeStageResult(stage, exportCheckpoint{Export: exported, Files: files}, "exported-images")
		return Result{Outputs: []jobstore.OutputIdentity{archive, result}}, err
	}}
}
func (p *CheckpointPipeline) MasterHandler() Handler {
	return Handler{Run: func(ctx context.Context, stage Stage) (Result, error) {
		if stage.Operation.Kind != planner.MasterISO || p.Native == nil {
			return Result{}, ErrMissingHandler
		}
		dir, err := p.directory("master")
		if err != nil {
			return Result{}, err
		}
		var assembled AssemblyCheckpoint
		var exported exportCheckpoint
		if err = readCheckpoint(ctx, stage, planner.AssembleImage, &assembled); err != nil {
			return Result{}, err
		}
		if assembled.PlanDigest != stage.Plan.Digest() || assembled.ManifestDigest != stage.Plan.Manifest().Digest {
			return Result{}, planner.ErrIdentityChanged
		}
		if err = readCheckpoint(ctx, stage, planner.ExportImage, &exported); err != nil {
			return Result{}, err
		}
		media := filepath.Join(dir, "media")
		if err = materializeArchive(ctx, stage, planner.AssembleImage, "setup-media.tar", media, assembled.Media); err != nil {
			return Result{}, err
		}
		images := filepath.Join(dir, "images")
		if err = materializeArchive(ctx, stage, planner.ExportImage, "exported-images.tar", images, exported.Files); err != nil {
			return Result{}, err
		}
		for i := range exported.Export.Files {
			f := &exported.Export.Files[i]
			if filepath.Base(f.Path) != f.Path {
				return Result{}, planner.ErrIdentityChanged
			}
			src := filepath.Join(images, f.Path)
			dst := filepath.Join(media, "sources", f.Path)
			if err = copyMaterialized(ctx, src, dst, f.Size, f.SHA256); err != nil {
				return Result{}, err
			}
			f.Path = dst
		}
		boot := filepath.Join(media, "sources", "boot.wim")
		bootOut, err := materializeCheckpoint(ctx, stage, planner.AssembleImage, "boot.wim", boot)
		if err != nil {
			return Result{}, err
		}
		label := stage.Plan.EffectiveSettings().Output.Label
		if label == "auto" {
			label = "UUP_WINDOWS"
		}
		iso := filepath.Join(dir, "image.iso")
		prepared, err := output.Master(ctx, output.MasterRequest{Plan: stage.Plan, Export: exported.Export, MediaDirectory: media, ISOPath: iso, Label: label, BootWIM: output.File{Path: boot, Size: bootOut.Size, SHA256: bootOut.SHA256}, BootImages: assembled.BootImages}, p.Native)
		if err != nil {
			return Result{}, err
		}
		// Verify before the large ISO is committed; publication independently repeats
		// verification on the committed predecessor and destination bytes.
		if _, err = output.Verify(ctx, stage.Plan, iso, prepared); err != nil {
			return Result{}, err
		}
		image, err := commitFile(ctx, stage, "image.iso", iso, "local-iso")
		if err != nil {
			return Result{}, err
		}
		result, err := writeStageResult(stage, prepared, "prepared-iso")
		return Result{Outputs: []jobstore.OutputIdentity{image, result}}, err
	}}
}
func copyMaterialized(ctx context.Context, src, dst string, size int64, sha string) error {
	r, err := os.Open(src)
	if err != nil {
		return err
	}
	defer r.Close()
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	return errors.Join(copyCheckpoint(ctx, f, r, size, sha), f.Sync(), f.Close())
}
func (p *CheckpointPipeline) PublicationInputs(ctx context.Context, stage Stage) (PublicationInputs, error) {
	dir, err := p.directory("publish")
	if err != nil {
		return PublicationInputs{}, err
	}
	input := PublicationInputs{ISOPath: filepath.Join(dir, "image.iso")}
	if err = readCheckpoint(ctx, stage, planner.MasterISO, &input.Prepared); err != nil {
		return input, err
	}
	_, err = materializeCheckpoint(ctx, stage, planner.MasterISO, "image.iso", input.ISOPath)
	return input, err
}
func (p *CheckpointPipeline) payloads(ctx context.Context, stage Stage, dir string, refs []metadata.ResourceReference) ([]service.UpdateInput, error) {
	var receipt PreparedInputs
	if err := readCheckpoint(ctx, stage, planner.DownloadPayloads, &receipt); err != nil {
		return nil, err
	}
	if receipt.PlanDigest != stage.Plan.Digest() || receipt.ManifestDigest != stage.Plan.Manifest().Digest {
		return nil, planner.ErrIdentityChanged
	}
	var out []service.UpdateInput
	wanted := map[model.PayloadIdentity]string{}
	for _, ref := range refs {
		wanted[ref.Payload] = filepath.Join(dir, ref.Payload.Key()+".data")
	}
	if err := materializePrepared(ctx, stage, receipt, wanted); err != nil {
		return nil, err
	}
	seen := map[model.PayloadIdentity]string{}
	for _, ref := range refs {
		if path := seen[ref.Payload]; path != "" {
			out = append(out, service.UpdateInput{Resource: ref, Path: path})
			continue
		}
		found := false
		for _, file := range receipt.Files {
			if file.Identity != ref.Payload {
				continue
			}
			if file.Path != "payloads/"+ref.Payload.Key()+".data" {
				return nil, planner.ErrIdentityChanged
			}
			path := filepath.Join(dir, ref.Payload.Key()+".data")
			out = append(out, service.UpdateInput{Resource: ref, Path: path})
			seen[ref.Payload] = path
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("frozen payload is absent from download checkpoint")
		}
	}
	return out, nil
}

// The download checkpoint uses a fixed archive, so a selected source with over
// 256 payloads needs only two predecessor pins. Scan once and verify every entry;
// only the stage's requested files are materialized into its owned scratch.
func materializePrepared(ctx context.Context, stage Stage, receipt PreparedInputs, wanted map[model.PayloadIdentity]string) error {
	expected := map[string]PreparedPayload{}
	for _, file := range receipt.Files {
		if file.Path != "payloads/"+file.Identity.Key()+".data" || expected[file.Path].Path != "" {
			return planner.ErrIdentityChanged
		}
		expected[file.Path] = file
	}
	cp, out, err := predecessorFile(stage, planner.DownloadPayloads, "payloads.tar")
	if err != nil {
		return err
	}
	r, err := openCheckpoint(ctx, stage, cp, out)
	if err != nil {
		return err
	}
	defer r.Close()
	tr := tar.NewReader(io.NewSectionReader(r, 0, out.Size))
	seen := map[string]bool{}
	found := map[model.PayloadIdentity]bool{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		file, ok := expected[h.Name]
		if !ok || seen[h.Name] || h.Typeflag != tar.TypeReg || h.Size != file.Identity.Size {
			return planner.ErrIdentityChanged
		}
		seen[h.Name] = true
		dst := io.Writer(io.Discard)
		var f *os.File
		if path := wanted[file.Identity]; path != "" {
			f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			dst = f
			found[file.Identity] = true
		}
		err = copyCheckpoint(ctx, dst, tr, file.Identity.Size, file.SHA256)
		if f != nil {
			err = errors.Join(err, f.Sync(), f.Close())
		}
		if err != nil {
			return err
		}
	}
	if len(seen) != len(expected) || len(found) != len(wanted) {
		return planner.ErrIdentityChanged
	}
	return nil
}
func (p *CheckpointPipeline) ServiceInputs(ctx context.Context, stage Stage) (ServiceInputs, error) {
	var out ServiceInputs
	dir, err := p.directory("service-inputs")
	if err != nil {
		return out, err
	}
	var assembled AssemblyCheckpoint
	if err = readCheckpoint(ctx, stage, planner.AssembleImage, &assembled); err != nil {
		return out, err
	}
	if assembled.PlanDigest != stage.Plan.Digest() || assembled.ManifestDigest != stage.Plan.Manifest().Digest {
		return out, planner.ErrIdentityChanged
	}
	path := filepath.Join(dir, "base.wim")
	file, err := materializeCheckpoint(ctx, stage, planner.AssembleImage, "base.wim", path)
	if err != nil {
		return out, err
	}
	for _, id := range assembled.Images {
		out.Images = append(out.Images, service.InspectedImage{ImageRef: service.ImageRef{WIMPath: path, Index: id.Index, Name: id.Edition}, Identity: id, SHA256: file.SHA256})
	}
	var refs []metadata.ResourceReference
	for _, update := range stage.Plan.ServicePlan().Updates {
		refs = append(refs, update.Resource)
	}
	if edge := stage.Plan.ServicePlan().SourceEdge; edge != nil {
		if p.Runtime == nil {
			return out, service.ErrProviderUnavailable
		}
		if err = p.Runtime.AcquireSourceEdge(ctx, tools.SourceImage{Path: path, Size: file.Size, SHA256: file.SHA256, Architecture: stage.Plan.Manifest().Source.Architecture}); err != nil {
			return out, err
		}
		refs = append(refs, *edge)
	}
	out.Updates, err = p.payloads(ctx, stage, dir, refs)
	if err == nil && stage.Plan.ServicePlan().SourceEdge != nil {
		for i := range out.Updates {
			if out.Updates[i].Resource == *stage.Plan.ServicePlan().SourceEdge {
				target := filepath.Join(dir, "Edge.wim")
				if err = os.Rename(out.Updates[i].Path, target); err != nil {
					return out, err
				}
				out.Updates[i].Path = target
			}
		}
	}
	return out, err
}
func (p *CheckpointPipeline) CustomizationInputs(ctx context.Context, stage Stage) (service.CustomizationRequest, error) {
	var out service.CustomizationRequest
	dir, err := p.directory("customize-inputs")
	if err != nil {
		return out, err
	}
	var serviced service.ServicedImages
	if err = readCheckpoint(ctx, stage, planner.ServiceImage, &serviced); err != nil {
		return out, err
	}
	if serviced.PlanDigest != stage.Plan.ServicePlan().Digest {
		return out, planner.ErrIdentityChanged
	}
	path := filepath.Join(dir, "serviced.wim")
	file, err := materializeCheckpoint(ctx, stage, planner.ServiceImage, "serviced.wim", path)
	if err != nil {
		return out, err
	}
	for _, id := range serviced.Images {
		out.Images = append(out.Images, service.InspectedImage{ImageRef: service.ImageRef{WIMPath: path, Index: id.Index, Name: id.Edition}, Identity: id, SHA256: file.SHA256})
	}
	plan := stage.Plan.CustomizationPlan()
	if plan.Apps.Deferred || len(plan.Features) > 0 || len(plan.Drivers) > 0 {
		return out, fmt.Errorf("selected-source composition requires resolved app metadata and currently supports no extra drivers/NetFx3")
	}
	var refs []metadata.ResourceReference
	for _, app := range plan.Apps.Provision {
		refs = append(refs, app.Source())
		refs = append(refs, app.Dependencies...)
		refs = append(refs, app.Resources...)
		for _, file := range app.External {
			refs = append(refs, file.Resource)
		}
		if app.License != nil && len(app.LicenseXML) == 0 {
			refs = append(refs, *app.License)
		}
	}
	out.Payloads, err = p.payloads(ctx, stage, dir, refs)
	return out, err
}

func openCheckpoint(ctx context.Context, stage Stage, cp jobstore.PredecessorIdentity, out jobstore.OutputIdentity) (*jobstore.PredecessorReader, error) {
	allowance, err := stage.Transaction.PredecessorReadAllowance(ctx, cp, out)
	if err != nil {
		return nil, err
	}
	return stage.Transaction.OpenPredecessor(ctx, cp, out, allowance)
}
