package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
)

func (e *Executor) Execute(ctx context.Context, req ServiceRequest, emit model.Emit) (out ServicedImages, err error) {
	if ctx == nil || req.Transaction == nil || req.Plan.Validate() != nil {
		return out, planner.ErrInvalidPlan
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if _, err = req.Transaction.ScratchPath("serviced.wim"); err != nil {
		return out, err
	}
	if e == nil || e.Backend == nil {
		return out, ErrProviderUnavailable
	}
	if err = e.Backend.Check(ctx, req); err != nil {
		return out, err
	}
	bases := map[string]InspectedImage{}
	for _, image := range req.Images {
		if image.Index < 1 || image.Identity.Index != image.Index || image.Identity.Architecture != req.Plan.Source.Architecture || !strings.EqualFold(image.Identity.Language, req.Plan.Source.Language) {
			return out, fmt.Errorf("%w: source image identity", ErrVerification)
		}
		if err = verifySHA256(ctx, image.WIMPath, image.SHA256); err != nil {
			return out, err
		}
		observed, inspectErr := e.Backend.InspectWIM(ctx, image.WIMPath, emit)
		if inspectErr != nil {
			return out, inspectErr
		}
		if image.Index > len(observed) || !sameImage(observed[image.Index-1], image.Identity) {
			return out, fmt.Errorf("%w: source WIM inspection", ErrVerification)
		}
		key := strings.ToLower(image.Identity.Edition)
		if _, ok := bases[key]; ok {
			return out, fmt.Errorf("ambiguous inspected source base %s", key)
		}
		bases[key] = image
	}
	for _, base := range req.Plan.Bases {
		if _, ok := bases[strings.ToLower(base)]; !ok {
			return out, fmt.Errorf("missing inspected assembly base %s", base)
		}
	}
	updatePaths, err := verifyUpdates(ctx, req)
	if err != nil {
		return out, err
	}
	if req.Plan.SourceEdge != nil {
		if _, ok := e.Backend.(SourceEdgeBackend); !ok {
			return out, ErrProviderUnavailable
		}
		var edge string
		for _, input := range req.Payloads {
			if input.Resource == *req.Plan.SourceEdge {
				if edge != "" {
					return out, ErrVerification
				}
				edge = input.Path
			}
		}
		if edge == "" {
			return out, fmt.Errorf("source EdgeContent input missing")
		}
		if err = verifyUpdateFile(ctx, req.Plan.SourceEdge.Payload, edge); err != nil {
			return out, err
		}
		updatePaths["source-edge-content"] = edge
	}
	out.PlanDigest = req.Plan.Digest
	for i, update := range req.Plan.Updates {
		if !update.Retain {
			continue
		}
		name := fmt.Sprintf("update-%03d.%s", i+1, update.Format)
		if err = copyRetained(ctx, req, name, updatePaths[update.ID]); err != nil {
			return ServicedImages{}, err
		}
		path, pathErr := req.Transaction.ScratchPath(name)
		if pathErr != nil {
			return ServicedImages{}, pathErr
		}
		out.RetainedUpdates = append(out.RetainedUpdates, RetainedUpdate{ID: update.ID, Path: path, Format: update.Format})
		identity, identityErr := fileOutput(ctx, path, name, "external-update")
		if identityErr != nil {
			return ServicedImages{}, identityErr
		}
		out.Outputs = append(out.Outputs, identity)
	}
	if req.Plan.Strategy == model.ServicingSharedBase {
		for i, base := range req.Plan.Bases {
			image := bases[strings.ToLower(base)]
			name := fmt.Sprintf("base-%03d.wim", i+1)
			path, pathErr := req.Transaction.ScratchPath(name)
			if pathErr != nil {
				return ServicedImages{}, pathErr
			}
			if err = e.Backend.Export(ctx, image.ImageRef, path, emit); err != nil {
				return ServicedImages{}, err
			}
			if _, err = e.serviceOne(ctx, req, path, "base-mount-"+fmt.Sprint(i+1), base, false, false, updatePaths, emit); err != nil {
				return ServicedImages{}, err
			}
			image.ImageRef = ImageRef{WIMPath: path, Index: 1, Name: base}
			bases[strings.ToLower(base)] = image
			if req.Plan.PreserveRequiredBases {
				out.RetainedBases = append(out.RetainedBases, path)
				identity, identityErr := fileOutput(ctx, path, name, "temporary-serviced-base")
				if identityErr != nil {
					return ServicedImages{}, identityErr
				}
				out.Outputs = append(out.Outputs, identity)
			}
		}
	}
	finalPath, err := req.Transaction.ScratchPath("serviced.wim")
	if err != nil {
		return ServicedImages{}, err
	}
	for i, edition := range req.Plan.Editions {
		if err = ctx.Err(); err != nil {
			return ServicedImages{}, err
		}
		base := bases[strings.ToLower(edition.Base)]
		name := fmt.Sprintf("edition-%03d.wim", i+1)
		path, pathErr := req.Transaction.ScratchPath(name)
		if pathErr != nil {
			return ServicedImages{}, pathErr
		}
		if err = e.Backend.Export(ctx, base.ImageRef, path, emit); err != nil {
			return ServicedImages{}, err
		}
		inspection, serviceErr := e.serviceOne(ctx, req, path, "edition-mount-"+fmt.Sprint(i+1), edition.Edition, edition.Derive, true, updatePaths, emit)
		if serviceErr != nil {
			return ServicedImages{}, serviceErr
		}
		if err = e.Backend.Export(ctx, ImageRef{WIMPath: path, Index: 1, Name: edition.Edition}, finalPath, emit); err != nil {
			return ServicedImages{}, err
		}
		out.Images = append(out.Images, ImageIdentity{Index: i + 1, Edition: inspection.Edition, Architecture: req.Plan.Source.Architecture, Language: req.Plan.Source.Language, Packages: inspection.Packages})
	}
	observed, err := e.Backend.InspectWIM(ctx, finalPath, emit)
	if err != nil {
		return ServicedImages{}, err
	}
	if len(observed) != len(out.Images) {
		return ServicedImages{}, fmt.Errorf("%w: final WIM image count", ErrVerification)
	}
	for i, image := range observed {
		if !sameImage(image, out.Images[i]) {
			return ServicedImages{}, fmt.Errorf("%w: final WIM index %d identity", ErrVerification, i+1)
		}
	}
	identity, err := fileOutput(ctx, finalPath, "serviced.wim", "serviced-install-image")
	if err != nil {
		return ServicedImages{}, err
	}
	out.Outputs = append(out.Outputs, identity)
	out.WIMPath = finalPath
	if emit != nil {
		emit(model.Event{StageID: "service-image", Kind: model.EventStage, Message: "Selected editions and required packages verified", Timestamp: time.Now()})
	}
	return out, ctx.Err()
}

func sameImage(a, b ImageIdentity) bool {
	return a.Index == b.Index && strings.EqualFold(a.Edition, b.Edition) && a.Architecture == b.Architecture && strings.EqualFold(a.Language, b.Language)
}
func verifySHA256(ctx context.Context, path, digest string) error {
	if (model.Digest{Algorithm: model.DigestSHA256, Value: digest}).Validate() != nil {
		return ErrVerification
	}
	identity, err := fileOutput(ctx, path, "", "")
	if err != nil {
		return err
	}
	if identity.SHA256 != digest {
		return fmt.Errorf("%w: input bytes changed", ErrVerification)
	}
	return nil
}
func fileOutput(ctx context.Context, path, name, role string) (jobstore.OutputIdentity, error) {
	f, err := os.Open(path)
	if err != nil {
		return jobstore.OutputIdentity{}, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return jobstore.OutputIdentity{}, ErrVerification
	}
	h := sha256.New()
	buf := make([]byte, 1<<20)
	var n int64
	for {
		if err := ctx.Err(); err != nil {
			return jobstore.OutputIdentity{}, err
		}
		count, readErr := f.Read(buf)
		if count > 0 {
			h.Write(buf[:count])
			n += int64(count)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return jobstore.OutputIdentity{}, readErr
		}
	}
	if n != stat.Size() {
		return jobstore.OutputIdentity{}, ErrVerification
	}
	return jobstore.OutputIdentity{Path: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Role: role}, nil
}
