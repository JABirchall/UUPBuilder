package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"uupbuilder/internal/engine/output"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/planner"
)

type PublicationInputs struct {
	ISOPath  string
	Prepared output.PreparedISO
}
type PublicationInputProvider interface {
	PublicationInputs(context.Context, Stage) (PublicationInputs, error)
}

// PublicationHandler is the sole registry handler able to mark the destination
// capability boundary. Its provider supplies inputs, never completion claims.
func PublicationHandler(provider PublicationInputProvider) Handler {
	return Handler{publishes: provider != nil, Run: func(ctx context.Context, stage Stage) (Result, error) {
		if provider == nil || stage.Transaction == nil || stage.Operation.Kind != planner.PublishISO {
			return Result{}, ErrMissingHandler
		}
		input, err := provider.PublicationInputs(ctx, stage)
		if err != nil {
			return Result{}, err
		}
		verified, err := output.Verify(ctx, stage.Plan, input.ISOPath, input.Prepared)
		if err != nil {
			return Result{}, err
		}
		s := stage.Plan.EffectiveSettings().Output
		name := s.Filename
		if name == "auto" {
			name = "Windows-" + string(stage.Plan.Manifest().Source.Architecture) + ".iso"
		}
		published, err := output.PublishVerified(ctx, verified, s.Directory, name)
		if err != nil {
			return Result{}, err
		}
		artifact, err := published.Artifact(ctx, stage.Plan.Digest(), stage.Plan.Manifest().Source)
		if err != nil {
			return Result{}, err
		}
		result, err := writeStageResult(stage, artifact, "published-iso")
		if err != nil {
			return Result{}, err
		}
		outputs := []jobstore.OutputIdentity{result}
		for name, path := range map[string]string{"image.sha256": artifact.VerificationPath, "report.json": artifact.ReportPath} {
			f, err := os.Open(path)
			if err != nil {
				return Result{}, err
			}
			dst, err := stage.Transaction.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				f.Close()
				return Result{}, err
			}
			hash := sha256.New()
			size, copyErr := io.Copy(io.MultiWriter(dst, hash), f)
			err = errors.Join(copyErr, f.Close(), dst.Sync(), dst.Close())
			if err != nil {
				return Result{}, err
			}
			outputs = append(outputs, jobstore.OutputIdentity{Path: name, Size: size, SHA256: hex.EncodeToString(hash.Sum(nil)), Role: "publication-sidecar"})
		}
		return Result{Outputs: outputs, Publication: &published}, ctx.Err()
	}}
}
