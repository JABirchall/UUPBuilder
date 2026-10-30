//go:build windows

package worker

import (
	"archive/tar"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"uupbuilder/internal/download"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
)

type PreparationFetcher interface {
	Fetch(context.Context, model.PayloadManifest, model.Locators, model.Emit) (download.Materialized, error)
}
type PreparedPayload struct {
	Identity model.PayloadIdentity `json:"identity"`
	Path     string                `json:"path"`
	SHA256   string                `json:"sha256"`
}
type PreparedInputs struct {
	Version        int               `json:"version"`
	PlanDigest     string            `json:"plan_digest"`
	ManifestDigest string            `json:"manifest_digest"`
	Files          []PreparedPayload `json:"files"`
}

// PreparationHandler borrows the source manager for its entire registered
// lifetime. The active worker retains sole transaction/store custody. Only
// identity-verified copies inside declared stage paths become U07 inputs.
func PreparationHandler(fetcher PreparationFetcher, emit model.Emit) Handler {
	return Handler{Run: func(ctx context.Context, stage Stage) (Result, error) {
		if fetcher == nil || stage.Transaction == nil || stage.Plan.Validate() != nil || stage.Operation.Kind != planner.DownloadPayloads {
			return Result{}, ErrMissingHandler
		}
		manifest := stage.Plan.Manifest()
		if stage.Operation.SourceDigest != manifest.Digest {
			return Result{}, planner.ErrIdentityChanged
		}
		// The composed manager verifies cache hits first, and obtains runtime-only
		// locators through its exact frozen-query refresh only for missing bytes.
		files, err := fetcher.Fetch(ctx, manifest, nil, emit)
		if err != nil {
			return Result{}, err
		}
		if len(files) != len(manifest.Payloads) {
			return Result{}, download.ErrIntegrity
		}
		if stage.Plan.Intent() == planner.BuildMedia {
			return prepareArchive(ctx, stage, files)
		}
		receipt := PreparedInputs{Version: 1, PlanDigest: stage.Plan.Digest(), ManifestDigest: manifest.Digest}
		var outputs []jobstore.OutputIdentity
		for _, p := range manifest.Payloads {
			file, ok := files[p.Identity]
			if !ok || file.Identity != p.Identity || (model.Digest{Algorithm: model.DigestSHA256, Value: file.SHA256}).Validate() != nil {
				return Result{}, download.ErrIntegrity
			}
			path := "payloads/" + p.Identity.Key() + ".data"
			if err := copyPrepared(ctx, stage, path, file); err != nil {
				return Result{}, err
			}
			receipt.Files = append(receipt.Files, PreparedPayload{Identity: p.Identity, Path: path, SHA256: file.SHA256})
			outputs = append(outputs, jobstore.OutputIdentity{Path: path, Size: p.Identity.Size, SHA256: file.SHA256, Role: "prepared-payload"})
		}
		data, err := json.Marshal(receipt)
		if err != nil {
			return Result{}, err
		}
		f, err := stage.Transaction.OpenFile("result.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return Result{}, err
		}
		_, writeErr := f.Write(data)
		syncErr := f.Sync()
		closeErr := f.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return Result{}, err
		}
		sum := sha256.Sum256(data)
		outputs = append(outputs, jobstore.OutputIdentity{Path: "result.json", Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Role: "prepared-inputs"})
		return Result{Outputs: outputs}, ctx.Err()
	}}
}

func prepareArchive(ctx context.Context, stage Stage, files download.Materialized) (Result, error) {
	manifest := stage.Plan.Manifest()
	receipt := PreparedInputs{Version: 1, PlanDigest: stage.Plan.Digest(), ManifestDigest: manifest.Digest}
	dst, err := stage.Transaction.OpenFile("payloads.tar", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return Result{}, err
	}
	h := sha256.New()
	counter := &countWriter{w: io.MultiWriter(dst, h)}
	tw := tar.NewWriter(counter)
	for _, payload := range manifest.Payloads {
		file, ok := files[payload.Identity]
		if !ok || file.Identity != payload.Identity {
			dst.Close()
			return Result{}, download.ErrIntegrity
		}
		name := "payloads/" + payload.Identity.Key() + ".data"
		receipt.Files = append(receipt.Files, PreparedPayload{Identity: file.Identity, Path: name, SHA256: file.SHA256})
		if err = tw.WriteHeader(&tar.Header{Name: name, Size: file.Identity.Size, Mode: 0600, Typeflag: tar.TypeReg}); err != nil {
			dst.Close()
			return Result{}, err
		}
		src, e := os.Open(file.Path)
		if e != nil {
			dst.Close()
			return Result{}, e
		}
		err = copyCheckpoint(ctx, tw, src, file.Identity.Size, file.SHA256)
		src.Close()
		if err != nil {
			dst.Close()
			return Result{}, err
		}
		// Download.Materialized records the original digest; selected production
		// payloads are SHA256 and the copied bytes must match that authority too.
		if file.Identity.Digest.Algorithm != model.DigestSHA256 || file.Identity.Digest.Value != file.SHA256 {
			dst.Close()
			return Result{}, download.ErrIntegrity
		}
	}
	err = errors.Join(tw.Close(), dst.Sync(), dst.Close())
	if err != nil {
		return Result{}, err
	}
	result, err := writeStageResult(stage, receipt, "prepared-inputs")
	return Result{Outputs: []jobstore.OutputIdentity{{Path: "payloads.tar", Size: counter.n, SHA256: hex.EncodeToString(h.Sum(nil)), Role: "prepared-payload-archive"}, result}}, err
}

type preparationReader struct {
	ctx context.Context
	r   io.Reader
}

func (r preparationReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}

func copyPrepared(ctx context.Context, stage Stage, path string, file download.CachedFile) error {
	src, err := os.Open(file.Path)
	if err != nil {
		return download.ErrIntegrity
	}
	defer src.Close()
	stat, err := src.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() != file.Identity.Size {
		return download.ErrIntegrity
	}
	dst, err := stage.Transaction.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	var source hash.Hash
	switch file.Identity.Digest.Algorithm {
	case model.DigestMD5:
		source = md5.New()
	case model.DigestSHA1:
		source = sha1.New()
	case model.DigestSHA256:
		source = sha256.New()
	case model.DigestSHA384:
		source = sha512.New384()
	case model.DigestSHA512:
		source = sha512.New()
	default:
		dst.Close()
		return download.ErrIntegrity
	}
	internal := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(dst, source, internal), preparationReader{ctx, io.LimitReader(src, file.Identity.Size+1)})
	if copyErr == nil && (n != file.Identity.Size || hex.EncodeToString(source.Sum(nil)) != file.Identity.Digest.Value || hex.EncodeToString(internal.Sum(nil)) != file.SHA256) {
		copyErr = download.ErrIntegrity
	}
	var syncErr error
	if copyErr == nil {
		syncErr = dst.Sync()
	}
	return errors.Join(copyErr, syncErr, dst.Close())
}
