package probes

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"strings"

	"uupbuilder/internal/model"
)

type artifactFiles interface {
	OpenFile(string, int, os.FileMode) (*os.File, error)
	Remove(string) error
}

type RetainedArtifact struct {
	Artifact Artifact `json:"artifact"`
	Path     string   `json:"path"`
	SHA256   string   `json:"sha256"`
}

func retainFixture(ctx context.Context, source *os.Root, destination artifactFiles, sourcePath, destinationPath string, expected Artifact) (RetainedArtifact, error) {
	if err := ctx.Err(); err != nil {
		return RetainedArtifact{}, err
	}
	if err := expected.validate(""); err != nil {
		return RetainedArtifact{}, err
	}
	if expected.Size == math.MaxInt64 {
		return RetainedArtifact{}, errors.New("artifact size exceeds bounded reader")
	}
	if _, err := model.ValidateRelativePath(sourcePath); err != nil {
		return RetainedArtifact{}, err
	}
	if _, err := model.ValidateRelativePath(destinationPath); err != nil {
		return RetainedArtifact{}, err
	}
	in, err := source.Open(sourcePath)
	if err != nil {
		return RetainedArtifact{}, err
	}
	defer in.Close()
	return retainFile(ctx, in, destination, destinationPath, expected)
}

func retainFile(ctx context.Context, in *os.File, destination artifactFiles, destinationPath string, expected Artifact) (RetainedArtifact, error) {
	if err := ctx.Err(); err != nil {
		return RetainedArtifact{}, err
	}
	if err := expected.validate(""); err != nil {
		return RetainedArtifact{}, err
	}
	if expected.Size == math.MaxInt64 {
		return RetainedArtifact{}, errors.New("artifact size exceeds bounded reader")
	}
	if _, err := model.ValidateRelativePath(destinationPath); err != nil {
		return RetainedArtifact{}, err
	}
	info, err := in.Stat()
	if err != nil {
		return RetainedArtifact{}, err
	}
	if !info.Mode().IsRegular() || info.Size() != expected.Size {
		return RetainedArtifact{}, errors.New("fixture must be a regular file with expected size")
	}
	out, err := destination.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return RetainedArtifact{}, err
	}
	valid := false
	defer func() {
		out.Close()
		if !valid {
			destination.Remove(destinationPath)
		}
	}()
	measured := sha256.New()
	var original hash.Hash = measured
	if expected.Digest.Algorithm == model.DigestSHA1 {
		original = sha1.New()
	}
	writers := []io.Writer{out, measured}
	if original != measured {
		writers = append(writers, original)
	}
	n, err := io.Copy(io.MultiWriter(writers...), io.LimitReader(contextReader{ctx, in}, expected.Size+1))
	if err != nil {
		return RetainedArtifact{}, err
	}
	if n != expected.Size || !strings.EqualFold(hex.EncodeToString(original.Sum(nil)), expected.Digest.Value) {
		return RetainedArtifact{}, fmt.Errorf("artifact %s: retained size/digest mismatch", expected.ID)
	}
	if err := ctx.Err(); err != nil {
		return RetainedArtifact{}, err
	}
	if err := out.Sync(); err != nil {
		return RetainedArtifact{}, err
	}
	if err := out.Close(); err != nil {
		return RetainedArtifact{}, err
	}
	valid = true
	return RetainedArtifact{expected, destinationPath, hex.EncodeToString(measured.Sum(nil))}, nil
}

type contextReader struct {
	context context.Context
	reader  io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.context.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}
