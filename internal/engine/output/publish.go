package output

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"uupbuilder/internal/model"
)

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func digest(ctx context.Context, f *os.File) (int64, string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, f})
	return n, hex.EncodeToString(h.Sum(nil)), err
}

// Publish reserves all three destination names exclusively. On failure only
// files created by this call are removed; the verified local ISO is retained.
func Publish(ctx context.Context, verified VerifiedArtifact, directory, filename string) (artifact model.Artifact, resultErr error) {
	if ctx == nil || verified.state == nil {
		return artifact, ErrVerification
	}
	v := verified.state
	if filepath.Base(filename) != filename || strings.ContainsAny(filename, "/\\:\x00") || !strings.EqualFold(filepath.Ext(filename), ".iso") || len(filename) <= 4 {
		return artifact, ErrVerification
	}
	if err := ctx.Err(); err != nil {
		return artifact, err
	}
	src, err := os.Open(v.path)
	if err != nil {
		return artifact, err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return artifact, err
	}
	if !info.Mode().IsRegular() {
		return artifact, ErrVerification
	}
	n, h, err := digest(ctx, src)
	if err != nil {
		return artifact, err
	}
	if n != v.size || h != v.sha256 {
		return artifact, ErrVerification
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return artifact, err
	}
	var files []*os.File
	var paths []string
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
		if resultErr != nil {
			for _, p := range paths {
				resultErr = errors.Join(resultErr, os.Remove(p))
			}
		}
	}()
	for attempt := 0; attempt < 10000; attempt++ {
		name := filename
		if attempt > 0 {
			name = fmt.Sprintf("%s (%d).iso", strings.TrimSuffix(filename, filepath.Ext(filename)), attempt)
		}
		base := filepath.Join(directory, name)
		collision := false
		for _, p := range []string{base, base + ".sha256", base + ".report.json"} {
			f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if e != nil {
				if !errors.Is(e, os.ErrExist) {
					return artifact, e
				}
				collision = true
				break
			}
			files = append(files, f)
			paths = append(paths, p)
		}
		if !collision {
			break
		}
		for _, f := range files {
			_ = f.Close()
		}
		for _, p := range paths {
			if e := os.Remove(p); e != nil {
				return artifact, e
			}
		}
		files = nil
		paths = nil
	}
	if len(files) != 3 {
		return artifact, errors.New("output filename collision limit reached")
	}
	if _, err = src.Seek(0, io.SeekStart); err != nil {
		return artifact, err
	}
	if _, err = io.Copy(files[0], contextReader{ctx, src}); err != nil {
		return artifact, err
	}
	if err = files[0].Sync(); err != nil {
		return artifact, err
	}
	n, h, err = digest(ctx, files[0])
	if err != nil {
		return artifact, err
	}
	if n != v.size || h != v.sha256 {
		return artifact, ErrVerification
	}
	artifact = model.Artifact{Kind: model.OutputISO, Path: paths[0], VerificationPath: paths[1], ReportPath: paths[2], SHA256: h, Size: n, PlanDigest: v.planDigest, Source: v.source}
	if _, err = fmt.Fprintf(files[1], "%s  %s\n", h, filepath.Base(paths[0])); err != nil {
		return model.Artifact{}, err
	}
	if err = writeReport(files[2], artifact, v); err != nil {
		return model.Artifact{}, err
	}
	for _, f := range files {
		if err = f.Sync(); err != nil {
			return model.Artifact{}, err
		}
	}
	if err = ctx.Err(); err != nil {
		return model.Artifact{}, err
	}
	for _, f := range files {
		if err = f.Close(); err != nil {
			return model.Artifact{}, err
		}
	}
	files = nil
	return artifact, nil
}
