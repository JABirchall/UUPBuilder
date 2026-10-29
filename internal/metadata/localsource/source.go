// Package localsource verifies retained read-only source handles. A verified
// hash here alone grants no manifest, catalog, or decoded-content authority.
package localsource

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"

	"uupbuilder/internal/model"
)

var ErrInput = errors.New("invalid local source")
var ErrIntegrity = errors.New("local source changed")

func Open(path string, id model.PayloadIdentity) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(path) {
		return nil, nil, ErrInput
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, nil, ErrIntegrity
	}
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() != id.Size {
		f.Close()
		return nil, nil, ErrIntegrity
	}
	return f, info, nil
}

type contextReaderAt struct {
	ctx  context.Context
	file *os.File
	size int64
}

func (r contextReaderAt) ReadAt(b []byte, off int64) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	if off < 0 || off > r.size || int64(len(b)) > r.size-off {
		return 0, ErrIntegrity
	}
	n, e := r.file.ReadAt(b, off)
	if r.ctx.Err() != nil {
		return n, r.ctx.Err()
	}
	return n, e
}
func Verify(ctx context.Context, file *os.File, path string, identity model.PayloadIdentity, initial os.FileInfo) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	now, err := file.Stat()
	if err != nil || !os.SameFile(initial, now) || now.Size() != initial.Size() || !now.ModTime().Equal(initial.ModTime()) {
		return "", ErrIntegrity
	}
	named, err := os.Stat(path)
	if err != nil || !os.SameFile(initial, named) {
		return "", ErrIntegrity
	}
	var original hash.Hash
	switch identity.Digest.Algorithm {
	case model.DigestMD5:
		original = md5.New()
	case model.DigestSHA1:
		original = sha1.New()
	case model.DigestSHA256:
		original = sha256.New()
	case model.DigestSHA384:
		original = sha512.New384()
	case model.DigestSHA512:
		original = sha512.New()
	default:
		return "", ErrInput
	}
	computed := sha256.New()
	buf := make([]byte, 64<<10)
	r := io.NewSectionReader(contextReaderAt{ctx, file, identity.Size}, 0, identity.Size)
	n, err := io.CopyBuffer(io.MultiWriter(original, computed), r, buf)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil || n != identity.Size || hex.EncodeToString(original.Sum(nil)) != identity.Digest.Value {
		return "", ErrIntegrity
	}
	// Check the retained handle and path again after the complete read.
	now, err = file.Stat()
	if err != nil || now.Size() != initial.Size() || !now.ModTime().Equal(initial.ModTime()) {
		return "", ErrIntegrity
	}
	named, err = os.Stat(path)
	if err != nil || !os.SameFile(initial, named) {
		return "", ErrIntegrity
	}
	return hex.EncodeToString(computed.Sum(nil)), nil
}
