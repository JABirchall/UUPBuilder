package wimindex

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"path/filepath"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

type sourceView struct {
	ctx      context.Context
	file     *os.File
	path     string
	identity model.PayloadIdentity
	initial  os.FileInfo
}

func openSource(ctx context.Context, r metadata.LocalResource) (*sourceView, error) {
	if !filepath.IsAbs(r.Path) {
		return nil, ErrInput
	}
	f, err := os.Open(r.Path)
	if err != nil {
		return nil, ErrIntegrity
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != r.Identity.Size {
		f.Close()
		return nil, ErrIntegrity
	}
	v := &sourceView{ctx: ctx, file: f, path: r.Path, identity: r.Identity, initial: info}
	return v, nil
}
func (v *sourceView) ReadAt(b []byte, off int64) (int, error) {
	if err := v.ctx.Err(); err != nil {
		return 0, err
	}
	if off < 0 || off > v.identity.Size || int64(len(b)) > v.identity.Size-off {
		return 0, ErrLayout
	}
	n, err := v.file.ReadAt(b, off)
	if v.ctx.Err() != nil {
		return n, v.ctx.Err()
	}
	return n, err
}
func (v *sourceView) rehash() (string, error) {
	if err := v.ctx.Err(); err != nil {
		return "", err
	}
	now, err := v.file.Stat()
	if err != nil || !os.SameFile(v.initial, now) || now.Size() != v.initial.Size() || !now.ModTime().Equal(v.initial.ModTime()) {
		return "", ErrIntegrity
	}
	named, err := os.Stat(v.path)
	if err != nil || !os.SameFile(v.initial, named) {
		return "", ErrIntegrity
	}
	var original hash.Hash
	switch v.identity.Digest.Algorithm {
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
	r := io.NewSectionReader(v, 0, v.identity.Size)
	n, err := io.CopyBuffer(io.MultiWriter(original, computed), r, buf)
	if v.ctx.Err() != nil {
		return "", v.ctx.Err()
	}
	if err != nil || n != v.identity.Size || hex.EncodeToString(original.Sum(nil)) != v.identity.Digest.Value {
		return "", ErrIntegrity
	}
	// Check the retained handle and path again after the complete read.
	now, err = v.file.Stat()
	if err != nil || now.Size() != v.initial.Size() || !now.ModTime().Equal(v.initial.ModTime()) {
		return "", ErrIntegrity
	}
	named, err = os.Stat(v.path)
	if err != nil || !os.SameFile(v.initial, named) {
		return "", ErrIntegrity
	}
	return hex.EncodeToString(computed.Sum(nil)), nil
}
