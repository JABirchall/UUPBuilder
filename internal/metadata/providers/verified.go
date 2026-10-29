package providers

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

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}

// Open and verify once, then retain that same handle for container reads.
// A local SHA-256 never replaces the original source digest or provenance.
func verified(ctx context.Context, r metadata.LocalResource) (*os.File, error) {
	if ctx == nil || r.Identity.Validate() != nil || !filepath.IsAbs(r.Path) {
		return nil, metadata.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.Identity.Encryption.Method != "" {
		return nil, ErrUnsupported
	}
	f, err := os.Open(r.Path)
	if err != nil {
		return nil, metadata.ErrIntegrity
	}
	failed := true
	defer func() {
		if failed {
			f.Close()
		}
	}()
	s, err := f.Stat()
	if err != nil || !s.Mode().IsRegular() || s.Size() != r.Identity.Size {
		return nil, metadata.ErrIntegrity
	}
	var h hash.Hash
	switch r.Identity.Digest.Algorithm {
	case model.DigestMD5:
		h = md5.New()
	case model.DigestSHA1:
		h = sha1.New()
	case model.DigestSHA256:
		h = sha256.New()
	case model.DigestSHA384:
		h = sha512.New384()
	case model.DigestSHA512:
		h = sha512.New()
	default:
		return nil, metadata.ErrInvalidInput
	}
	n, err := io.Copy(h, contextReader{ctx, io.LimitReader(f, r.Identity.Size+1)})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || n != r.Identity.Size || hex.EncodeToString(h.Sum(nil)) != r.Identity.Digest.Value {
		return nil, metadata.ErrIntegrity
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, metadata.ErrIntegrity
	}
	failed = false
	return f, nil
}

func documentLimit(l metadata.Limits) (int64, error) {
	if l.MaxDocumentBytes < 0 || l.MaxDocumentBytes > 8<<20 || l.MaxTotalBytes < 0 || l.MaxTotalBytes > 32<<20 || l.MaxDocuments < 0 || l.MaxDocuments > 256 {
		return 0, metadata.ErrLimit
	}
	if l.MaxDocumentBytes == 0 {
		l.MaxDocumentBytes = 8 << 20
	}
	if l.MaxTotalBytes > 0 && l.MaxTotalBytes < l.MaxDocumentBytes {
		return l.MaxTotalBytes, nil
	}
	return l.MaxDocumentBytes, nil
}
