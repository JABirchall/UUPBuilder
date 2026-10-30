//go:build windows

package download

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
	"strings"

	"uupbuilder/internal/model"
)

type digests struct{ source, internal hash.Hash }

func newDigests(algorithm model.DigestAlgorithm) digests {
	var source hash.Hash
	switch algorithm {
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
	}
	return digests{source: source, internal: sha256.New()}
}
func (d digests) Write(p []byte) (int, error) {
	d.source.Write(p)
	d.internal.Write(p)
	return len(p), nil
}
func (d digests) matches(id model.PayloadIdentity) bool {
	return hex.EncodeToString(d.source.Sum(nil)) == id.Digest.Value
}
func (d digests) sha256() string { return hex.EncodeToString(d.internal.Sum(nil)) }

// stream checks cancellation between bounded reads/writes, never allocates from
// advertised size, and refuses even one byte beyond the frozen expected size.
func stream(ctx context.Context, dst io.Writer, src io.Reader, limit int64, progress func(int64)) (int64, error) {
	buffer := make([]byte, 128*1024)
	var copied int64
	empty := 0
	for {
		if err := ctx.Err(); err != nil {
			return copied, err
		}
		want := int64(len(buffer))
		remaining := limit - copied
		if remaining < want {
			want = remaining + 1
		}
		n, readErr := src.Read(buffer[:int(want)])
		if n > 0 {
			empty = 0
			if int64(n) > remaining {
				return copied, ErrIntegrity
			}
			written, err := dst.Write(buffer[:n])
			copied += int64(written)
			if err != nil || written != n {
				return copied, ErrStorage
			}
			if progress != nil {
				progress(copied)
			}
		} else {
			empty++
		}
		if readErr != nil {
			if readErr == io.EOF {
				return copied, nil
			}
			if ctx.Err() != nil {
				return copied, ctx.Err()
			}
			return copied, ErrTransfer
		}
		if empty >= 100 {
			return copied, ErrTransfer
		}
	}
}

func (m *Manager) transfer(ctx context.Context, p model.Payload, loc Locator, progress *progressReporter) (CachedFile, error) {
	id := p.Identity
	key := id.Key()
	f, err := m.opts.Job.OpenFile(key+".part", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return CachedFile{}, ErrStorage
	}
	defer f.Close()
	record, offset, err := loadResume(m.opts.Job, id, f)
	if err != nil {
		return CachedFile{}, err
	}
	hashes := newDigests(id.Digest.Algorithm)
	if offset > 0 {
		n, err := stream(ctx, hashes, io.NewSectionReader(f, 0, offset), offset, nil)
		if err != nil {
			return CachedFile{}, err
		}
		if n != offset {
			return CachedFile{}, ErrStorage
		}
	}
	progress.start(offset)
	resp, err := m.request(ctx, loc, offset)
	if err != nil {
		return CachedFile{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return CachedFile{}, errExpired
	}
	restart := func() (CachedFile, error) {
		if err := resetPartial(m.opts.Job, key, f); err != nil {
			return CachedFile{}, err
		}
		return CachedFile{}, errRestart
	}
	if resp.StatusCode == 416 {
		total, err := unsatisfiedTotal(resp.Header.Get("Content-Range"))
		if err == nil && offset == id.Size && total == id.Size && hashes.matches(id) {
			progress.send(model.DownloadVerifying)
			if f.Close() != nil {
				return CachedFile{}, ErrStorage
			}
			return m.publish(ctx, id, hashes.sha256())
		}
		return restart()
	}
	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		return CachedFile{}, ErrTransfer
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return CachedFile{}, ErrTransfer
	}
	kind, validator := responseValidator(resp.Header)
	if resp.StatusCode == 206 {
		start, end, total, err := parseContentRange(resp.Header.Get("Content-Range"))
		if offset == 0 || err != nil || start != offset || end != id.Size-1 || total != id.Size || kind == "" || kind != record.ValidatorKind || validator != record.ValidatorHash ||
			(resp.ContentLength >= 0 && resp.ContentLength != end-start+1) {
			return restart()
		}
	} else {
		// A server ignoring Range sends the complete object; discard the prefix
		// before consuming that same response rather than append or request again.
		if offset > 0 {
			if err := resetPartial(m.opts.Job, key, f); err != nil {
				return CachedFile{}, err
			}
			offset = 0
			hashes = newDigests(id.Digest.Algorithm)
			progress.start(0)
		}
		if resp.ContentLength >= 0 && resp.ContentLength != id.Size {
			return CachedFile{}, ErrIntegrity
		}
	}
	if kind != "" {
		if err := writeJSON(m.opts.Job, key+".resume.json", resumeRecord{Version: 1, Key: key, ValidatorKind: kind, ValidatorHash: validator}); err != nil {
			return CachedFile{}, err
		}
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return CachedFile{}, ErrStorage
	}
	bytes, err := stream(ctx, io.MultiWriter(f, hashes), resp.Body, id.Size-offset, func(n int64) { progress.advance(offset + n) })
	if err != nil {
		if err == ErrIntegrity {
			if resetErr := resetPartial(m.opts.Job, key, f); resetErr != nil {
				return CachedFile{}, resetErr
			}
		}
		return CachedFile{}, err
	}
	if offset+bytes != id.Size {
		return CachedFile{}, ErrTransfer
	}
	if id.Size == 0 {
		progress.send(model.DownloadVerifying)
	}
	if !hashes.matches(id) {
		if err := resetPartial(m.opts.Job, key, f); err != nil {
			return CachedFile{}, err
		}
		return CachedFile{}, ErrIntegrity
	}
	if f.Sync() != nil || f.Close() != nil {
		return CachedFile{}, ErrStorage
	}
	return m.publish(ctx, id, hashes.sha256())
}
