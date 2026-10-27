//go:build windows

package download

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"uupbuilder/internal/model"
)

type cacheRecord struct {
	Version  int                   `json:"version"`
	Identity model.PayloadIdentity `json:"identity"`
	SHA256   string                `json:"sha256"`
}

func (m *Manager) cached(ctx context.Context, id model.PayloadIdentity) (CachedFile, bool, error) {
	key := id.Key()
	var record cacheRecord
	err := readJSON(m.opts.Cache, key+".json", &record)
	if os.IsNotExist(err) {
		return CachedFile{}, false, nil
	}
	if err != nil || record.Version != 1 || record.Identity != id || (model.Digest{Algorithm: model.DigestSHA256, Value: record.SHA256}).Validate() != nil {
		return m.rejectCache(key)
	}
	f, err := m.opts.Cache.OpenFile(key+".data", os.O_RDONLY, 0)
	if err != nil {
		return m.rejectCache(key)
	}
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() != id.Size {
		f.Close()
		return m.rejectCache(key)
	}
	hashes := newDigests(id.Digest.Algorithm)
	n, err := stream(ctx, hashes, f, id.Size, nil)
	closeErr := f.Close()
	if ctx.Err() != nil {
		return CachedFile{}, false, ctx.Err()
	}
	if err != nil || closeErr != nil || n != id.Size || !hashes.matches(id) || hashes.sha256() != record.SHA256 {
		return m.rejectCache(key)
	}
	return CachedFile{Path: filepath.Join(m.opts.Cache.Path(), key+".data"), SHA256: record.SHA256, Identity: id}, true, nil
}

func (m *Manager) rejectCache(key string) (CachedFile, bool, error) {
	for _, name := range []string{key + ".json", key + ".data"} {
		if err := m.opts.Cache.Remove(name); err != nil && !os.IsNotExist(err) {
			return CachedFile{}, false, ErrStorage
		}
	}
	return CachedFile{}, false, nil
}

// publish copies across ownership roots, hashes the copy, syncs and closes it,
// then uses W1's handle-relative atomic rename. A completed record is written
// only after data verification/publication; interrupted staging is never reused
// as a cache hit. Readers always verify both hashes and exact size again.
func (m *Manager) publish(ctx context.Context, id model.PayloadIdentity, expectedSHA string) (CachedFile, error) {
	key := id.Key()
	src, err := m.opts.Job.OpenFile(key+".part", os.O_RDONLY, 0)
	if err != nil {
		return CachedFile{}, ErrStorage
	}
	dst, err := m.opts.Cache.OpenFile(key+".staging", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		src.Close()
		return CachedFile{}, ErrStorage
	}
	hashes := newDigests(id.Digest.Algorithm)
	n, copyErr := stream(ctx, io.MultiWriter(dst, hashes), src, id.Size, nil)
	srcErr := src.Close()
	var syncErr error
	if copyErr == nil {
		syncErr = dst.Sync()
	}
	closeErr := dst.Close()
	if ctx.Err() != nil {
		return CachedFile{}, ctx.Err()
	}
	if copyErr != nil {
		return CachedFile{}, copyErr
	}
	if srcErr != nil || syncErr != nil || closeErr != nil {
		return CachedFile{}, ErrStorage
	}
	if n != id.Size || !hashes.matches(id) || hashes.sha256() != expectedSHA {
		m.opts.Cache.Remove(key + ".staging")
		return CachedFile{}, ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return CachedFile{}, err
	}
	if m.opts.Cache.Replace(key+".staging", key+".data", true) != nil {
		return CachedFile{}, ErrStorage
	}
	if err := writeJSON(m.opts.Cache, key+".json", cacheRecord{Version: 1, Identity: id, SHA256: expectedSHA}); err != nil {
		return CachedFile{}, err
	}
	for _, name := range []string{key + ".part", key + ".resume.json"} {
		if err := m.opts.Job.Remove(name); err != nil && !os.IsNotExist(err) {
			return CachedFile{}, ErrStorage
		}
	}
	return CachedFile{Path: filepath.Join(m.opts.Cache.Path(), key+".data"), SHA256: expectedSHA, Identity: id}, nil
}
