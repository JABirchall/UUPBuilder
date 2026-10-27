//go:build windows

package tools

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"uupbuilder/internal/model"
)

const (
	maxArchiveBytes   int64  = 512 << 20
	maxExpandedBytes  uint64 = 2 << 30
	maxArchiveEntries        = 4096
)

// materializeZIP is a private byte-materialization backend, currently
// unreachable from Ensure. Tests use synthetic data only. It cannot approve a
// provider, execute a probe, install an ADK/driver, or establish prerequisites.
func (m *Manager) materializeZIP(ctx context.Context, p provider, emit model.Emit) (result []VerifiedFile, resultErr error) {
	ctx, done, err := m.start(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	select {
	case m.gate <- struct{}{}:
		defer func() { <-m.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := validateProvider(p); err != nil {
		return nil, ErrIntegrity
	}
	if p.Route != "vendor-zip" || len(p.Packages) != 1 {
		return nil, ErrArchive
	}
	if err := requireCompletePins(p); err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(p)
	dir := "providers/" + p.ID + "/" + p.Version + "/" + m.manifest.digest + "/" + string(p.NativeArchitecture)
	marker, _ := json.Marshal(struct {
		Manifest string `json:"manifest_digest"`
		Provider string `json:"provider_digest"`
	}{m.manifest.digest, digestBytes(encoded)})
	f, err := m.workspace.OpenFile(dir+"/"+completionMarker, os.O_RDONLY, 0)
	if err == nil {
		b, readErr := io.ReadAll(io.LimitReader(f, int64(len(marker)+1)))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || string(b) != string(marker) {
			return nil, ErrIntegrity
		}
		return m.verifyPublished(ctx, dir, p)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrStorage
	}
	if err := m.checkDirectory(dir, p, false); err != nil {
		return nil, err
	}
	pin := p.Packages[0]
	if pin.Size > maxArchiveBytes {
		return nil, ErrArchive
	}
	payload, err := model.NewPayload(model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: pin.SHA256}, Size: pin.Size, Provenance: model.PackageProvenance{Source: pin.URL, Name: pin.Name}}, "tools/"+pin.Name)
	if err != nil {
		return nil, ErrIntegrity
	}
	cached, err := m.fetcher.FetchOne(ctx, payload, model.Locator{URL: pin.URL}, emit)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, ErrAcquisition
	}
	if cached.Identity != payload.Identity || cached.SHA256 != pin.SHA256 || !filepath.IsAbs(cached.Path) {
		return nil, ErrIntegrity
	}
	archive, err := os.Open(cached.Path)
	if err != nil {
		return nil, ErrStorage
	}
	defer archive.Close()
	stat, err := archive.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() != pin.Size {
		return nil, ErrIntegrity
	}
	if err := copyVerified(ctx, io.Discard, archive, pin.Size, pin.SHA256); err != nil {
		return nil, err
	}
	z, err := zip.NewReader(archive, pin.Size)
	if err != nil {
		return nil, ErrArchive
	}
	entries, err := inspectZIP(z)
	if err != nil {
		return nil, err
	}
	for _, file := range p.Files {
		entry := entries[file.Path]
		if entry == nil || entry.FileInfo().IsDir() || entry.UncompressedSize64 != uint64(file.Size) {
			return nil, ErrIntegrity
		}
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, ErrStorage
	}
	stage := "staging/" + hex.EncodeToString(token[:])
	if err := m.workspace.MkdirAll(stage); err != nil {
		return nil, ErrStorage
	}
	defer func() {
		if err := m.removeStage(stage, p); err != nil {
			result = nil
			resultErr = errors.Join(resultErr, err)
		}
	}()
	// Verify the entire declared set before publishing any file in the provider
	// directory. Unknown archive entries are validated but never materialized.
	for _, file := range p.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parent := filepath.ToSlash(filepath.Dir(file.Path))
		if parent == "." {
			parent = ""
		}
		if err := m.workspace.MkdirAll(strings.TrimSuffix(stage+"/"+parent, "/")); err != nil {
			return nil, ErrStorage
		}
		dst, err := m.workspace.OpenFile(stage+"/"+file.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, ErrStorage
		}
		src, openErr := entries[file.Path].Open()
		if openErr != nil {
			dst.Close()
			return nil, ErrIntegrity
		}
		copyErr := copyVerified(ctx, dst, src, file.Size, file.SHA256)
		srcErr := src.Close()
		syncErr := dst.Sync()
		closeErr := dst.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if srcErr != nil {
			return nil, ErrIntegrity
		}
		if syncErr != nil || closeErr != nil {
			return nil, ErrStorage
		}
	}
	for _, file := range p.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parent := filepath.ToSlash(filepath.Dir(file.Path))
		if parent == "." {
			parent = ""
		}
		if err := m.workspace.MkdirAll(strings.TrimSuffix(dir+"/"+parent, "/")); err != nil {
			return nil, ErrStorage
		}
		if err := m.workspace.Replace(stage+"/"+file.Path, dir+"/"+file.Path, true); err != nil {
			return nil, ErrStorage
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mark, err := m.workspace.OpenFile(stage+"/"+completionMarker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	_, writeErr := mark.Write(marker)
	syncErr := mark.Sync()
	closeErr := mark.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return nil, ErrStorage
	}
	if err := m.workspace.Replace(stage+"/"+completionMarker, dir+"/"+completionMarker, false); err != nil {
		return nil, ErrStorage
	}
	return m.verifyPublished(ctx, dir, p)
}

func requireCompletePins(p provider) error {
	files := map[string]filePin{}
	for _, f := range p.Files {
		if strings.EqualFold(f.Path, completionMarker) || f.Size > maxArchiveBytes {
			return ErrIntegrity
		}
		files[f.Path] = f
	}
	for _, f := range p.Files {
		for _, dep := range f.Dependencies {
			if _, ok := files[dep]; !ok {
				return ErrIntegrity
			}
		}
	}
	for _, n := range p.Notices {
		pin, ok := files[n]
		if !ok || pin.Role != "notice" {
			return ErrIntegrity
		}
	}
	return nil
}

func inspectZIP(z *zip.Reader) (map[string]*zip.File, error) {
	if len(z.File) > maxArchiveEntries {
		return nil, ErrArchive
	}
	seen := map[string]bool{}
	files := map[string]*zip.File{}
	kinds := map[string]bool{}
	var total uint64
	for _, f := range z.File {
		dir := f.FileInfo().IsDir()
		name := f.Name
		if dir {
			name = strings.TrimSuffix(name, "/")
		}
		key := strings.ToLower(name)
		if !pathValid(name) || seen[key] || (f.Mode().Type() != 0 && f.Mode().Type() != os.ModeDir) || f.Flags&1 != 0 {
			return nil, ErrArchive
		}
		seen[key] = true
		kinds[key] = dir
		files[name] = f
		if f.UncompressedSize64 > uint64(maxArchiveBytes) || f.UncompressedSize64 > maxExpandedBytes-total {
			return nil, ErrArchive
		}
		total += f.UncompressedSize64
	}
	for name := range kinds {
		for parent := name; strings.Contains(parent, "/"); {
			parent = parent[:strings.LastIndexByte(parent, '/')]
			if isDir, exists := kinds[parent]; exists && !isDir {
				return nil, ErrArchive
			}
		}
	}
	return files, nil
}

// Remove only exact private staging entries, then empty directories. There is
// no recursive deletion and no removal of cache, installed tools or other jobs.
func (m *Manager) removeStage(stage string, p provider) error {
	dirs := map[string]bool{stage: true}
	var result error
	remove := func(path string) {
		if err := m.workspace.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = ErrStorage
		}
	}
	remove(stage + "/" + completionMarker)
	for _, file := range p.Files {
		remove(stage + "/" + file.Path)
		for parent := filepath.ToSlash(filepath.Dir(file.Path)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			dirs[stage+"/"+parent] = true
		}
	}
	ordered := make([]string, 0, len(dirs))
	for dir := range dirs {
		ordered = append(ordered, dir)
	}
	slices.SortFunc(ordered, func(a, b string) int { return len(b) - len(a) })
	for _, dir := range ordered {
		remove(dir)
	}
	return result
}
