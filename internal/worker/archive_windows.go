package worker

import (
	"archive/tar"
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

type ArchiveEntry struct {
	Path, SHA256 string
	Size         int64
}

// Checkpoint archives contain only regular files. The manifest is committed in
// the same transaction; extraction accepts exactly its names, sizes and hashes.
func extractCheckpointArchive(ctx context.Context, src io.Reader, directory string, entries []ArchiveEntry) error {
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	expected := map[string]ArchiveEntry{}
	folded := map[string]bool{}
	for _, entry := range entries {
		name, err := model.ValidateRelativePath(entry.Path)
		if err != nil || name != entry.Path || folded[strings.ToLower(name)] || entry.Size < 0 || (model.Digest{Algorithm: model.DigestSHA256, Value: entry.SHA256}).Validate() != nil {
			return fmt.Errorf("invalid checkpoint archive manifest")
		}
		expected[name] = entry
		folded[strings.ToLower(name)] = true
	}
	tr := tar.NewReader(src)
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		entry, ok := expected[h.Name]
		if !ok || seen[h.Name] || h.Typeflag != tar.TypeReg || h.Size != entry.Size {
			return fmt.Errorf("unexpected checkpoint archive member")
		}
		seen[h.Name] = true
		path := filepath.Join(directory, filepath.FromSlash(h.Name))
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		err = errors.Join(copyCheckpoint(ctx, f, tr, entry.Size, entry.SHA256), f.Sync(), f.Close())
		if err != nil {
			return err
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("checkpoint archive is missing files")
	}
	return ctx.Err()
}
func copyCheckpoint(ctx context.Context, dst io.Writer, src io.Reader, size int64, sha string) error {
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), preparationReader{ctx, io.LimitReader(src, size+1)})
	if err != nil {
		return err
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != sha {
		return fmt.Errorf("checkpoint content identity mismatch")
	}
	return ctx.Err()
}
func archiveDirectory(ctx context.Context, dst io.Writer, directory string) ([]ArchiveEntry, error) {
	tw := tar.NewWriter(dst)
	var entries []ArchiveEntry
	err := filepath.WalkDir(directory, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if de.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("archive source link rejected")
		}
		if de.IsDir() {
			return nil
		}
		info, err := de.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("archive source is not a file")
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		name = filepath.ToSlash(name)
		if _, err = model.ValidateRelativePath(name); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if err = tw.WriteHeader(&tar.Header{Name: name, Size: info.Size(), Mode: 0600, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(tw, h), preparationReader{ctx, f})
		if err != nil {
			return err
		}
		if n != info.Size() {
			return fmt.Errorf("archive source changed")
		}
		entries = append(entries, ArchiveEntry{Path: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
		return nil
	})
	return entries, errors.Join(err, tw.Close())
}
