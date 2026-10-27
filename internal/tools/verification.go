//go:build windows

package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const completionMarker = ".uupbuilder-verified.json"

// copyVerified bounds reads (including a one-byte overflow check), observes
// cancellation while hashing, and never interprets or executes file contents.
func copyVerified(ctx context.Context, dst io.Writer, src io.Reader, size int64, expected string) error {
	if size < 0 || !validSHA(expected) {
		return ErrIntegrity
	}
	h := sha256.New()
	r := io.LimitReader(src, size+1)
	writer := io.MultiWriter(dst, h)
	var n int64
	buf := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		read, err := r.Read(buf)
		if read > 0 {
			written, writeErr := writer.Write(buf[:read])
			n += int64(written)
			if writeErr != nil {
				return ErrStorage
			}
			if written != read {
				return ErrStorage
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrIntegrity
		}
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != expected {
		return ErrIntegrity
	}
	return ctx.Err()
}

func (m *Manager) verifyPublished(ctx context.Context, dir string, p provider) ([]VerifiedFile, error) {
	if err := m.checkDirectory(dir, p, true); err != nil {
		return nil, err
	}
	result := make([]VerifiedFile, 0, len(p.Files))
	for _, pin := range p.Files {
		f, err := m.workspace.OpenFile(dir+"/"+pin.Path, os.O_RDONLY, 0)
		if err != nil {
			return nil, ErrIntegrity
		}
		stat, statErr := f.Stat()
		if statErr != nil || !stat.Mode().IsRegular() || stat.Size() != pin.Size {
			f.Close()
			return nil, ErrIntegrity
		}
		err = copyVerified(ctx, io.Discard, f, pin.Size, pin.SHA256)
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, ErrStorage
		}
		result = append(result, VerifiedFile{ProviderID: p.ID, LogicalPath: pin.Path, Path: filepath.Join(m.workspace.Path(), filepath.FromSlash(dir), filepath.FromSlash(pin.Path)), SHA256: pin.SHA256, Version: pin.Version, Role: pin.Role, NativeArchitecture: pin.NativeArchitecture})
	}
	return result, nil
}

// checkDirectory rejects unpinned side-loaded files. Workspace.OpenFile keeps
// every directory walk below the W1 root, including reparse/rename races.
func (m *Manager) checkDirectory(dir string, p provider, complete bool) error {
	expected := map[string]bool{completionMarker: false}
	for _, pin := range p.Files {
		expected[strings.ToLower(pin.Path)] = false
		for parent := filepath.ToSlash(filepath.Dir(pin.Path)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			expected[strings.ToLower(parent)] = true
		}
	}
	var walk func(string) error
	walk = func(relative string) error {
		name := dir
		if relative != "" {
			name += "/" + relative
		}
		f, err := m.workspace.OpenFile(name, os.O_RDONLY, 0)
		if errors.Is(err, os.ErrNotExist) && relative == "" && !complete {
			return nil
		}
		if err != nil {
			return ErrIntegrity
		}
		entries, readErr := f.ReadDir(-1)
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return ErrStorage
		}
		for _, e := range entries {
			child := e.Name()
			if relative != "" {
				child = relative + "/" + child
			}
			isDir, ok := expected[strings.ToLower(child)]
			if !ok || e.Type()&os.ModeSymlink != 0 || e.IsDir() != isDir || (!e.IsDir() && !e.Type().IsRegular()) {
				return ErrIntegrity
			}
			if isDir {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk("")
}
