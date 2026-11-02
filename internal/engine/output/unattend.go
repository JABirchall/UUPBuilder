package output

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// stageUnattend copies user-supplied bytes into the private media tree before
// its contents are bound for mastering and subsequent ISO verification.
func stageUnattend(ctx context.Context, root, source string) (err error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("autounattend: inspect media root: %w", err)
	}
	for _, entry := range entries {
		if strings.EqualFold(entry.Name(), "autounattend.xml") {
			return errors.New("autounattend: media already contains autounattend.xml")
		}
	}
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("autounattend: open source: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 0xffffffff {
		return errors.New("autounattend: source must be a nonempty regular file no larger than 4 GiB minus one byte")
	}
	in, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("autounattend: open source: %w", err)
	}
	defer in.Close()
	path := filepath.Join(root, "autounattend.xml")
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("autounattend: create media file: %w", err)
	}
	defer func() {
		closeErr := out.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	n, err := io.Copy(out, &unattendReader{ctx: ctx, r: io.LimitReader(in, info.Size()+1)})
	if err != nil {
		return fmt.Errorf("autounattend: copy: %w", err)
	}
	if n != info.Size() {
		return errors.New("autounattend: source size changed during copy")
	}
	return out.Sync()
}

type unattendReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *unattendReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
