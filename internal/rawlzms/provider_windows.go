//go:build windows

package rawlzms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// compressapi.h: COMPRESS_ALGORITHM_LZMS=5, COMPRESS_RAW=(1<<29).
// BOOL uses the zero/nonzero return; handles and SIZE_T are pointer-sized.
// AllocationRoutines=NULL uses OS-managed codec memory, whose internal peak is
// not specified by the API. Only the caller buffers have a 1 MiB hard bound.
type Provider struct {
	ctx                           context.Context
	file                          *os.File
	path                          string
	initial                       os.FileInfo
	identity                      Identity
	library                       windows.Handle
	create, decompress, closeProc uintptr
}

func SystemPath() (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "cabinet.dll"), nil
}
func Open(ctx context.Context, path string) (*Provider, error) {
	if ctx == nil {
		return nil, ErrProvider
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expected, err := SystemPath()
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Clean(path), expected) {
		return nil, ErrProvider
	}
	u, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Borrow only the installed OS file, denying write/delete sharing while the
	// measured provider is loaded. No source directory enters DLL search paths.
	h, err := windows.CreateFile(u, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	p := &Provider{ctx: ctx, path: path, file: os.NewFile(uintptr(h), path)}
	ok := false
	defer func() {
		if !ok {
			if p.library != 0 {
				windows.FreeLibrary(p.library)
			}
			p.file.Close()
		}
	}()
	p.initial, err = p.file.Stat()
	if err != nil || !p.initial.Mode().IsRegular() {
		return nil, ErrProvider
	}
	p.identity, err = p.measure()
	if err != nil {
		return nil, err
	}
	p.library, err = windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, err
	}
	var module [32768]uint16
	n, err := windows.GetModuleFileName(p.library, &module[0], uint32(len(module)))
	if err != nil || n == 0 || int(n) >= len(module) {
		return nil, ErrProvider
	}
	loaded, err := os.Stat(windows.UTF16ToString(module[:n]))
	if err != nil || !os.SameFile(p.initial, loaded) {
		return nil, ErrProvider
	}
	p.create, err = windows.GetProcAddress(p.library, "CreateDecompressor")
	if err != nil {
		return nil, err
	}
	p.decompress, err = windows.GetProcAddress(p.library, "Decompress")
	if err != nil {
		return nil, err
	}
	p.closeProc, err = windows.GetProcAddress(p.library, "CloseDecompressor")
	if err != nil {
		return nil, err
	}
	ok = true
	return p, nil
}
func (p *Provider) measure() (Identity, error) {
	now, err := p.file.Stat()
	if err != nil || !os.SameFile(p.initial, now) || now.Size() != p.initial.Size() || !now.ModTime().Equal(p.initial.ModTime()) {
		return Identity{}, ErrProvider
	}
	named, err := os.Stat(p.path)
	if err != nil || !os.SameFile(p.initial, named) {
		return Identity{}, ErrProvider
	}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	r := io.NewSectionReader(p.file, 0, p.initial.Size())
	for {
		if err := p.ctx.Err(); err != nil {
			return Identity{}, err
		}
		n, e := r.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return Identity{}, e
		}
	}
	return Identity{Name: "cabinet.dll", SHA256: hex.EncodeToString(h.Sum(nil)), Size: p.initial.Size()}, nil
}
func (p *Provider) Identity() Identity { return p.identity }
func (p *Provider) Decode(ctx context.Context, b []byte, size int) (out []byte, runErr error) {
	if err := bounds(ctx, b, size); err != nil {
		return nil, err
	}
	if p.library == 0 {
		return nil, os.ErrClosed
	}
	var handle uintptr
	ok, _, err := syscall.SyscallN(p.create, 5|0x20000000, 0, uintptr(unsafe.Pointer(&handle)))
	if ok == 0 {
		return nil, compressionError("CreateDecompressor", err)
	}
	defer func() {
		ok, _, err := syscall.SyscallN(p.closeProc, handle)
		if ok == 0 {
			runErr = errors.Join(runErr, compressionError("CloseDecompressor", err))
		}
		if runErr != nil {
			out = nil
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out = make([]byte, size)
	var actual uintptr
	ok, _, err = syscall.SyscallN(p.decompress, handle, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&actual)))
	runtime.KeepAlive(b)
	runtime.KeepAlive(out)
	if ok == 0 {
		return nil, compressionError("Decompress", err)
	}
	if actual != uintptr(size) {
		return nil, errors.New("native LZMS decompressed size mismatch")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
func (p *Provider) Close() error {
	if p.library == 0 {
		return nil
	}
	identity, err := p.measure()
	if err == nil && identity != p.identity {
		err = ErrProvider
	}
	err = errors.Join(err, windows.FreeLibrary(p.library), p.file.Close())
	p.library = 0
	return err
}
func compressionError(api string, err syscall.Errno) error {
	if err == 0 {
		return fmt.Errorf("%s returned FALSE without error code", api)
	}
	return fmt.Errorf("%s: %w", api, err)
}
