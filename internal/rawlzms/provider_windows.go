//go:build windows

package rawlzms

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	platform "uupbuilder/internal/platform/windows"
)

// The historical RAW LZMS contract retains its unchanged 1 MiB caller bound.
type Provider struct {
	dll                           *platform.SystemDLL
	identity                      Identity
	create, decompress, closeProc uintptr
}

func SystemPath() (string, error) {
	d, e := windows.GetSystemDirectory()
	if e != nil {
		return "", e
	}
	return filepath.Join(d, "cabinet.dll"), nil
}
func Open(ctx context.Context, path string) (*Provider, error) {
	if ctx == nil {
		return nil, ErrProvider
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	expected, e := SystemPath()
	if e != nil {
		return nil, e
	}
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Clean(path), expected) {
		return nil, ErrProvider
	}
	dll, e := platform.OpenSystemDLL(ctx, "cabinet.dll")
	if e != nil {
		if errors.Is(e, platform.ErrSystemDLL) {
			return nil, errors.Join(ErrProvider, e)
		}
		return nil, e
	}
	id := dll.Identity()
	p := &Provider{dll: dll, identity: Identity{Name: id.Name, SHA256: id.SHA256, Size: id.Size}}
	for n, ptr := range map[string]*uintptr{"CreateDecompressor": &p.create, "Decompress": &p.decompress, "CloseDecompressor": &p.closeProc} {
		*ptr, e = dll.Proc(n)
		if e != nil {
			return nil, errors.Join(e, dll.Close())
		}
	}
	return p, nil
}
func (p *Provider) Identity() Identity { return p.identity }
func (p *Provider) Close() error {
	if p.dll == nil {
		return nil
	}
	e := p.dll.Close()
	p.dll = nil
	if errors.Is(e, platform.ErrSystemDLL) {
		return errors.Join(ErrProvider, e)
	}
	return e
}
func (p *Provider) Decode(ctx context.Context, b []byte, size int) (out []byte, runErr error) {
	if err := bounds(ctx, b, size); err != nil {
		return nil, err
	}
	if p.dll == nil {
		return nil, os.ErrClosed
	}
	out = make([]byte, size)
	if err := p.decodeInto(ctx, b, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Only the two separately bounded public contracts may reach this primitive.
func (p *Provider) decodeInto(ctx context.Context, b, out []byte) (runErr error) {
	if p.dll == nil {
		return os.ErrClosed
	}
	var handle uintptr
	ok, _, err := syscall.SyscallN(p.create, 5|0x20000000, 0, uintptr(unsafe.Pointer(&handle)))
	if ok == 0 {
		return compressionError("CreateDecompressor", err)
	}
	defer func() {
		ok, _, err := syscall.SyscallN(p.closeProc, handle)
		if ok == 0 {
			runErr = errors.Join(runErr, compressionError("CloseDecompressor", err))
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	var actual uintptr
	ok, _, err = syscall.SyscallN(p.decompress, handle, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&actual)))
	runtime.KeepAlive(b)
	runtime.KeepAlive(out)
	if ok == 0 {
		return compressionError("Decompress", err)
	}
	if actual != uintptr(len(out)) {
		return errors.New("native LZMS decompressed size mismatch")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func compressionError(api string, err syscall.Errno) error {
	if err == 0 {
		return fmt.Errorf("%s returned FALSE without error code", api)
	}
	return fmt.Errorf("%s: %w", api, err)
}
