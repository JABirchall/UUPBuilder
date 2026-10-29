package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

var ErrSystemDLL = errors.New("installed system DLL custody failed")

type DLLIdentity struct {
	Name, SHA256 string
	Size         int64
}

// SystemDLL retains the measured installed file, denies write/delete sharing,
// and binds the loaded module to that file. Close rehashes before unloading.
type SystemDLL struct {
	ctx      context.Context
	file     *os.File
	path     string
	initial  os.FileInfo
	identity DLLIdentity
	library  windows.Handle
}

func OpenSystemDLL(ctx context.Context, name string) (result *SystemDLL, runErr error) {
	if ctx == nil {
		return nil, ErrSystemDLL
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if !strings.HasSuffix(name, ".dll") || strings.ToLower(name) != name || len(name) > 128 {
		return nil, ErrSystemDLL
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return nil, ErrSystemDLL
		}
	}
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
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
	p := &SystemDLL{ctx: ctx, path: path, file: os.NewFile(uintptr(h), path)}
	ok := false
	defer func() {
		if !ok {
			if p.library != 0 {
				runErr = errors.Join(runErr, windows.FreeLibrary(p.library))
			}
			runErr = errors.Join(runErr, p.file.Close())
		}
	}()
	p.initial, err = p.file.Stat()
	if err != nil || !p.initial.Mode().IsRegular() {
		return nil, ErrSystemDLL
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
		return nil, ErrSystemDLL
	}
	loaded, err := os.Stat(windows.UTF16ToString(module[:n]))
	if err != nil || !os.SameFile(p.initial, loaded) {
		return nil, ErrSystemDLL
	}
	ok = true
	return p, nil
}
func (p *SystemDLL) Identity() DLLIdentity { return p.identity }
func (p *SystemDLL) Proc(name string) (uintptr, error) {
	if p.library == 0 || name == "" || strings.ContainsRune(name, 0) {
		return 0, ErrSystemDLL
	}
	return windows.GetProcAddress(p.library, name)
}
func (p *SystemDLL) Close() error {
	if p.library == 0 {
		return nil
	}
	id, e := p.measure()
	if e == nil && id != p.identity {
		e = ErrSystemDLL
	}
	e = errors.Join(e, windows.FreeLibrary(p.library), p.file.Close())
	p.library = 0
	return e
}
func (p *SystemDLL) measure() (DLLIdentity, error) {
	now, err := p.file.Stat()
	if err != nil || !os.SameFile(p.initial, now) || now.Size() != p.initial.Size() || !now.ModTime().Equal(p.initial.ModTime()) {
		return DLLIdentity{}, ErrSystemDLL
	}
	named, err := os.Stat(p.path)
	if err != nil || !os.SameFile(p.initial, named) {
		return DLLIdentity{}, ErrSystemDLL
	}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	r := io.NewSectionReader(p.file, 0, p.initial.Size())
	for {
		if err := p.ctx.Err(); err != nil {
			return DLLIdentity{}, err
		}
		n, e := r.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return DLLIdentity{}, e
		}
	}
	return DLLIdentity{Name: filepath.Base(p.path), SHA256: hex.EncodeToString(h.Sum(nil)), Size: p.initial.Size()}, nil
}
