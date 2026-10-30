package windows

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

type readPinPart struct {
	file      *os.File
	id        FileIdentity
	directory bool
}

// ReadPin borrows a live Workspace, exposing no path, handle or writer. Parents
// deny delete; leaf/owner deny write/delete. Close releases only read handles.
type ReadPin struct {
	mu        sync.Mutex
	workspace *Workspace
	parts     []readPinPart
	size      int64
	closed    bool
	closeErr  error
}

func (w *Workspace) OpenReadPin(name string) (*ReadPin, error) {
	if w == nil {
		return nil, os.ErrClosed
	}
	n, err := workspaceName(name)
	if err != nil || filepath.ToSlash(n) != name || len(strings.Split(name, "/")) > 64 {
		return nil, errors.New("canonical bounded workspace file required")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	// Existing root-custody primitive checks the reopened object against the
	// actual os.Root handle and denies delete sharing. No caller root is used.
	parent, _, err := w.lockDirectory(".")
	if err != nil {
		return nil, fmt.Errorf("read pin root: %w", err)
	}
	p := &ReadPin{workspace: w}
	fail := func(e error) (*ReadPin, error) { return nil, errors.Join(e, p.Close()) }
	add := func(f *os.File, directory bool) error {
		i, e := nativeInfo(f)
		if e != nil {
			return errors.Join(e, f.Close())
		}
		p.parts = append(p.parts, readPinPart{f, nativeIdentity(i), directory})
		if i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (i.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && i.NumberOfLinks != 1 {
			return errors.New("read pin refuses reparse/shared/nonregular objects")
		}
		return nil
	}
	if err = add(parent, true); err != nil {
		return fail(err)
	}
	owner, err := nativeTreeOpenShared(windows.Handle(parent.Fd()), ownerFile, windows.FILE_GENERIC_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_SHARE_READ, nil)
	if err != nil {
		return fail(fmt.Errorf("read pin owner open: %w", err))
	}
	if err = add(owner, false); err != nil {
		return fail(err)
	}
	b, err := io.ReadAll(io.LimitReader(owner, 4097))
	var id WorkspaceIdentity
	if err != nil || len(b) > 4096 || json.Unmarshal(b, &id) != nil || id != w.Identity() {
		return fail(errors.Join(err, errors.New("read pin workspace ownership changed")))
	}
	parts := strings.Split(name, "/")
	for j, part := range parts {
		dir := j < len(parts)-1
		options, share := uint32(windows.FILE_NON_DIRECTORY_FILE), uint32(windows.FILE_SHARE_READ)
		if dir {
			options = windows.FILE_DIRECTORY_FILE
			share |= windows.FILE_SHARE_WRITE
		}
		f, e := nativeTreeOpenShared(windows.Handle(parent.Fd()), part, windows.FILE_GENERIC_READ, windows.FILE_OPEN, options, share, nil)
		if e != nil {
			return fail(fmt.Errorf("read pin component open: %w", e))
		}
		if e = add(f, dir); e != nil {
			return fail(e)
		}
		parent = f
	}
	i, err := nativeInfo(parent)
	size := uint64(i.FileSizeHigh)<<32 | uint64(i.FileSizeLow)
	if err != nil || size > math.MaxInt64 {
		return fail(errors.Join(err, errors.New("read pin file size invalid")))
	}
	p.size = int64(size)
	return p, nil
}

func (p *ReadPin) Size() int64 { return p.size }
func (p *ReadPin) checkLocked() error {
	if p.closed || p.workspace == nil || len(p.parts) < 3 {
		return os.ErrClosed
	}
	root, e := p.workspace.root.Open(".")
	if e != nil {
		return e
	}
	i, e := nativeInfo(root)
	e = errors.Join(e, root.Close())
	if e != nil || nativeIdentity(i) != p.parts[0].id {
		return errors.Join(e, errors.New("read pin root identity changed"))
	}
	for j, part := range p.parts {
		i, e = nativeInfo(part.file)
		if e != nil {
			return e
		}
		if nativeIdentity(i) != part.id || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (i.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != part.directory || !part.directory && i.NumberOfLinks != 1 {
			return errors.New("read pin identity/topology changed")
		}
		if j == len(p.parts)-1 && uint64(i.FileSizeHigh)<<32|uint64(i.FileSizeLow) != uint64(p.size) {
			return errors.New("read pin size changed")
		}
	}
	return nil
}
func (p *ReadPin) Check() error {
	if p == nil {
		return os.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.workspace == nil {
		return os.ErrClosed
	}
	p.workspace.mu.Lock()
	defer p.workspace.mu.Unlock()
	return p.checkLocked()
}
func (p *ReadPin) ReadAt(b []byte, off int64) (int, error) {
	if p == nil {
		return 0, os.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.workspace == nil {
		return 0, os.ErrClosed
	}
	p.workspace.mu.Lock()
	defer p.workspace.mu.Unlock()
	if e := p.checkLocked(); e != nil {
		return 0, e
	}
	if len(b) > 64<<10 || off < 0 {
		return 0, errors.New("read pin requires nonnegative offset and at most64KiB")
	}
	n, e := p.parts[len(p.parts)-1].file.ReadAt(b, off)
	return n, errors.Join(e, p.checkLocked())
}
func (p *ReadPin) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		for j := len(p.parts) - 1; j >= 0; j-- {
			p.closeErr = errors.Join(p.closeErr, p.parts[j].file.Close())
		}
		p.parts = nil
	}
	return p.closeErr
}
