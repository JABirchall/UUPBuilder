package windows

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"uupbuilder/internal/model"
)

var ErrTreePreserved = errors.New("owned tree preserved: custody or topology unproved")
var ErrTreeLimit = errors.New("owned tree bound exceeded")

type TreeLimits struct {
	MaxEntries, MaxDepth         int
	MaxLogicalBytes              uint64
	MaxReadBytes, MaxResultBytes uint64
}
type TreeIdentity struct {
	Workspace                               WorkspaceIdentity
	RelativePath, OperationID, SourceDigest string
	Root                                    FileIdentity
}
type treeEntry struct {
	file        *os.File
	id          FileIdentity
	directory   bool
	size        uint64
	streams     map[string]uint64
	streamFiles []*os.File
	alias       bool
}

// OwnedTree is an active, non-reopenable scope. A transaction must journal its
// intent before creation. This lower-level scope alone grants no graph authority
// and never adopts a directory or image-produced descendants.
type OwnedTree struct {
	mu              sync.Mutex
	w               *Workspace
	identity        TreeIdentity
	ownerID         FileIdentity
	root            *os.File
	parents         []*os.File
	entries         map[string]*treeEntry
	limits          TreeLimits
	logical         uint64
	resultBytes     uint64
	closed, removed bool
	closeErr        error
	// Private native-call port for deterministic identity races; nil always
	// uses the fixed handle-relative deletion open in production.
	reopenRemoval func(windows.Handle, string, bool) (*os.File, error)
}

func treeBounds(l TreeLimits) (TreeLimits, error) {
	if l.MaxEntries < 0 || l.MaxEntries > 4096 || l.MaxDepth < 0 || l.MaxDepth > 32 || l.MaxLogicalBytes > 64<<20 || l.MaxReadBytes > 16<<20 || l.MaxResultBytes > 4<<20 {
		return l, ErrTreeLimit
	}
	if l.MaxEntries == 0 {
		l.MaxEntries = 4096
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = 32
	}
	if l.MaxLogicalBytes == 0 {
		l.MaxLogicalBytes = 64 << 20
	}
	if l.MaxReadBytes == 0 {
		l.MaxReadBytes = 16 << 20
	}
	if l.MaxResultBytes == 0 {
		l.MaxResultBytes = 4 << 20
	}
	if l.MaxReadBytes < 80<<10 || l.MaxResultBytes < 128<<10 {
		return l, ErrTreeLimit
	}
	return l, nil
}

// CreateOwnedTree creates one fresh child under an already owned parent. Its
// caller must retain a nonnil returned scope even when an error accompanies it.
func (w *Workspace) CreateOwnedTree(relative, operation, source string, l TreeLimits) (*OwnedTree, error) {
	l, e := treeBounds(l)
	if e != nil {
		return nil, e
	}
	if w == nil || w.root == nil || !validID(operation) || !validID(source) {
		return nil, ErrTreePreserved
	}
	owner, e := treeWorkspaceOwner(w)
	if e != nil {
		return nil, e
	}
	n, e := workspaceName(relative)
	if e != nil {
		return nil, e
	}
	parent, parents, e := treeParent(w, filepath.ToSlash(filepath.Dir(n)))
	if e != nil {
		return nil, e
	}
	retained := false
	defer func() {
		if !retained {
			for _, p := range parents {
				p.Close()
			}
		}
	}()
	i, e := nativeInfo(parent)
	if e != nil || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.Join(e, ErrTreePreserved)
	}
	self, e := CurrentPeerIdentity()
	if e != nil {
		return nil, e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + self.UserSID + ")(A;OICI;FA;;;SY)")
	if e != nil {
		return nil, e
	}
	f, e := nativeTreeOpen(windows.Handle(parent.Fd()), filepath.Base(n), windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE, sd)
	if e != nil {
		return nil, e
	}
	t := &OwnedTree{w: w, root: f, parents: parents, ownerID: owner, resultBytes: 4096, entries: map[string]*treeEntry{}, limits: l, identity: TreeIdentity{Workspace: w.Identity(), RelativePath: filepath.ToSlash(n), OperationID: operation, SourceDigest: source}}
	retained = true
	i, e = nativeInfo(f)
	if e != nil {
		return t, errors.Join(ErrTreePreserved, e)
	}
	t.identity.Root = nativeIdentity(i)
	if e = t.validate(); e != nil {
		return t, e
	}
	return t, nil
}

func (t *OwnedTree) Identity() TreeIdentity {
	if t == nil {
		return TreeIdentity{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.identity
}

func (t *OwnedTree) validate() error {
	if t == nil || t.closed || t.root == nil || t.removed {
		return errors.Join(ErrTreePreserved, os.ErrClosed)
	}
	owner, e := treeWorkspaceOwner(t.w)
	if e != nil || owner != t.ownerID {
		return errors.Join(ErrTreePreserved, e)
	}
	for _, p := range t.parents {
		i, e := nativeInfo(p)
		if e != nil || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.Join(ErrTreePreserved, e)
		}
	}
	parent := t.parents[len(t.parents)-1]
	f, e := nativeTreeOpen(windows.Handle(parent.Fd()), filepath.Base(t.identity.RelativePath), windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
	if e != nil {
		return errors.Join(ErrTreePreserved, e)
	}
	i, e := nativeInfo(f)
	e = errors.Join(e, f.Close())
	if e != nil || nativeIdentity(i) != t.identity.Root || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(ErrTreePreserved, e)
	}
	return nil
}

func (t *OwnedTree) entry(name string) (*treeEntry, error) {
	if name == "." {
		return &treeEntry{file: t.root, id: t.identity.Root, directory: true}, nil
	}
	n, e := treeName(name, t.limits.MaxDepth)
	if e != nil {
		return nil, e
	}
	v := t.entries[strings.ToLower(n)]
	if v == nil {
		return nil, ErrTreePreserved
	}
	return v, nil
}

func treeName(name string, depth int) (string, error) {
	if len(name) > 4096 {
		return "", ErrTreeLimit
	}
	n, e := model.ValidateRelativePath(name)
	if e != nil {
		return "", e
	}
	if strings.Count(n, "/")+1 > depth {
		return "", ErrTreeLimit
	}
	return n, nil
}

func (t *OwnedTree) parent(name string) (*os.File, string, error) {
	p := filepath.ToSlash(filepath.Dir(name))
	v, e := t.entry(p)
	if e != nil || !v.directory {
		return nil, "", ErrTreePreserved
	}
	i, e := nativeInfo(v.file)
	if e != nil || nativeIdentity(i) != v.id || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, "", errors.Join(ErrTreePreserved, e)
	}
	return v.file, filepath.Base(name), nil
}

func (t *OwnedTree) CreateFile(ctx context.Context, name string, data []byte) error {
	if t == nil {
		return ErrTreePreserved
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.create(ctx, name, data, false)
}

func (t *OwnedTree) CreateDirectory(ctx context.Context, name string) error {
	if t == nil {
		return ErrTreePreserved
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.create(ctx, name, nil, true)
}

// Close releases handles only. It never implies deletion or clean cancellation.
func (t *OwnedTree) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		for _, v := range t.entries {
			for _, f := range v.streamFiles {
				t.closeErr = errors.Join(t.closeErr, f.Close())
			}
			t.closeErr = errors.Join(t.closeErr, v.file.Close())
		}
		t.closeErr = errors.Join(t.closeErr, t.root.Close())
		for _, p := range t.parents {
			t.closeErr = errors.Join(t.closeErr, p.Close())
		}
		if !t.removed {
			t.closeErr = errors.Join(t.closeErr, fmt.Errorf("%w: %s [volume=%d file=%d]", ErrTreePreserved, t.identity.RelativePath, t.identity.Root.VolumeSerial, t.identity.Root.FileIndex))
		}
	}
	return t.closeErr
}
