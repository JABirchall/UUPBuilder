package windows

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
)

var ErrPreparationCustody = errors.New("fixed preparation custody refused")

type directoryChain struct {
	files []*os.File
	ids   []FileIdentity
}

// Every component is opened relative to the previous native handle without
// following a reparse point. Denying delete sharing retains ancestor names.
func pinDirectoryChain(path string) (*directoryChain, error) {
	if strings.HasPrefix(path, `\\?\`) && len(path) >= 7 && path[5] == ':' {
		path = path[4:]
	}
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if !filepath.IsAbs(path) || len(volume) != 2 || volume[1] != ':' {
		return nil, ErrPreparationCustody
	}
	u, e := windows.UTF16PtrFromString(volume + `\`)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(u, windows.FILE_GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	c := &directoryChain{files: []*os.File{os.NewFile(uintptr(h), volume+`\`)}}
	fail := func(e error) (*directoryChain, error) { return nil, errors.Join(e, c.close()) }
	parts := strings.Split(strings.TrimPrefix(path[len(volume):], `\`), `\`)
	for _, part := range parts {
		if part == "" {
			continue
		}
		if strings.ContainsAny(part, ":/\x00") || part == "." || part == ".." {
			return fail(ErrPreparationCustody)
		}
		f, e := nativeTreeOpenShared(windows.Handle(c.files[len(c.files)-1].Fd()), part, windows.FILE_GENERIC_READ, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil)
		if e != nil {
			return fail(e)
		}
		c.files = append(c.files, f)
		i, e := nativeInfo(f)
		if e != nil || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fail(errors.Join(e, ErrPreparationCustody))
		}
	}
	for _, f := range c.files {
		i, e := nativeInfo(f)
		if e != nil || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || i.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return fail(errors.Join(e, ErrPreparationCustody))
		}
		c.ids = append(c.ids, nativeIdentity(i))
	}
	return c, nil
}
func (c *directoryChain) check() error {
	if c == nil || len(c.files) == 0 || len(c.files) != len(c.ids) {
		return ErrPreparationCustody
	}
	for n, f := range c.files {
		i, e := nativeInfo(f)
		if e != nil || nativeIdentity(i) != c.ids[n] || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.Join(e, ErrPreparationCustody)
		}
	}
	return nil
}
func (c *directoryChain) close() error {
	var e error
	for n := len(c.files) - 1; n >= 0; n-- {
		e = errors.Join(e, c.files[n].Close())
	}
	c.files = nil
	return e
}

type PreparationParentIdentity struct {
	Workspace           WorkspaceIdentity
	Parent, Root, Owner FileIdentity
	VolumeID            string
}

// PinnedWorkspace borrows one freshly created workspace. It neither reopens a
// saved owner token nor grants deletion rights over any native descendants.
type PinnedWorkspace struct {
	workspace     *Workspace
	chain         *directoryChain
	owner         *os.File
	id            PreparationParentIdentity
	ownsWorkspace bool
}

func PinFreshWorkspace(w *Workspace) (*PinnedWorkspace, error) {
	if w == nil || w.fresh == nil || !w.fresh.ready || w.root == nil {
		return nil, ErrPreparationCustody
	}
	c, e := pinDirectoryChain(filepath.Join(w.fresh.selectedParent, filepath.Base(w.Path())))
	if e != nil {
		return nil, e
	}
	p := &PinnedWorkspace{workspace: w, chain: c}
	fail := func(e error) (*PinnedWorkspace, error) { return nil, errors.Join(e, p.Close()) }
	last := c.files[len(c.files)-1]
	p.owner, e = nativeTreeOpenShared(windows.Handle(last.Fd()), ownerFile, windows.FILE_GENERIC_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_SHARE_READ, nil)
	if e != nil {
		return fail(e)
	}
	i, e := nativeInfo(p.owner)
	if e != nil || nativeIdentity(i) != w.fresh.ownerID || i.NumberOfLinks != 1 || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || c.ids[len(c.ids)-1] != w.fresh.rootID || len(c.ids) < 2 || c.ids[len(c.ids)-2] != w.fresh.parentID {
		return fail(errors.Join(e, ErrPreparationCustody))
	}
	body, e := io.ReadAll(io.LimitReader(p.owner, 4097))
	var marker WorkspaceIdentity
	if e != nil || len(body) > 4096 || json.Unmarshal(body, &marker) != nil || marker != w.Identity() {
		return fail(errors.Join(e, ErrPreparationCustody))
	}
	v, e := InspectStorage(w.Path())
	if e != nil || !v.Capabilities.Local || !strings.EqualFold(v.Capabilities.Name, "NTFS") {
		return fail(errors.Join(e, ErrPreparationCustody))
	}
	p.id = PreparationParentIdentity{w.Identity(), w.fresh.parentID, w.fresh.rootID, w.fresh.ownerID, v.ID}
	if e = p.Check(w.Path()); e != nil {
		return fail(e)
	}
	return p, nil
}
func (p *PinnedWorkspace) Identity() PreparationParentIdentity { return p.id }
func (p *PinnedWorkspace) Check(temp string) error {
	if p == nil || p.owner == nil || p.workspace == nil || p.workspace.Identity() != p.id.Workspace {
		return ErrPreparationCustody
	}
	if e := p.chain.check(); e != nil {
		return e
	}
	i, e := nativeInfo(p.owner)
	if e != nil || nativeIdentity(i) != p.id.Owner || i.NumberOfLinks != 1 || i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(e, ErrPreparationCustody)
	}
	// Check the selected spelling too: a junction to the same physical object
	// is refused, not treated as a reviewed parent path.
	c, e := pinDirectoryChain(temp)
	if e != nil {
		return e
	}
	defer c.close()
	if c.ids[len(c.ids)-1] != p.id.Root {
		return ErrPreparationCustody
	}
	v, e := InspectStorage(temp)
	if e != nil || v.ID != p.id.VolumeID {
		return errors.Join(e, ErrPreparationCustody)
	}
	return nil
}
func (p *PinnedWorkspace) CreateEvidenceFile(name string) (*os.File, error) {
	if filepath.Base(name) != name || name == "." || strings.ContainsAny(name, ":/\\") {
		return nil, ErrPreparationCustody
	}
	if e := p.Check(p.id.Workspace.Path); e != nil {
		return nil, e
	}
	f, e := nativeTreeOpenShared(windows.Handle(p.chain.files[len(p.chain.files)-1].Fd()), name, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE, windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_SHARE_READ, nil)
	if e != nil {
		return nil, e
	}
	return f, nil
}
func (p *PinnedWorkspace) Close() error {
	if p == nil {
		return nil
	}
	var e error
	if p.owner != nil {
		e = p.owner.Close()
		p.owner = nil
	}
	if p.chain != nil {
		e = errors.Join(e, p.chain.close())
		p.chain = nil
	}
	if p.ownsWorkspace && p.workspace != nil {
		e = errors.Join(e, p.workspace.Close())
		p.workspace = nil
	}
	return e
}

func samePinnedPath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(strings.TrimPrefix(a, `\\?\`)), filepath.Clean(strings.TrimPrefix(b, `\\?\`)))
}

type ExecutableIdentity struct {
	Path, SHA256 string
	Size         int64
	File         FileIdentity
}
type PinnedExecutable struct {
	file  *os.File
	chain *directoryChain
	id    ExecutableIdentity
}

// OpenPinnedExecutable measures one local .exe while denying write/delete
// sharing. It does not launch, elevate, trust a signature, or grant consent.
func OpenPinnedExecutable(ctx context.Context, path string) (*PinnedExecutable, error) {
	if ctx == nil || !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return nil, ErrPreparationCustody
	}
	c, e := pinDirectoryChain(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	p := &PinnedExecutable{chain: c}
	fail := func(e error) (*PinnedExecutable, error) { return nil, errors.Join(e, p.Close()) }
	p.file, e = nativeTreeOpenShared(windows.Handle(c.files[len(c.files)-1].Fd()), filepath.Base(path), windows.FILE_GENERIC_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_SHARE_READ, nil)
	if e != nil {
		return fail(e)
	}
	i, e := nativeInfo(p.file)
	if e != nil || i.NumberOfLinks != 1 || i.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fail(errors.Join(e, ErrPreparationCustody))
	}
	s, e := p.file.Stat()
	if e != nil || s.Size() <= 0 || s.Size() > 128<<20 {
		return fail(errors.Join(e, ErrPreparationCustody))
	}
	actual, e := finalPath(windows.Handle(p.file.Fd()))
	if e != nil {
		return fail(e)
	}
	p.id = ExecutableIdentity{Path: actual, Size: s.Size(), File: nativeIdentity(i)}
	p.id.SHA256, e = p.hash(ctx)
	if e != nil {
		return fail(e)
	}
	return p, nil
}
func (p *PinnedExecutable) Identity() ExecutableIdentity { return p.id }
func (p *PinnedExecutable) hash(ctx context.Context) (string, error) {
	h := sha256.New()
	r := io.NewSectionReader(p.file, 0, p.id.Size)
	b := make([]byte, 64<<10)
	for {
		if e := ctx.Err(); e != nil {
			return "", e
		}
		n, e := r.Read(b)
		h.Write(b[:n])
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (p *PinnedExecutable) Verify(ctx context.Context) error {
	if p == nil || p.file == nil || ctx == nil {
		return ErrPreparationCustody
	}
	if e := p.chain.check(); e != nil {
		return e
	}
	i, e := nativeInfo(p.file)
	if e != nil || nativeIdentity(i) != p.id.File || i.NumberOfLinks != 1 {
		return errors.Join(e, ErrPreparationCustody)
	}
	s, e := p.file.Stat()
	if e != nil || s.Size() != p.id.Size {
		return errors.Join(e, ErrPreparationCustody)
	}
	h, e := p.hash(ctx)
	if e != nil || h != p.id.SHA256 {
		return errors.Join(e, ErrPreparationCustody)
	}
	return nil
}
func (p *PinnedExecutable) Close() error {
	if p == nil {
		return nil
	}
	var e error
	if p.file != nil {
		e = p.file.Close()
		p.file = nil
	}
	if p.chain != nil {
		e = errors.Join(e, p.chain.close())
		p.chain = nil
	}
	return e
}

// ProcessTokenIdentity describes only the currently queried process token.
// It grants no impersonation, privilege adjustment or launch authority.
type ProcessTokenIdentity struct {
	TokenID, AuthenticationID uint64
	UserSID                   string
	SessionID                 uint32
	Elevated                  bool
}

func CurrentProcessTokenIdentity() (ProcessTokenIdentity, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var out ProcessTokenIdentity
	if e := noImpersonation(); e != nil {
		return out, e
	}
	var t windows.Token
	if e := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t); e != nil {
		return out, e
	}
	defer t.Close()
	b, e := tokenData(t, windows.TokenStatistics)
	if e != nil || len(b) < 16 {
		return out, errors.Join(e, ErrPreparationCustody)
	}
	out.TokenID = binary.LittleEndian.Uint64(b)
	out.AuthenticationID = binary.LittleEndian.Uint64(b[8:])
	u, e := t.GetTokenUser()
	if e != nil {
		return out, e
	}
	out.UserSID = u.User.Sid.String()
	b, e = tokenData(t, windows.TokenSessionId)
	if e != nil || len(b) != 4 {
		return out, errors.Join(e, ErrPreparationCustody)
	}
	out.SessionID = binary.LittleEndian.Uint32(b)
	out.Elevated = t.IsElevated()
	return out, nil
}
func CheckProcessTokenIdentity(expected ProcessTokenIdentity) error {
	actual, e := CurrentProcessTokenIdentity()
	if e != nil {
		return e
	}
	if actual != expected || expected.TokenID == 0 {
		return ErrPreparationCustody
	}
	return nil
}
