package windows

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
)

const ownerFile = ".uupbuilder-owner.json"

// Workspace holds a directory handle. All file operations resolve relative to
// that handle through os.Root, which prevents escape even under rename/reparse
// races; a prior lexical check or a checked absolute path is insufficient.
type Workspace struct {
	root      *os.Root
	identity  WorkspaceIdentity
	mu        sync.Mutex
	mounts    map[string]mountClaim
	fresh     *workspaceRemoval
	closeOnce sync.Once
	closeErr  error
}
type mountClaim struct {
	descriptor OwnedMount
	info       os.FileInfo
}

func randomToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func validID(s string) bool {
	return strings.TrimSpace(s) == s && s != "" && len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n")
}

// CreateWorkspace creates a fresh private child beneath a selected local NTFS
// parent. It never adopts or deletes an existing directory. A nonnil result on
// initialization failure retains the fresh scope identity; callers must retain
// its reported custody. All acquired handles are closed and errors are joined.
func CreateWorkspace(parent, jobID string) (w *Workspace, err error) {
	if !filepath.IsAbs(parent) || !validID(jobID) {
		return nil, errors.New("absolute parent and job identity required")
	}
	cap, err := InspectFileSystem(parent)
	if err != nil {
		return nil, err
	}
	if !cap.Local || !strings.EqualFold(cap.Name, "NTFS") {
		return nil, errors.New("workspace requires local NTFS")
	}
	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, parentRoot.Close())
		if err != nil && w != nil && w.fresh.ready {
			err = errors.Join(err, w.Close())
			err = fmt.Errorf("workspace preserved at %s [job=%s volume=%d file=%d]: %w", w.Path(), jobID, w.fresh.rootID.VolumeSerial, w.fresh.rootID.FileIndex, err)
		}
	}()
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	parentHandle, err := parentRoot.Open(".")
	if err != nil {
		return nil, err
	}
	return createWorkspace(parentRoot, parentHandle, parent, jobID, token)
}

// createWorkspace takes ownership of parentHandle even on initialization failure.
func createWorkspace(parentRoot *os.Root, parentHandle *os.File, parent, jobID, token string) (w *Workspace, err error) {
	name := "uupbuilder-" + token
	defer func() {
		if err != nil && w != nil {
			err = errors.Join(err, w.Close())
			err = fmt.Errorf("workspace preserved at %s [job=%s volume=%d file=%d]: %w", w.Path(), jobID, w.fresh.rootID.VolumeSerial, w.fresh.rootID.FileIndex, err)
		}
	}()
	parentOwned := false
	defer func() {
		if !parentOwned {
			err = errors.Join(err, parentHandle.Close())
		}
	}()
	parentInfo, err := nativeInfo(parentHandle)
	if err != nil {
		return nil, err
	}
	created, err := createPrivateDirectory(windows.Handle(parentHandle.Fd()), name)
	if err != nil {
		return nil, err
	}
	// Custody begins at the native creation, before any fallible initialization.
	w = &Workspace{identity: WorkspaceIdentity{Path: filepath.Join(parent, name), JobID: jobID, Token: token}, mounts: make(map[string]mountClaim), fresh: &workspaceRemoval{selectedParent: parent, parent: parentHandle, parentID: nativeIdentity(parentInfo), created: os.NewFile(uintptr(created), name)}}
	parentOwned = true
	original, err := nativeInfo(w.fresh.created)
	if err != nil {
		return w, err
	}
	w.fresh.rootID = nativeIdentity(original)
	resolved, err := finalPath(created)
	if err != nil {
		return w, err
	}
	w.identity.Path = resolved
	w.root, err = parentRoot.OpenRoot(name)
	if err != nil {
		return w, err
	}
	owner, err := w.root.OpenFile(ownerFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return w, err
	}
	w.fresh.owner = owner
	ownerInfo, err := nativeInfo(owner)
	if err != nil {
		return w, err
	}
	w.fresh.ownerID = nativeIdentity(ownerInfo)
	b, _ := json.Marshal(w.identity)
	if _, err = owner.Write(b); err != nil {
		return w, err
	}
	if err = owner.Sync(); err != nil {
		return w, err
	}
	if err = owner.Close(); err != nil {
		return w, err
	}
	w.fresh.owner = nil
	if err = w.fresh.created.Close(); err != nil {
		return w, err
	}
	w.fresh.created = nil
	w.fresh.ready = true
	return w, nil
}

// Windows ignores Unix permission bits in Mkdir. Supply a protected inheritable
// DACL at the native create boundary, anchored to the already opened parent.
func createPrivateDirectory(parent windows.Handle, name string) (windows.Handle, error) {
	self, err := CurrentPeerIdentity()
	if err != nil {
		return 0, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + self.UserSID + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return 0, err
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var h windows.Handle
	err = windows.NtCreateFile(&h, windows.FILE_GENERIC_READ, &attributes, &windows.IO_STATUS_BLOCK{}, nil, windows.FILE_ATTRIBUTE_DIRECTORY, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	if status, ok := err.(windows.NTStatus); ok {
		err = status.Errno()
	}
	return h, err
}

// OpenWorkspace checks a persisted capability against the handle-relative owner
// marker. Higher layers must obtain this capability from their trusted journal.
func OpenWorkspace(id WorkspaceIdentity) (*Workspace, error) {
	if !filepath.IsAbs(id.Path) || !validID(id.JobID) || !validToken(id.Token) {
		return nil, errors.New("invalid workspace identity")
	}
	r, err := os.OpenRoot(id.Path)
	if err != nil {
		return nil, err
	}
	f, err := r.Open(ownerFile)
	if err != nil {
		r.Close()
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	f.Close()
	var got WorkspaceIdentity
	if err != nil || len(b) > 4096 || json.Unmarshal(b, &got) != nil || got != id {
		r.Close()
		return nil, errors.New("workspace ownership mismatch")
	}
	cap, err := InspectFileSystem(id.Path)
	if err != nil || !cap.Local || !strings.EqualFold(cap.Name, "NTFS") {
		r.Close()
		return nil, errors.New("workspace no longer resides on local NTFS")
	}
	return &Workspace{root: r, identity: id, mounts: make(map[string]mountClaim)}, nil
}

func validToken(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 16 && s == strings.ToLower(s)
}
func (w *Workspace) Path() string                { return w.identity.Path }
func (w *Workspace) Identity() WorkspaceIdentity { return w.identity }
func (w *Workspace) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeLocked()
}

func (w *Workspace) closeLocked() error {
	w.closeOnce.Do(func() {
		if w.root != nil {
			w.closeErr = errors.Join(w.closeErr, w.root.Close())
		}
		if w.fresh != nil {
			for _, file := range []*os.File{w.fresh.owner, w.fresh.created, w.fresh.parent} {
				if file != nil {
					w.closeErr = errors.Join(w.closeErr, file.Close())
				}
			}
		}
		if w.closeErr != nil {
			w.closeErr = fmt.Errorf("workspace handles preserved at %s [job=%s]: %w", w.Path(), w.Identity().JobID, w.closeErr)
		}
	})
	return w.closeErr
}

func workspaceName(name string) (string, error) {
	n, err := model.ValidateRelativePath(name)
	if err != nil {
		return "", err
	}
	if strings.EqualFold(strings.Split(n, "/")[0], ownerFile) {
		return "", errors.New("reserved workspace owner marker")
	}
	return filepath.FromSlash(n), nil
}
func (w *Workspace) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	n, err := workspaceName(name)
	if err != nil {
		return nil, err
	}
	// Delay truncation until the exact opened object's ownership is checked.
	f, err := w.root.OpenFile(n, flag&^os.O_TRUNC, perm)
	if err != nil {
		return nil, err
	}
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_TRUNC|os.O_APPEND) != 0 {
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
			f.Close()
			return nil, err
		}
		if info.NumberOfLinks > 1 {
			f.Close()
			return nil, errors.New("refusing mutation of a file with shared hard links")
		}
		if flag&os.O_TRUNC != 0 {
			if err := f.Truncate(0); err != nil {
				f.Close()
				return nil, err
			}
		}
	}
	return f, nil
}
func (w *Workspace) MkdirAll(name string) error {
	n, err := workspaceName(name)
	if err != nil {
		return err
	}
	return w.root.MkdirAll(n, 0700)
}

// Remove removes one entry only; it deliberately offers no recursive deletion.
func (w *Workspace) Remove(name string) error {
	n, err := workspaceName(name)
	if err != nil {
		return err
	}
	return w.root.Remove(n)
}

// Replace publishes a workspace file in one rename metadata operation. Both
// source and destination parents are opened beneath the root, including when
// the destination does not yet exist. No copy/delete fallback is attempted.
func (w *Workspace) Replace(source, destination string, replaceExisting bool) error {
	s, err := workspaceName(source)
	if err != nil {
		return err
	}
	d, err := workspaceName(destination)
	if err != nil {
		return err
	}
	src, err := w.root.Open(s)
	if err != nil {
		return err
	}
	defer src.Close()
	// ReOpenFile adds DELETE access to this exact open object, without resolving
	// its name a second time. It cannot be redirected by a reparse/rename race.
	h, _, callErr := windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile").Call(src.Fd(), windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, 0)
	if windows.Handle(h) == windows.InvalidHandle {
		return fmt.Errorf("reopen source: %w", callErr)
	}
	defer windows.CloseHandle(windows.Handle(h))
	parent, err := w.root.Open(filepath.Dir(d))
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := renameHandle(windows.Handle(h), windows.Handle(parent.Fd()), filepath.Base(d), replaceExisting); err != nil {
		return fmt.Errorf("rename beneath destination parent: %w", err)
	}
	return nil
}

// ClaimMount reserves an empty directory; it never calls image mounting APIs.
func (w *Workspace) ClaimMount(name, operationID string) (OwnedMount, error) {
	if !validID(operationID) {
		return OwnedMount{}, errors.New("operation identity required")
	}
	n, err := workspaceName(name)
	if err != nil {
		return OwnedMount{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.mounts[strings.ToLower(n)]; ok {
		return OwnedMount{}, errors.New("mount directory already claimed")
	}
	if err := w.root.Mkdir(n, 0700); err != nil {
		return OwnedMount{}, err
	}
	m := OwnedMount{Workspace: w.identity, RelativePath: filepath.ToSlash(n), JobID: w.identity.JobID, OperationID: operationID}
	f, err := w.root.Open(n)
	if err != nil {
		return OwnedMount{}, err
	}
	info, err := f.Stat()
	directoryID, idErr := fileIdentity(f)
	f.Close()
	if err != nil {
		return OwnedMount{}, err
	}
	if idErr != nil {
		return OwnedMount{}, idErr
	}
	m.DirectoryID = directoryID
	w.mounts[strings.ToLower(n)] = mountClaim{descriptor: m, info: info}
	return m, nil
}

// RestoreMount rebinds a mount claim from a trusted durable journal after a
// restart. Both the workspace capability and native directory identity must
// match; this function does not discover, mount, unmount or adopt other paths.
func (w *Workspace) RestoreMount(m OwnedMount) error {
	if m.Workspace != w.identity || m.JobID != w.identity.JobID || !validID(m.OperationID) {
		return errors.New("foreign mount ownership")
	}
	n, err := workspaceName(m.RelativePath)
	if err != nil {
		return err
	}
	f, err := w.root.Open(n)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	identity, err := fileIdentity(f)
	if err != nil {
		return err
	}
	if !info.IsDir() || identity != m.DirectoryID {
		return errors.New("persisted mount directory identity changed")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if prior, ok := w.mounts[strings.ToLower(n)]; ok && prior.descriptor != m {
		return errors.New("mount directory already owned by another operation")
	}
	w.mounts[strings.ToLower(n)] = mountClaim{descriptor: m, info: info}
	return nil
}

func fileIdentity(f *os.File) (FileIdentity, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return FileIdentity{}, err
	}
	return FileIdentity{VolumeSerial: info.VolumeSerialNumber, FileIndex: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)}, nil
}
func (w *Workspace) ValidateMount(m OwnedMount) error {
	n, err := workspaceName(m.RelativePath)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	claim, ok := w.mounts[strings.ToLower(n)]
	if !ok || claim.descriptor != m {
		return errors.New("mount is not owned by this operation")
	}
	f, err := w.root.Open(n)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.IsDir() || !os.SameFile(st, claim.info) {
		return errors.New("mount directory identity changed")
	}
	return nil
}

// AtomicReplace is the shared native namespace rename primitive for trusted
// absolute paths (e.g. config persistence). For privileged workspace IO use
// Workspace.Replace, which binds both ends to owned directory handles.
func AtomicReplace(source, destination string, replaceExisting bool) error {
	fail := func(err error) error { return &os.LinkError{Op: "rename", Old: source, New: destination, Err: err} }
	if !filepath.IsAbs(source) || !filepath.IsAbs(destination) {
		return fail(errors.New("absolute rename paths required"))
	}
	s, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return fail(err)
	}
	h, err := windows.CreateFile(s, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fail(err)
	}
	defer windows.CloseHandle(h)
	if err := renameHandle(h, 0, destination, replaceExisting); err != nil {
		return fail(err)
	}
	return nil
}

func renameHandle(h, parent windows.Handle, name string, replace bool) error {
	dst, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	// FILE_RENAME_INFO is naturally aligned differently on 386 and 64-bit hosts.
	type renameInfo struct {
		ReplaceIfExists uint32
		RootDirectory   windows.Handle
		FileNameLength  uint32
		FileName        [1]uint16
	}
	var layout renameInfo
	offset := int(unsafe.Offsetof(layout.FileName))
	filename := dst[:len(dst)-1]
	// The Win32 FILE_RENAME_INFO path is NUL-terminated even though its byte
	// length excludes that terminator. Do not rely on allocator padding: at
	// exact allocation boundaries it can be read as an invalid path suffix.
	buffer := make([]byte, max(int(unsafe.Sizeof(layout)), offset+2*len(dst)))
	info := (*renameInfo)(unsafe.Pointer(&buffer[0]))
	if replace {
		info.ReplaceIfExists = 1
	}
	info.RootDirectory = parent
	info.FileNameLength = uint32(2 * len(filename))
	copy(unsafe.Slice(&info.FileName[0], len(dst)), dst)
	if parent != 0 {
		// NtSetInformationFile supports an explicit destination directory
		// handle on the Windows 10 baseline; no path re-resolution is needed.
		err = windows.NtSetInformationFile(h, &windows.IO_STATUS_BLOCK{}, &buffer[0], uint32(len(buffer)), 10)
		if status, ok := err.(windows.NTStatus); ok {
			err = status.Errno()
		}
	} else {
		err = windows.SetFileInformationByHandle(h, 3, &buffer[0], uint32(len(buffer)))
	}
	runtime.KeepAlive(buffer)
	return err
}

func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, 512)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n+1)
	}
}

// InspectFileSystem describes the volume containing an existing path, using its
// resolved handle so a junction cannot misreport the containing volume.
func InspectFileSystem(path string) (model.FileSystemCapabilities, error) {
	if !filepath.IsAbs(path) {
		return model.FileSystemCapabilities{}, errors.New("absolute filesystem path required")
	}
	f, err := os.Open(path)
	if err != nil {
		return model.FileSystemCapabilities{}, err
	}
	defer f.Close()
	var flags uint32
	name := make([]uint16, 256)
	if err := windows.GetVolumeInformationByHandle(windows.Handle(f.Fd()), nil, 0, nil, nil, &flags, &name[0], uint32(len(name))); err != nil {
		return model.FileSystemCapabilities{}, err
	}
	p, err := finalPath(windows.Handle(f.Fd()))
	if err != nil {
		return model.FileSystemCapabilities{}, err
	}
	vol := filepath.VolumeName(p) + `\`
	v, _ := windows.UTF16PtrFromString(vol)
	drive := windows.GetDriveType(v)
	return model.FileSystemCapabilities{Name: windows.UTF16ToString(name), Local: drive == windows.DRIVE_FIXED, ACLs: flags&windows.FILE_PERSISTENT_ACLS != 0, AlternateStreams: flags&windows.FILE_NAMED_STREAMS != 0, ReparsePoints: flags&windows.FILE_SUPPORTS_REPARSE_POINTS != 0, HardLinks: flags&windows.FILE_SUPPORTS_HARD_LINKS != 0}, nil
}

// lockDirectory pins a resolved existing directory until CreateProcess has
// consumed its path. Native equality is rechecked after opening without delete
// sharing, preventing a substitution between resolution and the native open.
func (w *Workspace) lockDirectory(name string) (*os.File, string, error) {
	n := "."
	var err error
	if name != "" && name != "." {
		n, err = workspaceName(name)
		if err != nil {
			return nil, "", err
		}
	}
	f, err := w.root.Open(n)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.IsDir() {
		return nil, "", errors.New("working directory is not an owned directory")
	}
	path, err := finalPath(windows.Handle(f.Fd()))
	if err != nil {
		return nil, "", err
	}
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, "", err
	}
	locked := os.NewFile(uintptr(h), path)
	got, err := locked.Stat()
	if err != nil || !os.SameFile(st, got) || got.Mode()&os.ModeSymlink != 0 {
		locked.Close()
		return nil, "", fmt.Errorf("working directory changed during resolution")
	}
	return locked, path, nil
}
