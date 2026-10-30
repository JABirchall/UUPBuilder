package windows

import (
	"errors"
	"io"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Unmount validates the original claim before invoking the provider. DISM may
// replace the mount directory on success; only that operation's empty, ordinary
// directory can become the new claim. Recovery never adopts a changed identity.
// The caller must durably record the returned claim and independently inspect
// actual OS mount state before authorizing checkpoint reuse or cleanup.
func (w *Workspace) Unmount(m OwnedMount, action func() error) (updated OwnedMount, err error) {
	if action == nil {
		return updated, errors.New("unmount action required")
	}
	if err := w.ValidateMount(m); err != nil {
		return updated, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := workspaceName(m.RelativePath)
	if err != nil {
		return updated, err
	}
	// Pin ordinary ancestors throughout the provider call without preventing
	// DISM from replacing the mount directory itself.
	parent, held, err := treeParent(w, filepath.ToSlash(filepath.Dir(n)))
	if err != nil {
		return updated, err
	}
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			err = errors.Join(err, held[i].Close())
		}
	}()
	before, err := nativeTreeOpen(windows.Handle(parent.Fd()), filepath.Base(n), windows.FILE_GENERIC_READ, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
	if err != nil {
		return updated, err
	}
	info, identityErr := nativeInfo(before)
	if err := errors.Join(identityErr, before.Close()); err != nil {
		return updated, err
	}
	if nativeIdentity(info) != m.DirectoryID || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return updated, errors.New("mount directory changed before unmount")
	}
	if err := action(); err != nil {
		return updated, err
	}
	// Open without following reparses and deny deletion while observing the
	// replacement. This never walks an image tree or removes any entries.
	after, err := nativeTreeOpenShared(windows.Handle(parent.Fd()), filepath.Base(n), windows.FILE_GENERIC_READ, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil)
	if err != nil {
		return updated, err
	}
	defer func() { err = errors.Join(err, after.Close()) }()
	info, err = nativeInfo(after)
	if err != nil {
		return updated, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return updated, errors.New("unmounted directory is a reparse point")
	}
	if err := workspaceNoStreams(after, true); err != nil {
		return updated, err
	}
	names, err := after.Readdirnames(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return updated, err
	}
	if len(names) != 0 {
		return updated, errors.New("unmounted directory is not empty")
	}
	stat, err := after.Stat()
	if err != nil {
		return updated, err
	}
	updated = m
	updated.DirectoryID = nativeIdentity(info)
	w.mounts[strings.ToLower(n)] = mountClaim{descriptor: updated, info: stat}
	return updated, nil
}
