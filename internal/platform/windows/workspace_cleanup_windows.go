package windows

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf16"

	native "golang.org/x/sys/windows"
)

type workspaceRemoval struct {
	parent                    *os.File
	created, owner            *os.File
	parentID, rootID, ownerID FileIdentity
	removed                   bool
	ready, markerRemoved      bool
	markerRemovalRequested    bool
	removeErr                 error
}

// RemoveEmpty consumes only a freshly created workspace's empty root. Its
// caller must quiesce all users and remove its known files through Remove first.
// Reopened capabilities never acquire this permission. Unknown entries/streams,
// replaced roots or ownership markers are preserved. No tree is traversed.
// Success also closes the workspace; failure leaves explicit identity custody.
func (w *Workspace) RemoveEmpty() (err error) {
	if w == nil {
		return errors.New("workspace preserved: missing fresh custody")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fresh == nil {
		return fmt.Errorf("workspace preserved at %s [job=%s]: no fresh custody", w.Path(), w.Identity().JobID)
	}
	c := w.fresh
	if c.removed {
		return c.removeErr
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("workspace cleanup incomplete; custody preserved at %s [job=%s volume=%d file=%d owner-file=%d marker-deletion-requested=%t marker-removed=%t root-deletion-requested=%t]: %w", w.Path(), w.Identity().JobID, c.rootID.VolumeSerial, c.rootID.FileIndex, c.ownerID.FileIndex, c.markerRemovalRequested, c.markerRemoved, c.removed, err)
		}
		c.removeErr = err
	}()
	if !c.ready {
		return errors.New("fresh workspace initialization incomplete")
	}
	parent, err := nativeInfo(c.parent)
	if err != nil || nativeIdentity(parent) != c.parentID || parent.FileAttributes&native.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(errors.New("parent custody changed"), err)
	}
	root, err := nativeTreeOpenShared(native.Handle(c.parent.Fd()), filepath.Base(w.Path()), native.FILE_GENERIC_READ|native.DELETE, native.FILE_OPEN, native.FILE_DIRECTORY_FILE, native.FILE_SHARE_READ|native.FILE_SHARE_WRITE, nil)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	info, err := nativeInfo(root)
	if err != nil || nativeIdentity(info) != c.rootID || info.FileAttributes&native.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(errors.New("root custody changed"), err)
	}
	if err := workspaceNoStreams(root, true); err != nil {
		return err
	}
	names, err := root.Readdirnames(2)
	if err != nil && err != io.EOF {
		return err
	}
	if len(names) != 1 || names[0] != ownerFile {
		return errors.New("unknown entries remain")
	}
	owner, err := nativeTreeOpenShared(native.Handle(root.Fd()), ownerFile, native.FILE_GENERIC_READ|native.DELETE, native.FILE_OPEN, native.FILE_NON_DIRECTORY_FILE, native.FILE_SHARE_READ, nil)
	if err != nil {
		return err
	}
	ownerClosed := false
	defer func() {
		if !ownerClosed {
			err = errors.Join(err, owner.Close())
		}
	}()
	info, err = nativeInfo(owner)
	if err != nil || nativeIdentity(info) != c.ownerID || info.NumberOfLinks != 1 || info.FileAttributes&native.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(errors.New("owner custody changed"), err)
	}
	if err := workspaceNoStreams(owner, false); err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(owner, 4097))
	var id WorkspaceIdentity
	if err != nil || len(body) > 4096 || json.Unmarshal(body, &id) != nil || id != w.Identity() {
		return errors.Join(errors.New("owner binding changed"), err)
	}
	if err := deleteHeld(owner); err != nil {
		return err
	}
	c.markerRemovalRequested = true
	err = owner.Close()
	ownerClosed = true
	if err != nil {
		return err
	}
	c.markerRemoved = true
	// The native directory disposition independently refuses a concurrent new
	// entry. It cannot recursively delete or follow that entry.
	if err := deleteHeld(root); err != nil {
		return err
	}
	c.removed = true
	return w.closeLocked()
}

func workspaceNoStreams(f *os.File, directory bool) error {
	b := alignedNativeBuffer(16 << 10)
	err := native.GetFileInformationByHandleEx(native.Handle(f.Fd()), native.FileStreamInfo, &b[0], uint32(len(b)))
	if directory && errors.Is(err, native.ERROR_HANDLE_EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	streams, err := parseStreams(b, 256)
	if err != nil {
		return err
	}
	for _, stream := range streams {
		if string(utf16.Decode(stream.Name)) != "::$DATA" {
			return errors.New("unknown workspace stream remains")
		}
	}
	return nil
}
