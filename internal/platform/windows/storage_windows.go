package windows

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
)

type StorageVolume struct {
	Path           string
	ID             string
	Capabilities   model.FileSystemCapabilities
	AvailableBytes uint64
	MaxFileBytes   uint64
}

// InspectStorage follows an existing directory handle to the actual chosen
// volume. A not-yet-created destination uses its nearest existing ancestor;
// preflight never creates a user directory or assumes the current drive.
func InspectStorage(path string) (StorageVolume, error) {
	v := StorageVolume{Path: path}
	if !filepath.IsAbs(path) {
		return v, errors.New("absolute chosen storage path required")
	}
	ancestor := filepath.Clean(path)
	var f *os.File
	for {
		opened, err := os.Open(ancestor)
		if err == nil {
			f = opened
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return v, err
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return v, err
		}
		ancestor = parent
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return v, err
	}
	if !info.IsDir() {
		return v, errors.New("storage ancestor is not a directory")
	}
	actual, err := finalPath(windows.Handle(f.Fd()))
	if err != nil {
		return v, err
	}
	v.Capabilities, err = InspectFileSystem(actual)
	if err != nil {
		return v, err
	}
	name, err := windows.UTF16PtrFromString(actual)
	if err != nil {
		return v, err
	}
	mount := make([]uint16, 32768)
	if err := windows.GetVolumePathName(name, &mount[0], uint32(len(mount))); err != nil {
		return v, err
	}
	guid := make([]uint16, 32768)
	if err := windows.GetVolumeNameForVolumeMountPoint(&mount[0], &guid[0], uint32(len(guid))); err != nil {
		return v, err
	}
	v.ID = strings.ToLower(windows.UTF16ToString(guid))
	if err := windows.GetDiskFreeSpaceEx(&mount[0], &v.AvailableBytes, nil, nil); err != nil {
		return v, err
	}
	switch strings.ToUpper(v.Capabilities.Name) {
	case "FAT32", "FAT":
		v.MaxFileBytes = (4 << 30) - 1
	case "NTFS", "REFS", "EXFAT":
		v.MaxFileBytes = math.MaxInt64
	default:
		return v, errors.New("chosen volume large-file capability unknown")
	}
	return v, nil
}

// ValidateWorkspaceParent binds the capability's resolved workspace to the
// selected scratch parent. It follows handles, so an alias or junction cannot
// substitute a different parent while retaining a valid workspace token.
func ValidateWorkspaceParent(id WorkspaceIdentity, selected string) error {
	parent, err := os.Open(selected)
	if err != nil {
		return err
	}
	defer parent.Close()
	info, err := parent.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("selected workspace parent is not a directory")
	}
	actual, err := finalPath(windows.Handle(parent.Fd()))
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(filepath.Dir(id.Path)), filepath.Clean(actual)) {
		return errors.New("workspace is outside the planned scratch parent")
	}
	return nil
}
