package windows

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// ShortMountPath observes an existing native alias without changing NTFS 8.3
// policy or creating a link. Both spellings must identify the claimed directory.
func (w *Workspace) ShortMountPath(m OwnedMount) (string, error) {
	if err := w.ValidateMount(m); err != nil {
		return "", err
	}
	path := filepath.Join(w.Path(), filepath.FromSlash(m.RelativePath))
	fail := func(err error) (string, error) {
		return "", fmt.Errorf("resolve owned DISM mount path %q; choose a shorter storage.workspace directory if native aliases are unavailable: %w", path, err)
	}
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fail(err)
	}
	buffer := make([]uint16, 32768)
	n, err := windows.GetShortPathName(wide, &buffer[0], uint32(len(buffer)))
	if err != nil {
		return fail(err)
	}
	if n == 0 || n >= uint32(len(buffer)) {
		return fail(errors.New("native alias exceeds path bound"))
	}
	short := windows.UTF16ToString(buffer[:n])
	ordinary := strings.TrimPrefix(short, `\\?\`)
	if length := len(utf16.Encode([]rune(ordinary))); length >= 260 {
		return fail(fmt.Errorf("native mount path has %d UTF-16 characters; the ordinary Win32 limit is 259", length))
	}
	f, err := os.Open(short)
	if err != nil {
		return fail(err)
	}
	id, identityErr := fileIdentity(f)
	if err := errors.Join(identityErr, f.Close()); err != nil {
		return fail(err)
	}
	if id != m.DirectoryID {
		return fail(errors.New("native alias changed the claimed directory identity"))
	}
	if err := w.ValidateMount(m); err != nil {
		return fail(err)
	}
	return short, nil
}
