package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// CBS constructs ordinary Win32 paths inside the image even when the caller
// supports extended paths. Check the actual source's stack, not a build pin or
// an assumed mount-prefix budget. Only direct WinSxS entries are enumerated.
func checkDISMServicingPaths(image string) error {
	root := filepath.Join(image, "Windows", "WinSxS")
	directory, err := os.Open(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil // DISM remains responsible for reporting an invalid image.
	}
	if err != nil {
		return err
	}
	defer directory.Close()
	for count := 0; ; {
		entries, err := directory.ReadDir(256)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		count += len(entries)
		if count > 65536 {
			return fmt.Errorf("%w: servicing-stack directory inspection exceeds bound", ErrProviderUnavailable)
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.Contains(strings.ToLower(entry.Name()), "_microsoft-windows-servicingstack_") {
				continue
			}
			path := filepath.Join(root, entry.Name(), "CbsCore.dll")
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
			ordinary := ordinaryDISMArguments([]string{path})[0]
			if length := len(utf16.Encode([]rune(ordinary))); length >= 260 {
				return fmt.Errorf("%w: CBS servicing-stack path has %d UTF-16 characters (Win32 limit 259): %s; select a shorter storage.workspace directory or move the executable and its UUP directory to a shorter path", ErrProviderUnavailable, length, ordinary)
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}
