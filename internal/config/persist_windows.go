//go:build windows

package config

import (
	"errors"
	"os"

	platform "uupbuilder/internal/platform/windows"
)

// Preserve config's private error contract while sharing the native single
// metadata rename primitive with workspace/cache/journal producers.
func replaceFile(source, destination string, replaceExisting bool) error {
	err := platform.AtomicReplace(source, destination, replaceExisting)
	if err == nil {
		return nil
	}
	var link *os.LinkError
	if errors.As(err, &link) {
		err = link.Err
	}
	return &os.LinkError{Op: "rename config", Old: source, New: destination, Err: err}
}
