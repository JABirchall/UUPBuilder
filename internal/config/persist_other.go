//go:build !windows

package config

import "os"

// The product is Windows-only. This backend allows the portable configuration
// boundary to be exercised on development hosts using same-filesystem rename.
func replaceFile(source, destination string, replaceExisting bool) error {
	if !replaceExisting {
		// A hard link atomically publishes a new name without clobbering an appearing
		// file. Save's deferred cleanup removes the temporary name afterward.
		return os.Link(source, destination)
	}
	return os.Rename(source, destination)
}
