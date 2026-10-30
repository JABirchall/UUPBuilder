package app

import (
	"fmt"
	"os"

	"uupbuilder/internal/config"
	"uupbuilder/internal/model"
)

// initializeBuildStorage runs only inside an explicitly started preparation.
// User-selected parents retain their existing capability/ownership checks;
// only the application's automatic parent is initialized here.
func initializeBuildStorage(storage model.StorageSettings) (workspace, cache string, err error) {
	workspace, cache = storage.Workspace, storage.Cache
	if workspace != "auto" && cache != "auto" {
		return workspace, cache, nil
	}
	base, err := config.DefaultDirectory()
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", "", fmt.Errorf("initialize automatic storage %q (choose writable storage.workspace and storage.cache directories to override): %w", base, err)
	}
	if workspace == "auto" {
		workspace = base
	}
	if cache == "auto" {
		cache = base
	}
	return workspace, cache, nil
}
