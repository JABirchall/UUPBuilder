package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	native "golang.org/x/sys/windows"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/tools"
	"uupbuilder/internal/tui"
)

// CheckTools only observes inbox file availability and the bundled acquisition
// recipe. It never creates workspaces, contacts the source or launches helpers.
func (s *buildService) CheckTools(ctx context.Context, draft tui.BuildDraft) ([]string, error) {
	if ctx == nil {
		return nil, fmt.Errorf("tool check requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, os.ErrClosed
	}
	selection, _, err := draft.Config.Request()
	if err != nil {
		return nil, err
	}
	host, err := platform.DetectHost(ctx)
	if err != nil {
		return nil, err
	}
	// The source manifest is deliberately unavailable until the confirmed run.
	_, err = tools.SelectedRequirement(host, model.SourceIdentity{UpdateID: selection.UpdateID, BuildLabel: "pending source inspection", Architecture: selection.Architecture, Language: selection.Language}, tools.SelectedRecipeDigest())
	if err != nil {
		return nil, err
	}
	system, err := native.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	if host.ProcessArchitecture == model.ArchitectureX86 && host.NativeArchitecture != model.ArchitectureX86 {
		root, err := native.GetWindowsDirectory()
		if err != nil {
			return nil, err
		}
		system = filepath.Join(root, "Sysnative")
	}
	return availableBuildTools(ctx, system)
}

func availableBuildTools(ctx context.Context, system string) ([]string, error) {
	var result []string
	for _, name := range []string{"expand.exe", "WindowsPowerShell/v1.0/powershell.exe", "imapi2fs.dll"} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := os.Stat(filepath.Join(system, filepath.FromSlash(name)))
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("required tool unavailable: %s", name)
		}
		result = append(result, filepath.Base(name)+": available")
	}
	return append(result, "wimlib: managed download after Start", "DISM: managed download after Start"), nil
}
