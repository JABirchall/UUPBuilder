package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

// Add-Edge is provided by the original source EdgeProvider, composed beside the
// managed DISM. It owns deployment paths, registry and ACL semantics; no target
// installer/browser is executed by the builder and no file overlay is guessed.
func (d *DISM) ApplySourceEdge(ctx context.Context, m platform.OwnedMount, source string, emit model.Emit) error {
	if d.runtime == nil || !d.runtime.SourceEdgeReady() || filepath.Base(source) != "Edge.wim" {
		return ErrProviderUnavailable
	}
	if _, err := d.offline(ctx, m, emit, "/Add-Edge", "/SupportPath:"+filepath.Dir(source)); err != nil {
		return err
	}
	return d.VerifySourceEdge(ctx, m, source, emit)
}

// Read back representative original bytes from every EdgeContent root. Native
// successful exit alone is insufficient. These are observations of the native
// deployment location, not instructions to install files into that location.
func (d *DISM) VerifySourceEdge(ctx context.Context, m platform.OwnedMount, source string, emit model.Emit) error {
	if d.runtime == nil || !d.runtime.SourceEdgeReady() {
		return ErrProviderUnavailable
	}
	mount, err := mountPath(m)
	if err != nil {
		return err
	}
	samples, err := d.sourceEdgeSamples(ctx, source, emit)
	if err != nil {
		return err
	}
	for name, digest := range samples {
		if err = verifySHA256(ctx, filepath.Join(mount, "Program Files (x86)", "Microsoft", filepath.FromSlash(name)), digest); err != nil {
			return fmt.Errorf("source-default Edge readback %s: %w", name, err)
		}
	}
	return nil
}
func (d *DISM) sourceEdgeSamples(ctx context.Context, source string, emit model.Emit) (map[string]string, error) {
	if d.edgeSamples != nil {
		if source != d.edgeSource {
			return nil, ErrVerification
		}
		return d.edgeSamples, nil
	}
	lease, err := openExecutable(source)
	if err != nil {
		return nil, err
	}
	defer lease.file.Close()
	// RunResult retains only a 64 KiB tail; collect bounded log chunks so earlier
	// offered roots cannot disappear from a large source directory listing.
	var listing strings.Builder
	var mu sync.Mutex
	overflow := false
	result, err := platform.NewRunner().Run(ctx, platform.Invocation{Executable: d.runtime.WIMLib(), Arguments: ordinaryDISMArguments([]string{"dir", source, "1"}), Workspace: d.workspace, JobID: d.workspace.Identity().JobID, OperationID: "list-source-edge", Cancellation: platform.CancelTerminateTree}, func(event model.Event) {
		if emit != nil {
			emit(event)
		}
		if event.Kind != model.EventLog {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if len(event.Message) > 8<<20-listing.Len() {
			overflow = true
			return
		}
		listing.WriteString(event.Message)
	})
	if err != nil {
		return nil, fmt.Errorf("list EdgeContent (exit %d): %w", result.ExitCode, err)
	}
	if overflow {
		return nil, ErrVerification
	}
	names, err := edgeSamplePaths(decodeOutput(listing.String()))
	if err != nil {
		return nil, err
	}
	if err := d.workspace.MkdirAll("edge-observation"); err != nil {
		return nil, err
	}
	dir := filepath.Join(d.workspace.Path(), "edge-observation")
	args := []string{"extract", source, "1"}
	for _, name := range names {
		args = append(args, "/"+name)
	}
	args = append(args, "--dest-dir="+dir, "--no-acls", "--preserve-dir-structure")
	result, err = platform.NewRunner().Run(ctx, platform.Invocation{Executable: d.runtime.WIMLib(), Arguments: ordinaryDISMArguments(args), Workspace: d.workspace, JobID: d.workspace.Identity().JobID, OperationID: "observe-source-edge", Cancellation: platform.CancelTerminateTree}, emit)
	if err != nil {
		return nil, fmt.Errorf("observe EdgeContent (exit %d): %w", result.ExitCode, err)
	}
	samples := map[string]string{}
	for _, name := range names {
		path := filepath.Join(dir, filepath.FromSlash(name))
		st, e := os.Lstat(path)
		if e != nil || !st.Mode().IsRegular() {
			return nil, ErrVerification
		}
		output, e := fileOutput(ctx, path, name, "source-edge-observation")
		if e != nil {
			return nil, e
		}
		samples[name] = output.SHA256
	}
	d.edgeSource = source
	d.edgeSamples = samples
	return samples, nil
}

// edgeSamplePaths derives representative readback paths from the offered WIM
// contents. Browser versions belong to source observations, never tool policy.
func edgeSamplePaths(listing string) ([]string, error) {
	roots := map[string]bool{}
	represented := map[string]bool{}
	seen := map[string]bool{}
	var names []string
	for _, line := range strings.Split(listing, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "/") && !strings.HasPrefix(line, `\`) {
			continue
		}
		name := strings.TrimPrefix(strings.ReplaceAll(line, `\`, "/"), "/")
		if name == "" {
			continue
		}
		clean, err := model.ValidateRelativePath(name)
		if err != nil || clean != name {
			return nil, ErrVerification
		}
		parts := strings.Split(name, "/")
		root := strings.ToLower(parts[0])
		switch root {
		case "edge", "edgecore", "edgeupdate", "edgewebview":
		default:
			continue
		}
		roots[root] = true
		match := strings.EqualFold(name, "Edge/Application/msedge.exe") || strings.EqualFold(name, "EdgeUpdate/MicrosoftEdgeUpdate.exe")
		if root == "edgecore" && len(parts) == 3 && strings.EqualFold(parts[2], "msedge.exe") {
			match = edgeVersionDirectory(parts[1])
		}
		if root == "edgewebview" && len(parts) == 4 && strings.EqualFold(parts[1], "Application") && strings.EqualFold(parts[3], "msedgewebview2.exe") {
			match = edgeVersionDirectory(parts[2])
		}
		if match {
			if seen[strings.ToLower(name)] {
				return nil, ErrVerification
			}
			seen[strings.ToLower(name)] = true
			represented[root] = true
			names = append(names, name)
		}
	}
	if len(roots) == 0 {
		return nil, ErrVerification
	}
	for root := range roots {
		if !represented[root] {
			return nil, fmt.Errorf("%w: source Edge root %s has no observable representative executable", ErrVerification, root)
		}
	}
	sort.Strings(names)
	return names, nil
}
func edgeVersionDirectory(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}
