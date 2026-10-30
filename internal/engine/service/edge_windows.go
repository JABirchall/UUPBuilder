package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	names := []string{"Edge/Application/msedge.exe", "EdgeCore/141.0.3537.71/msedge.exe", "EdgeUpdate/MicrosoftEdgeUpdate.exe", "EdgeWebView/Application/141.0.3537.71/msedgewebview2.exe"}
	if err := d.workspace.MkdirAll("edge-observation"); err != nil {
		return nil, err
	}
	dir := filepath.Join(d.workspace.Path(), "edge-observation")
	args := []string{"extract", source, "1"}
	for _, name := range names {
		args = append(args, "/"+name)
	}
	args = append(args, "--dest-dir="+dir, "--no-acls", "--preserve-dir-structure")
	result, err := platform.NewRunner().Run(ctx, platform.Invocation{Executable: d.runtime.WIMLib(), Arguments: ordinaryDISMArguments(args), Workspace: d.workspace, JobID: d.workspace.Identity().JobID, OperationID: "observe-source-edge", Cancellation: platform.CancelTerminateTree}, emit)
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
