package tools

import (
	"archive/zip"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	native "golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strings"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

// This recipe is a new acquisition route, not a change to the historical
// capability manifest. Pins were measured from the official wimlib archive and
// signed Microsoft ADK 28000.3481 CABs; MSI File IDs provide the extraction map.
// It acquires files only. Native servicing still requires a privileged worker.
//
//go:embed manifests/selected-amd64-28000.json
var selectedBytes []byte

type selectedFile struct {
	Relative, SHA256, Version, Cabinet, MsiFile string
	Size                                        int64
}
type selectedCabinet struct {
	Cabinet, SHA256 string
	Bytes           int64
}
type runtimeRecipe struct {
	Cabinets     []selectedCabinet
	DISM, WIMLib []selectedFile
	SourceDISM   []selectedFile
}

func selectedRecipe() (r runtimeRecipe, err error) { err = json.Unmarshal(selectedBytes, &r); return }
func SelectedRecipeDigest() string                 { return digestBytes(selectedBytes) }

// SelectedRequirement freezes an implemented recipe, not a native acceptance
// certificate. Privilege, file pins and resulting artifacts are checked at run.
func SelectedRequirement(host model.Host, source model.SourceIdentity, manifest string) (Requirement, error) {
	r := Requirement{Host: host, Target: source.Architecture, Operations: []Operation{Extract, Inspect, Reconstruct, Service, MasterISO}, ManifestDigest: SelectedRecipeDigest(), Source: source, SourceManifestDigest: manifest, RuleDigest: digestBytes([]byte("u10b-selected-source-28000-v1"))}
	if r.Validate() != nil || host.NativeArchitecture != "amd64" || source.UpdateID != "8f550c54-da87-45d3-89e3-0c03a6f16ae8" || source.BuildLabel != "28000.3365" || source.Architecture != "amd64" || source.Language != "en-gb" {
		return Requirement{}, fmt.Errorf("selected managed source/runtime recipe unavailable for this host or source")
	}
	return r, nil
}
func IsSelectedRequirement(r Requirement) bool {
	want, e := SelectedRequirement(r.Host, r.Source, r.SourceManifestDigest)
	if e != nil {
		return false
	}
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(r)
	return string(a) == string(b)
}

// SelectedRuntime holds read-only, deny-write/delete handles for every runtime
// file until Close. It never installs/registers drivers or launches elevation.
type SelectedRuntime struct {
	wimlib, dism string
	files        []*os.File
	workspace    *platform.Workspace
	sourceEdge   bool
}

func (r *SelectedRuntime) WIMLib() string {
	if r == nil {
		return ""
	}
	return r.wimlib
}
func (r *SelectedRuntime) DISM() string {
	if r == nil {
		return ""
	}
	return r.dism
}
func (r *SelectedRuntime) Build() uint32 {
	if r == nil || len(r.files) == 0 {
		return 0
	}
	return 28000
}

func (r *SelectedRuntime) DISMIdentity() (sha256, version string) {
	if r == nil || len(r.files) == 0 {
		return "", ""
	}
	recipe, err := selectedRecipe()
	if err != nil {
		return "", ""
	}
	for _, file := range recipe.DISM {
		if strings.EqualFold(file.Relative, "dism.exe") {
			return file.SHA256, file.Version
		}
	}
	return "", ""
}
func (r *SelectedRuntime) Close() error {
	var err error
	for _, f := range r.files {
		err = errors.Join(err, f.Close())
	}
	r.files = nil
	r.wimlib = ""
	r.dism = ""
	return err
}

// AcquireSelected downloads and verifies the complete pinned helper set into a
// fresh owned workspace. FetchOne supplies the existing retry/cache transport.
// The caller owns the workspace and closes the lease before disposing of it.
func AcquireSelected(ctx context.Context, w *platform.Workspace, fetch Fetcher, emit model.Emit) (runtime *SelectedRuntime, err error) {
	if ctx == nil || w == nil || fetch == nil {
		return nil, ErrInvalidInput
	}
	host, e := platform.DetectHost(ctx)
	if e != nil {
		return nil, e
	}
	if host.NativeArchitecture != model.ArchitectureAMD64 {
		return nil, fmt.Errorf("managed 28000 runtime is currently implemented for native amd64")
	}
	recipe, e := selectedRecipe()
	if e != nil {
		return nil, e
	}
	runtime = &SelectedRuntime{workspace: w}
	defer func() {
		if err != nil {
			runtime.Close()
			runtime = nil
		}
	}()
	for _, dir := range []string{"runtime/wimlib", "runtime/dism", "runtime/cabinets"} {
		if err = w.MkdirAll(dir); err != nil {
			return
		}
	}
	acquire := func(name, url, sha string, size int64) (string, error) {
		p, e := model.NewPayload(model.PayloadIdentity{Size: size, Digest: model.Digest{Algorithm: model.DigestSHA256, Value: sha}, Provenance: model.PackageProvenance{Source: url, Name: name}}, "tools/"+name)
		if e != nil {
			return "", e
		}
		got, e := fetch.FetchOne(ctx, p, model.Locator{URL: url}, emit)
		if e != nil {
			return "", e
		}
		if got.Identity != p.Identity || got.SHA256 != sha {
			return "", ErrIntegrity
		}
		f, e := os.Open(got.Path)
		if e != nil {
			return "", e
		}
		defer f.Close()
		dst, e := w.OpenFile("runtime/cabinets/"+name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return "", e
		}
		e = errors.Join(copyVerified(ctx, dst, f, size, sha), dst.Sync(), dst.Close())
		return plainRuntimePath(filepath.Join(w.Path(), "runtime/cabinets", name)), e
	}
	archive, e := acquire("wimlib.zip", "https://wimlib.net/downloads/wimlib-1.14.5-windows-x86_64-bin.zip", "2f446d6fa3866582175f1a22a7be198eeee0aec7aba5b4e04ad25c99eae2d265", 778747)
	if e != nil {
		err = e
		return
	}
	z, e := zip.OpenReader(archive)
	if e != nil {
		err = e
		return
	}
	defer z.Close()
	entries, e := inspectZIP(&z.Reader)
	if e != nil {
		err = e
		return
	}
	for _, pin := range recipe.WIMLib {
		entry := entries[pin.Relative]
		if entry == nil {
			err = ErrIntegrity
			return
		}
		src, e := entry.Open()
		if e != nil {
			err = e
			return
		}
		err = writeSelected(ctx, w, "runtime/wimlib/"+pin.Relative, src, pin)
		src.Close()
		if err != nil {
			return
		}
	}
	system, e := native.GetSystemDirectory()
	if e != nil {
		err = e
		return
	}
	if host.ProcessArchitecture == model.ArchitectureX86 {
		root, e := native.GetWindowsDirectory()
		if e != nil {
			err = e
			return
		}
		system = filepath.Join(root, "Sysnative")
	}
	for i, cab := range recipe.Cabinets {
		path, e := acquire(cab.Cabinet, "https://download.microsoft.com/download/0dfa675f-bff6-4c31-bad9-86bc5b7db5ed/adk/Installers/"+cab.Cabinet, cab.SHA256, cab.Bytes)
		if e != nil {
			err = e
			return
		}
		rel := fmt.Sprintf("runtime/expanded-%d", i)
		if err = w.MkdirAll(rel); err != nil {
			return
		}
		directory := plainRuntimePath(filepath.Join(w.Path(), rel))
		result, e := platform.NewRunner().Run(ctx, platform.Invocation{Executable: filepath.Join(system, "expand.exe"), Arguments: []string{"-F:*", path, directory}, Workspace: w, JobID: w.Identity().JobID, OperationID: "acquire-runtime", Cancellation: platform.CancelTerminateTree}, emit)
		if e != nil {
			err = fmt.Errorf("extract managed DISM CAB (exit %d): %w", result.ExitCode, e)
			return
		}
		for _, pin := range recipe.DISM {
			if pin.Cabinet != cab.Cabinet {
				continue
			}
			src, e := os.Open(filepath.Join(directory, pin.MsiFile))
			if e != nil {
				err = e
				return
			}
			err = writeSelected(ctx, w, "runtime/dism/"+filepath.ToSlash(pin.Relative), src, pin)
			src.Close()
			if err != nil {
				return
			}
		}
	}
	for _, group := range []struct {
		dir  string
		pins []selectedFile
	}{{"wimlib", recipe.WIMLib}, {"dism", recipe.DISM}} {
		for _, pin := range group.pins {
			path := plainRuntimePath(filepath.Join(w.Path(), "runtime", group.dir, pin.Relative))
			f, e := lockSelected(path)
			if e != nil {
				err = e
				return
			}
			runtime.files = append(runtime.files, f)
			if err = copyVerified(ctx, io.Discard, f, pin.Size, pin.SHA256); err != nil {
				return
			}
		}
	}
	runtime.wimlib = plainRuntimePath(filepath.Join(w.Path(), "runtime/wimlib/wimlib-imagex.exe"))
	runtime.dism = plainRuntimePath(filepath.Join(w.Path(), "runtime/dism/dism.exe"))
	return runtime, nil
}

// AcquireSourceEdge adds the two exact source provider files to the portable
// runtime. The original assembled WIM is a verified direct stage predecessor;
// each extracted member is independently pinned before any native load.
func (r *SelectedRuntime) AcquireSourceEdge(ctx context.Context, base string) error {
	if r == nil || r.Build() == 0 || r.workspace == nil {
		return ErrInvalidInput
	}
	if r.sourceEdge {
		return nil
	}
	recipe, err := selectedRecipe()
	if err != nil {
		return err
	}
	if err = r.workspace.MkdirAll("runtime/source-edge"); err != nil {
		return err
	}
	dir := plainRuntimePath(filepath.Join(r.workspace.Path(), "runtime/source-edge"))
	for _, pin := range recipe.SourceDISM {
		member := "/Windows/System32/Dism/" + pin.Relative
		result, e := platform.NewRunner().Run(ctx, platform.Invocation{Executable: r.WIMLib(), Arguments: []string{"extract", plainRuntimePath(base), "1", member, "--dest-dir=" + dir, "--no-acls"}, Workspace: r.workspace, JobID: r.workspace.Identity().JobID, OperationID: "source-edge-provider", Cancellation: platform.CancelTerminateTree}, nil)
		if e != nil {
			return fmt.Errorf("extract source Edge provider (exit %d): %w", result.ExitCode, e)
		}
		f, e := os.Open(filepath.Join(dir, filepath.Base(pin.Relative)))
		if e != nil {
			return e
		}
		err = writeSelected(ctx, r.workspace, "runtime/dism/"+pin.Relative, f, pin)
		f.Close()
		if err != nil {
			return err
		}
		f, err = lockSelected(filepath.Join(filepath.Dir(r.dism), filepath.FromSlash(pin.Relative)))
		if err != nil {
			return err
		}
		r.files = append(r.files, f)
		if err = copyVerified(ctx, io.Discard, f, pin.Size, pin.SHA256); err != nil {
			return err
		}
	}
	r.sourceEdge = true
	return nil
}
func (r *SelectedRuntime) SourceEdgeReady() bool { return r != nil && r.Build() != 0 && r.sourceEdge }
func plainRuntimePath(path string) string        { return strings.TrimPrefix(path, `\\?\`) }
func writeSelected(ctx context.Context, w *platform.Workspace, path string, src io.Reader, pin selectedFile) error {
	if _, err := model.ValidateRelativePath(path); err != nil {
		return err
	}
	if err := w.MkdirAll(filepath.ToSlash(filepath.Dir(path))); err != nil {
		return err
	}
	f, err := w.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	return errors.Join(copyVerified(ctx, f, src, pin.Size, pin.SHA256), f.Sync(), f.Close())
}
func lockSelected(path string) (*os.File, error) {
	p, e := native.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := native.CreateFile(p, native.GENERIC_READ, native.FILE_SHARE_READ, nil, native.OPEN_EXISTING, native.FILE_ATTRIBUTE_NORMAL|native.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	var info native.ByHandleFileInformation
	if e = native.GetFileInformationByHandle(h, &info); e != nil || info.FileAttributes&(native.FILE_ATTRIBUTE_REPARSE_POINT|native.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		native.CloseHandle(h)
		return nil, ErrIntegrity
	}
	return os.NewFile(uintptr(h), path), nil
}
