package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	native "golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uupbuilder/internal/download"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

type selectedLocalFetcher string

func (s selectedLocalFetcher) FetchOne(ctx context.Context, p model.Payload, _ model.Locator, _ model.Emit) (download.CachedFile, error) {
	path := filepath.Join(string(s), p.Identity.Provenance.Name)
	if p.Identity.Provenance.Name == "wimlib.zip" {
		path = filepath.Join(string(s), "wimlib/wimlib-1.14.5-windows-x86_64-bin.zip")
	}
	return download.CachedFile{Path: path, Identity: p.Identity, SHA256: p.Identity.Digest.Value}, nil
}
func TestSelectedActualRuntimeAcquisition(t *testing.T) {
	dir := os.Getenv("UUP_SELECTED_TOOL_INPUTS")
	if dir == "" {
		t.Skip("set UUP_SELECTED_TOOL_INPUTS to actual acquired archives")
	}
	w, err := platform.CreateWorkspace(t.TempDir(), "selected-runtime")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	runtime, err := AcquireSelected(context.Background(), w, selectedLocalFetcher(dir), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if len(runtime.files) != 195 || runtime.Build() != 28000 {
		t.Fatal("runtime incomplete")
	}
	if base := os.Getenv("UUP_SELECTED_SOURCE_WIM"); base != "" {
		if err = runtime.AcquireSourceEdge(context.Background(), observedSourceImage(t, base)); err != nil {
			t.Fatal(err)
		}
		if !runtime.SourceEdgeReady() || len(runtime.files) != 199 {
			t.Fatal("source provider lease incomplete")
		}
	}
	result, err := platform.NewRunner().Run(context.Background(), platform.Invocation{Executable: runtime.WIMLib(), Arguments: []string{"--version"}, Workspace: w, JobID: w.Identity().JobID, OperationID: "inspect-runtime", Cancellation: platform.CancelTerminateTree}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pinned runtime files=%d, wimlib exit=%d; DISM servicing not executed", len(runtime.files), result.ExitCode)
}

func TestSelectedRecipePinsWholeRuntime(t *testing.T) {
	recipe, err := selectedRecipe()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipe.Cabinets) != 7 || len(recipe.DISM) != 189 || len(recipe.WIMLib) != 6 {
		t.Fatalf("incomplete recipe: %d/%d/%d", len(recipe.Cabinets), len(recipe.DISM), len(recipe.WIMLib))
	}
	names := map[string]bool{}
	for _, file := range recipe.DISM {
		if names[strings.ToLower(file.Relative)] || !validSHA(file.SHA256) || file.Size < 1 {
			t.Fatal("invalid pin", file)
		}
		names[strings.ToLower(file.Relative)] = true
	}
	if !names["dism.exe"] {
		t.Fatal("missing DISM")
	}
	if SelectedRecipeDigest() == "" {
		t.Fatal("recipe not bound")
	}
}

func TestSelectedRequirementKeepsNativeHostConstraint(t *testing.T) {
	host := model.Host{WindowsBuild: 19041, NativeArchitecture: "amd64", ProcessArchitecture: "amd64"}
	source := model.SourceIdentity{UpdateID: "8f550c54-da87-45d3-89e3-0c03a6f16ae8", BuildLabel: "28000.3365", Architecture: "amd64", Language: "en-gb"}
	r, e := SelectedRequirement(host, source, strings.Repeat("a", 64))
	if e != nil || !IsSelectedRequirement(r) {
		t.Fatal(e)
	}
	host.NativeArchitecture = "arm64"
	if _, e = SelectedRequirement(host, source, strings.Repeat("a", 64)); e == nil {
		t.Fatal("unsupported native host accepted")
	}
}

func TestManagedRequirementBindsAnySourceWithoutWideningNativeCapabilities(t *testing.T) {
	host := model.Host{WindowsBuild: 19041, NativeArchitecture: "amd64", ProcessArchitecture: "amd64"}
	source := model.SourceIdentity{UpdateID: "independent-source", BuildLabel: "26300.9818", Architecture: "amd64", Language: "en-us"}
	requirement, err := SelectedRequirement(host, source, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if requirement.Source != source || !IsSelectedRequirement(requirement) {
		t.Fatal("source identity was altered")
	}
	for _, change := range []func(*Requirement){func(r *Requirement) { r.Host.NativeArchitecture = "arm64" }, func(r *Requirement) { r.Target = "arm64"; r.Source.Architecture = "arm64" }, func(r *Requirement) { r.SourceManifestDigest = "" }} {
		other := requirement
		change(&other)
		if IsSelectedRequirement(other) {
			t.Fatal("unimplemented native capability or unbound source accepted")
		}
	}
}

func TestSourceImageLeaseBindsObservedBytesAndStaysImmutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "base.wim")
	body := []byte("verified predecessor content")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	image := SourceImage{Path: path, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), Architecture: model.ArchitectureAMD64}
	wrong := image
	wrong.SHA256 = strings.Repeat("a", 64)
	if f, err := lockSourceImage(context.Background(), wrong); err == nil {
		f.Close()
		t.Fatal("unverified predecessor accepted")
	}
	f, err := lockSourceImage(context.Background(), image)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = os.WriteFile(path, []byte("replacement"), 0600); err == nil {
		t.Fatal("verified predecessor was mutable during extraction")
	}
	wrong = image
	wrong.Architecture = model.ArchitectureARM64
	if f, err := lockSourceImage(context.Background(), wrong); err == nil {
		f.Close()
		t.Fatal("arm64 source provider accepted by amd64 runtime")
	}
}

func observedSourceImage(t *testing.T, path string) SourceImage {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		t.Fatal(err)
	}
	return SourceImage{Path: path, Size: size, SHA256: hex.EncodeToString(h.Sum(nil)), Architecture: model.ArchitectureAMD64}
}
func TestSourceProviderObservationMeasuresVersionAndEnforcesSignatureAndArchitecture(t *testing.T) {
	system, err := native.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(system, "kernel32.dll")
	f, err := lockSelected(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pin, err := observeSourceProvider(context.Background(), f, "EdgeProvider.dll")
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if pin.Size != info.Size() || !validSHA(pin.SHA256) || !strings.HasPrefix(pin.Version, "10.0.") {
		t.Fatalf("provider observations missing: %+v", pin)
	}
	// A Go test executable is not a source DLL, regardless of its filename.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := lockSelected(self)
	if err != nil {
		t.Fatal(err)
	}
	defer invalid.Close()
	if _, err = observeSourceProvider(context.Background(), invalid, "EdgeProvider.dll"); err == nil {
		t.Fatal("non-DLL provider accepted")
	}
}

func TestSourceProviderRejectsChangedCodeSignature(t *testing.T) {
	system, err := native.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(system, "kernel32.dll"))
	if err != nil {
		t.Fatal(err)
	}
	binary, err := pe.NewFile(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(binary.Sections) == 0 {
		t.Fatal("no code section")
	}
	position := int(binary.Sections[0].Offset) + 32
	if position >= len(body) {
		t.Fatal("invalid code section bounds")
	}
	body[position] ^= 0xff
	path := filepath.Join(t.TempDir(), "EdgeProvider.dll")
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := lockSelected(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = observeSourceProvider(context.Background(), f, "EdgeProvider.dll"); err == nil {
		t.Fatal("modified provider code retained signature trust")
	}
}
