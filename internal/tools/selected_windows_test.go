package tools

import (
	"context"
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
		if err = runtime.AcquireSourceEdge(context.Background(), base); err != nil {
			t.Fatal(err)
		}
		if !runtime.SourceEdgeReady() || len(runtime.files) != 197 {
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

func TestSelectedRequirementRejectsOtherSourceAndNativeHost(t *testing.T) {
	host := model.Host{WindowsBuild: 19041, NativeArchitecture: "amd64", ProcessArchitecture: "amd64"}
	source := model.SourceIdentity{UpdateID: "8f550c54-da87-45d3-89e3-0c03a6f16ae8", BuildLabel: "28000.3365", Architecture: "amd64", Language: "en-gb"}
	r, e := SelectedRequirement(host, source, strings.Repeat("a", 64))
	if e != nil || !IsSelectedRequirement(r) {
		t.Fatal(e)
	}
	source.Language = "en-us"
	if _, e = SelectedRequirement(host, source, strings.Repeat("a", 64)); e == nil {
		t.Fatal("unsupported source accepted")
	}
}
