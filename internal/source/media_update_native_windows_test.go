package source

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata/localsource"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/tools"
)

type mediaCacheOnlyHelpers map[model.PayloadIdentity]download.CachedFile

func (f mediaCacheOnlyHelpers) FetchOne(_ context.Context, p model.Payload, _ model.Locator, _ model.Emit) (download.CachedFile, error) {
	if file, ok := f[p.Identity]; ok {
		return file, nil
	}
	return download.CachedFile{}, fmt.Errorf("cache-only helper missing %s", p.Identity.Provenance.Name)
}

// This opt-in uses the normal pinned managed acquisition route with retained
// helper bytes only. It neither downloads nor services/mounts an image.
func TestNativeRetainedNestedUpdateWIM(t *testing.T) {
	recordPath, helperRoot := os.Getenv("UUP_MEDIA_UPDATE_RECORD"), os.Getenv("UUP_MEDIA_HELPER_CACHE")
	if recordPath == "" || helperRoot == "" {
		t.Skip("set retained update identity record and managed helper cache")
	}
	ctx := context.Background()
	var record struct {
		Identity model.PayloadIdentity `json:"identity"`
		SHA256   string                `json:"sha256"`
	}
	body, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(body, &record); err != nil || record.Identity.Validate() != nil {
		t.Fatalf("invalid retained update identity: %v", err)
	}
	input := filepath.Join(filepath.Dir(recordPath), record.Identity.Key()+".data")
	source, initial, err := localsource.Open(input, record.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	before, err := localsource.Verify(ctx, source, input, record.Identity, initial)
	if err != nil || before != record.SHA256 {
		t.Fatalf("actual update integrity: %v", err)
	}
	helperFiles := mediaCacheOnlyHelpers{}
	entries, err := os.ReadDir(helperRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if path.Ext(entry.Name()) != ".json" {
			continue
		}
		var cached struct {
			Identity model.PayloadIdentity `json:"identity"`
			SHA256   string                `json:"sha256"`
		}
		raw, e := os.ReadFile(filepath.Join(helperRoot, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if json.Unmarshal(raw, &cached) != nil || cached.Identity.Validate() != nil || cached.SHA256 == "" {
			continue
		}
		helperFiles[cached.Identity] = download.CachedFile{Identity: cached.Identity, SHA256: cached.SHA256, Path: filepath.Join(helperRoot, cached.Identity.Key()+".data")}
	}
	w, err := platform.CreateWorkspace(t.TempDir(), "native-update-regression")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	runtime, err := tools.AcquireSelected(ctx, w, helperFiles, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err = w.MkdirAll("inspect"); err != nil {
		t.Fatal(err)
	}
	r := mediaNativeRun{inspector: NativeInspector{Workspace: w, WIMLib: runtime.WIMLib()}, root: "inspect", created: []string{"inspect"}}
	defer func() {
		for i := len(r.created) - 1; i >= 0; i-- {
			w.Remove(r.created[i])
		}
	}()
	listing, err := r.run(ctx, runtime.WIMLib(), "dir", input, "1")
	if err != nil {
		t.Fatal(err)
	}
	var members []string
	for _, line := range strings.Split(listing.Stdout, "\n") {
		member := strings.ReplaceAll(strings.TrimSpace(line), `\`, "/")
		if strings.HasPrefix(member, "/") && strings.EqualFold(path.Ext(member), ".wim") {
			members = append(members, member)
		}
	}
	if len(members) != 1 {
		t.Fatalf("narrow test requires one observed nested update WIM: %v", members)
	}
	nested, _, err := r.extractWIMFile(ctx, input, 1, members[0], mediaStagingLimit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual nested update source %s member %s extracted to %q", record.Identity.Provenance.Name, members[0], nested)
	cbs, err := r.readWIMFile(ctx, nested, 1, "/update.mum", mediaDocumentLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(cbs) == 0 {
		t.Fatal("actual nested CBS document missing")
	}
	t.Logf("actual nested update contains %d original CBS bytes", len(cbs))
	after, err := localsource.Verify(ctx, source, input, record.Identity, initial)
	if err != nil || after != before {
		t.Fatalf("actual update source changed: %v", err)
	}
}
