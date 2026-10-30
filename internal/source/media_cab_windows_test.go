package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/localsource"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

func TestNativeCBSExtractionFromVerifiedCacheNames(t *testing.T) {
	for _, multiple := range []bool{false, true} {
		name := "single-member"
		if multiple {
			name = "multiple-members"
		}
		t.Run(name, func(t *testing.T) {
			body := []byte(`<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"><assemblyIdentity name="Example.Base.Package" version="1.0.0.0" processorArchitecture="amd64"/></assembly>`)
			members := map[string][]byte{"update.mum": body}
			if multiple {
				members["other.bin"] = []byte("unselected source bytes")
			}
			raw := sourceTestCAB(members)
			sum := sha256.Sum256(raw)
			id := model.PayloadIdentity{Size: int64(len(raw)), Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, Provenance: model.PackageProvenance{Source: "native-regression", Name: "source.cab"}}
			input := filepath.Join(t.TempDir(), "verified-cache.data")
			if err := os.WriteFile(input, raw, 0600); err != nil {
				t.Fatal(err)
			}
			workspace, err := platform.CreateWorkspace(t.TempDir(), "native-cbs-regression")
			if err != nil {
				t.Fatal(err)
			}
			defer workspace.Close()
			if err = workspace.MkdirAll("inspect"); err != nil {
				t.Fatal(err)
			}
			r := mediaNativeRun{inspector: NativeInspector{Workspace: workspace}, root: "inspect", created: []string{"inspect"}}
			defer func() {
				for i := len(r.created) - 1; i >= 0; i-- {
					workspace.Remove(r.created[i])
				}
			}()
			docs, err := r.cabCBS(context.Background(), id, input, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(docs) != 1 || docs[0].Resource.Payload != id || docs[0].Resource.Member != "update.mum" || !bytes.Equal(docs[0].Original, body) {
				t.Fatalf("CBS bytes or source binding changed: %+v", docs)
			}
		})
	}
}

type failedMediaInspectorRunner struct{}

func (failedMediaInspectorRunner) Run(context.Context, platform.Invocation, model.Emit) (platform.RunResult, error) {
	text := "[ERROR] Requested path does not exist in this image"
	units := utf16.Encode([]rune(text))
	body := make([]byte, 2+len(units)*2)
	body[0] = 0xff
	body[1] = 0xfe
	for i, u := range units {
		binary.LittleEndian.PutUint16(body[2+i*2:], u)
	}
	return platform.RunResult{ExitCode: 47, Stderr: string(body)}, &platform.ProcessExitError{Code: 47}
}

func TestNativeInspectionFailureRetainsDecodedHelperAndMemberContext(t *testing.T) {
	w, err := platform.CreateWorkspace(t.TempDir(), "native-error-regression")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r := mediaNativeRun{inspector: NativeInspector{Workspace: w, WIMLib: `C:\managed\wimlib-imagex.exe`, runner: failedMediaInspectorRunner{}}}
	_, _, err = r.wimFileRecord(context.Background(), `C:\cache\verified.data`, 1, "/update.mum")
	var exit *platform.ProcessExitError
	if err == nil || !strings.Contains(err.Error(), "wimlib-imagex.exe") || !strings.Contains(err.Error(), "dir") || !strings.Contains(err.Error(), "/update.mum") || !strings.Contains(err.Error(), "Requested path does not exist") || !errors.As(err, &exit) || exit.Code != 47 {
		t.Fatalf("lost source/native error context: %v", err)
	}
}

func TestNativeInspectionArgumentsKeepCustodyPathsOutOfToolParser(t *testing.T) {
	args := []string{"dir", `\\?\C:\owned\source.wim`, "1", `--ref=\\?\C:\owned\ref.esd`, `--dest-dir=\\?\C:\owned\stage`, `--ref=\\?\UNC\server\share\ref.wim`, `--path=/Windows/System32/file.exe`}
	got := mediaProcessArguments(args)
	want := []string{"dir", `C:\owned\source.wim`, "1", `--ref=C:\owned\ref.esd`, `--dest-dir=C:\owned\stage`, `--ref=\\server\share\ref.wim`, `--path=/Windows/System32/file.exe`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("process arguments=%q want%q", got, want)
	}
	if !strings.HasPrefix(args[1], `\\?\`) {
		t.Fatal("borrowed custody path mutated")
	}
}

func TestNativeCBSRetainedCABMetadata(t *testing.T) {
	recordPath := os.Getenv("UUP_MEDIA_CBS_CAB_RECORD")
	if recordPath == "" {
		t.Skip("set UUP_MEDIA_CBS_CAB_RECORD to an original retained cache identity record")
	}
	body, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Identity model.PayloadIdentity `json:"identity"`
		SHA256   string                `json:"sha256"`
	}
	if err = json.Unmarshal(body, &record); err != nil || record.Identity.Validate() != nil {
		t.Fatalf("invalid retained record: %v", err)
	}
	file := filepath.Join(filepath.Dir(recordPath), record.Identity.Key()+".data")
	source, initial, err := localsource.Open(file, record.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	before, err := localsource.Verify(context.Background(), source, file, record.Identity, initial)
	if err != nil || before != record.SHA256 {
		t.Fatalf("retained source integrity: %v", err)
	}
	workspace, err := platform.CreateWorkspace(t.TempDir(), "retained-cbs-regression")
	if err != nil {
		t.Fatal(err)
	}
	defer workspace.Close()
	if err = workspace.MkdirAll("inspect"); err != nil {
		t.Fatal(err)
	}
	r := mediaNativeRun{inspector: NativeInspector{Workspace: workspace}, root: "inspect", created: []string{"inspect"}}
	defer func() {
		for i := len(r.created) - 1; i >= 0; i-- {
			workspace.Remove(r.created[i])
		}
	}()
	docs, err := r.cabCBS(context.Background(), record.Identity, file, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 || docs[0].Resource.Payload != record.Identity || docs[0].Resource.Member != "update.mum" {
		t.Fatalf("actual CBS source binding differs: %+v", docs)
	}
	sum := sha256.Sum256(docs[0].Original)
	t.Logf("actual source %s: retained %d CBS bytes, SHA256 %x", record.Identity.Provenance.Name, len(docs[0].Original), sum)
	if destination := os.Getenv("UUP_MEDIA_CBS_EVIDENCE_DIRECTORY"); destination != "" {
		if !filepath.IsAbs(destination) {
			t.Fatal("absolute private evidence destination required")
		}
		if err = os.MkdirAll(destination, 0700); err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(record.Identity.Provenance.Name, filepath.Ext(record.Identity.Provenance.Name)) + ".update.mum"
		if clean, e := model.ValidateRelativePath(name); e != nil || clean != name || strings.ContainsAny(name, `/\`) {
			t.Fatal("invalid evidence filename")
		}
		if err = os.WriteFile(filepath.Join(destination, name), docs[0].Original, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Use a synthetic source envelope for this container-only observation, not
	// a claim about a complete selected OS source or a servicing acceptance run.
	m, err := model.NewPayloadManifest(sourceIdentity(), []model.Payload{{Identity: record.Identity, Destination: "retained-source.cab"}})
	if err != nil {
		t.Fatal(err)
	}
	inv := metadata.Inventory{Source: m.Source, Manifest: m}
	if err = r.addCBS(context.Background(), &inv, record.Identity, file, docs, false); err != nil {
		t.Fatal(err)
	}
	for _, pack := range inv.Packages {
		t.Logf("actual CBS identity %s release %q", pack.Identity.Name, pack.ReleaseType)
	}
	if expected := os.Getenv("UUP_MEDIA_EXPECT_UPDATE_KIND"); expected != "" {
		if len(inv.Updates) != 1 || string(inv.Updates[0].Kind) != expected {
			t.Fatalf("actual CBS update classification=%+v, expected%q", inv.Updates, expected)
		}
	}
	if expected := os.Getenv("UUP_MEDIA_EXPECT_UPDATE_TARGET"); expected != "" {
		if len(inv.Updates) != 1 || string(inv.Updates[0].Target) != expected {
			t.Fatalf("actual CBS update target=%+v expected%q", inv.Updates, expected)
		}
		if err = bindMediaUpdateRelationships(&inv); err != nil {
			t.Fatalf("recovery scope incorrectly reached OS prerequisite binding:%v", err)
		}
	}
	after, err := localsource.Verify(context.Background(), source, file, record.Identity, initial)
	if err != nil || after != before {
		t.Fatalf("retained source changed after native extraction: %v", err)
	}
}
