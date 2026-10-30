package source

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/localsource"
	"uupbuilder/internal/metadata/providers"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/tools"
)

// A private opt-in source observation, never an installed-package-state claim.
func TestNativeRetainedBasePackageOffer(t *testing.T) {
	recordPath, helperRoot, packageName, destination := os.Getenv("UUP_MEDIA_BASE_RECORD"), os.Getenv("UUP_MEDIA_HELPER_CACHE"), os.Getenv("UUP_MEDIA_PARENT_PACKAGE"), os.Getenv("UUP_MEDIA_CBS_EVIDENCE_DIRECTORY")
	if recordPath == "" || helperRoot == "" || packageName == "" || destination == "" {
		t.Skip("set retained base/package/helper/evidence inputs")
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
		t.Fatalf("invalid retained base record:%v", err)
	}
	input := filepath.Join(filepath.Dir(recordPath), record.Identity.Key()+".data")
	source, initial, err := localsource.Open(input, record.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	before, err := localsource.Verify(ctx, source, input, record.Identity, initial)
	if err != nil || before != record.SHA256 {
		t.Fatalf("base source integrity:%v", err)
	}
	observed, err := (providers.WIM{}).Inspect(ctx, metadata.LocalResource{Identity: record.Identity, Path: input}, metadata.Limits{})
	if err != nil || len(observed.Documents) != 1 {
		t.Fatalf("actual WIM XML:%v", err)
	}
	text, err := decodeMediaText(string(observed.Documents[0].Original))
	if err != nil {
		t.Fatal(err)
	}
	var wim struct {
		Images []struct {
			Index   int    `xml:"INDEX,attr"`
			Name    string `xml:"NAME"`
			Windows struct {
				InstallationType string `xml:"INSTALLATIONTYPE"`
			} `xml:"WINDOWS"`
		} `xml:"IMAGE"`
	}
	if err = mediaXMLDecoder([]byte(text)).Decode(&wim); err != nil {
		t.Fatal(err)
	}
	helperFiles := mediaCacheOnlyHelpers{}
	entries, err := os.ReadDir(helperRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
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
	w, err := platform.CreateWorkspace(t.TempDir(), "native-base-observation")
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
	if err = os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(destination, "base-wim-original.xml"), observed.Documents[0].Original, 0600); err != nil {
		t.Fatal(err)
	}
	var evidence []map[string]any
	for _, image := range wim.Images {
		if image.Windows.InstallationType != "WindowsPE" {
			continue
		}
		listing, e := r.listWIMPaths(ctx, input, image.Index)
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range strings.Split(listing, "\n") {
			member := strings.ReplaceAll(strings.TrimSpace(line), `\`, "/")
			if !strings.HasPrefix(strings.ToLower(member), strings.ToLower("/Windows/servicing/Packages/"+packageName+"~")) || !strings.HasSuffix(strings.ToLower(member), ".mum") {
				continue
			}
			raw, e := r.readWIMFile(ctx, input, image.Index, member, mediaDocumentLimit)
			if e != nil {
				t.Fatal(e)
			}
			decoded, e := decodeMediaText(string(raw))
			if e != nil {
				t.Fatal(e)
			}
			var assembly struct {
				Identity struct {
					Attributes []xml.Attr `xml:",any,attr"`
				} `xml:"urn:schemas-microsoft-com:asm.v3 assemblyIdentity"`
			}
			if e = mediaXMLDecoder([]byte(decoded)).Decode(&assembly); e != nil {
				t.Fatal(e)
			}
			attributes := map[string]string{}
			for _, attribute := range assembly.Identity.Attributes {
				attributes[attribute.Name.Local] = attribute.Value
			}
			name := fmt.Sprintf("base-image-%d-%s", image.Index, filepath.Base(filepath.FromSlash(member)))
			if e = os.WriteFile(filepath.Join(destination, name), raw, 0600); e != nil {
				t.Fatal(e)
			}
			row := map[string]any{"SourcePayload": record.Identity, "SourceSHA256": before, "ImageIndex": image.Index, "ImageName": image.Name, "InstallationType": image.Windows.InstallationType, "Member": member, "Identity": attributes, "OriginalFile": name, "InstalledState": "unexamined"}
			evidence = append(evidence, row)
			t.Logf("actual source image%d %q (%s) offers%s identity%v; installed state unexamined", image.Index, image.Name, image.Windows.InstallationType, member, attributes)
		}
	}
	if len(evidence) == 0 {
		t.Fatalf("no actual base image offered requested package %s", packageName)
	}
	serialized, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(destination, "base-package-offer.json"), serialized, 0600); err != nil {
		t.Fatal(err)
	}
	after, err := localsource.Verify(ctx, source, input, record.Identity, initial)
	if err != nil || after != before {
		t.Fatalf("base source changed:%v", err)
	}
}
