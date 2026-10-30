package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/localsource"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/tools"
)

// Diagnostic only: retained original cache, managed cached helper, native reads.
// No network, mounts, DISM, or servicing operations are used.
func TestCheckpointRetainedSourceEvidence(t *testing.T) {
	records, helperRoot, output := os.Getenv("UUP_CHECKPOINT_RECORDS"), os.Getenv("UUP_MEDIA_HELPER_CACHE"), os.Getenv("UUP_CHECKPOINT_OUTPUT")
	if records == "" || helperRoot == "" || output == "" {
		t.Skip("set retained records, helper cache, and diagnostic output directory")
	}
	ctx := context.Background()
	type retained struct {
		Identity model.PayloadIdentity `json:"identity"`
		SHA256   string                `json:"sha256"`
	}
	helpers := mediaCacheOnlyHelpers{}
	entries, err := os.ReadDir(helperRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if path.Ext(entry.Name()) != ".json" {
			continue
		}
		var cached retained
		body, err := os.ReadFile(filepath.Join(helperRoot, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(body, &cached) != nil || cached.Identity.Validate() != nil || cached.SHA256 == "" {
			continue
		}
		helpers[cached.Identity] = download.CachedFile{Identity: cached.Identity, SHA256: cached.SHA256, Path: filepath.Join(helperRoot, cached.Identity.Key()+".data")}
	}
	w, err := platform.CreateWorkspace(t.TempDir(), "checkpoint-evidence")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	runtime, err := tools.AcquireSelected(ctx, w, helpers, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	for _, recordPath := range filepath.SplitList(records) {
		var record retained
		body, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &record); err != nil || record.Identity.Validate() != nil {
			t.Fatalf("invalid retained source: %v", err)
		}
		input := filepath.Join(filepath.Dir(recordPath), record.Identity.Key()+".data")
		src, initial, err := localsource.Open(input, record.Identity)
		if err != nil {
			t.Fatal(err)
		}
		before, err := localsource.Verify(ctx, src, input, record.Identity, initial)
		if err != nil || before != record.SHA256 {
			src.Close()
			t.Fatalf("source integrity before: %v", err)
		}
		root := "inspect-" + record.Identity.Key()
		if err := w.MkdirAll(root); err != nil {
			src.Close()
			t.Fatal(err)
		}
		r := mediaNativeRun{inspector: NativeInspector{Workspace: w, WIMLib: runtime.WIMLib()}, root: root, created: []string{root}}
		listing, err := r.run(ctx, runtime.WIMLib(), "dir", input, "1")
		if err != nil {
			src.Close()
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(output, record.Identity.Provenance.Name+".listing.txt"), []byte(listing.Stdout), 0600); err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(listing.Stdout, "\n") {
			member := strings.ReplaceAll(strings.TrimSpace(line), `\`, "/")
			if !strings.HasPrefix(member, "/") {
				continue
			}
			if strings.EqualFold(path.Base(member), "onepackage.AggregatedMetadata.cab") || strings.EqualFold(path.Base(member), "wsusscan.cab") {
				file, _, err := r.extractWIMFile(ctx, input, 1, member, mediaDocumentLimit)
				if err != nil {
					src.Close()
					t.Fatal(err)
				}
				body, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(output, record.Identity.Provenance.Name+"."+path.Base(member)), body, 0600); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if !strings.EqualFold(path.Ext(member), ".wim") || os.Getenv("UUP_CHECKPOINT_METADATA_ONLY") != "" {
				continue
			}
			nested, _, err := r.extractWIMFile(ctx, input, 1, member, mediaStagingLimit)
			if err != nil {
				src.Close()
				t.Fatal(err)
			}
			cbs, err := r.readWIMFile(ctx, nested, 1, "/update.mum", mediaDocumentLimit)
			if err != nil {
				src.Close()
				t.Fatal(err)
			}
			name := record.Identity.Provenance.Name + "." + path.Base(member) + ".update.mum"
			if err := os.WriteFile(filepath.Join(output, name), cbs, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(cbs)
			t.Logf("source=%s payload-sha256=%s member=%s/update.mum bytes=%d document-sha256=%x", record.Identity.Provenance.Name, before, member, len(cbs), sum)
		}
		after, err := localsource.Verify(ctx, src, input, record.Identity, initial)
		src.Close()
		if err != nil || after != before {
			t.Fatalf("source integrity after: %v", err)
		}
		for i := len(r.created) - 1; i >= 0; i-- {
			if err := w.Remove(r.created[i]); err != nil {
				t.Fatal(fmt.Errorf("cleanup %s: %w", r.created[i], err))
			}
		}
	}
}

// Reuses the original native-read CBS bytes from the diagnostic above. It does
// not need to repeat 5 GiB of cache hashing/extraction for binder-only changes.
func TestCheckpointRetainedCBSRelationships(t *testing.T) {
	root := os.Getenv("UUP_CHECKPOINT_CBS_DIRECTORY")
	if root == "" {
		t.Skip("set retained original CBS diagnostic directory")
	}
	inv := checkpointFixture(t, "10.0.26100.1")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".update.mum") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		text, err := decodeMediaText(string(body))
		if err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Identity mediaCBSIdentity `xml:"urn:schemas-microsoft-com:asm.v3 assemblyIdentity"`
			Package  struct {
				ID      string `xml:"identifier,attr"`
				Release string `xml:"releaseType,attr"`
			} `xml:"urn:schemas-microsoft-com:asm.v3 package"`
		}
		if err := mediaXMLDecoder([]byte(text)).Decode(&parsed); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		ref := metadata.DocumentReference{Resource: metadata.ResourceReference{Payload: inv.Manifest.Payloads[0].Identity, Member: entry.Name()}, SHA256: hex.EncodeToString(sum[:])}
		evidence := metadata.Evidence{Source: inv.Source, Document: ref, Selector: "/assembly/assemblyIdentity"}
		id := parsed.Identity.identity()
		inv.Documents = append(inv.Documents, metadata.Document{Reference: ref, Format: metadata.FormatCBSXML, Original: body})
		inv.Packages = append(inv.Packages, metadata.Package{Identity: id, Identifier: parsed.Package.ID, ReleaseType: parsed.Package.Release, Evidence: evidence})
		inv.Updates = append(inv.Updates, metadata.Update{ID: parsed.Package.ID, Kind: metadata.UpdateCumulative, Packages: []metadata.PackageIdentity{id}, Evidence: evidence})
	}
	if len(inv.Updates) != 2 {
		t.Fatalf("expected two retained original CBS documents, observed %d", len(inv.Updates))
	}
	if err := bindMediaUpdateRelationships(&inv); err != nil {
		t.Fatal(err)
	}
	edges := 0
	for _, update := range inv.Updates {
		edges += len(update.Predecessors)
		t.Logf("original CBS update %s %+v: predecessors %v; editions %v", update.ID, update.Packages, update.Predecessors, update.Editions)
	}
	if edges != 1 {
		t.Fatalf("actual checkpoint pair should establish exactly one baseline predecessor, observed %d", edges)
	}
}
