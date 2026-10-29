package wimindex

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// Private source bytes and locators are never copied into product resources.
// Configuration is mandatory for actual evidence; an ordinary skipped run is
// never reported as successful actual inspection.
func TestPreparedSourceResourceIndex(t *testing.T) {
	root := os.Getenv("UUP_WIM_INDEX_PREPARED_ROOT")
	if root == "" {
		t.Skip("exact prepared input descriptor not configured")
	}
	var prepared struct {
		Manifest model.PayloadManifest
		Files    []struct {
			Path, SHA256 string
			Identity     model.PayloadIdentity
		}
	}
	body, err := os.ReadFile(filepath.Join(root, "actual-preparation", "prepared-source.json"))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(body, &prepared) != nil {
		t.Fatal("invalid private descriptor")
	}
	m := prepared.Manifest
	if m.Validate() != nil || m.Digest != "675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9" || m.Source != (model.SourceIdentity{UpdateID: "3d12aa3e-806a-46c9-900e-bf7613959273", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}) || len(m.Payloads) != 40 {
		t.Fatal("prepared manifest identity changed")
	}
	var expected []struct {
		Name   string `json:"name"`
		SHA256 string `json:"input_sha256"`
		Size   int64  `json:"size"`
	}
	body, err = os.ReadFile(filepath.Join(root, "task-6-prepared-wim-headers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(body, &expected) != nil || len(expected) != 13 {
		t.Fatal("header census identity changed")
	}
	var files []metadata.LocalResource
	for _, e := range expected {
		found := 0
		for _, f := range prepared.Files {
			if f.Identity.Provenance.Name == e.Name {
				if f.Identity.Size != e.Size || f.SHA256 != e.SHA256 || f.Identity.Digest != (model.Digest{Algorithm: model.DigestSHA256, Value: e.SHA256}) {
					t.Fatal("prepared/census identity mismatch")
				}
				files = append(files, metadata.LocalResource{Identity: f.Identity, Path: f.Path})
				found++
			}
		}
		if found != 1 {
			t.Fatalf("missing or duplicate prepared reference: %s", e.Name)
		}
	}
	idx, err := Open(context.Background(), m, files, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	s := idx.Snapshot()
	type shape struct {
		Kind                                             string
		Flags                                            byte
		Compression, ChunkSize                           uint32
		Count                                            int
		PhysicalMin, PhysicalMax, LogicalMin, LogicalMax uint64
	}
	type summary struct {
		Payload                                                 model.PayloadIdentity
		SHA256                                                  string
		Rehashed                                                bool
		GUID                                                    string
		HeaderFlags                                             uint32
		HeaderChunkSize                                         uint32
		BootIndex                                               uint32
		Entries, Metadata, Ordinary, SolidResources, SolidBlobs int
		Images                                                  []Image
		MappingComplete                                         bool
		Shapes                                                  []shape
		ResourceDescriptors                                     []Entry
	}
	report := struct {
		ManifestDigest, IndexDigest                                                    string
		Containers                                                                     []summary
		Entries, Metadata, Ordinary, SolidResources, SolidBlobs, UniqueSHA1, Witnesses int
		Complete, ContentVerified, ConversionSupported                                 bool
		Gaps                                                                           []Gap
	}{ManifestDigest: m.Digest, IndexDigest: idx.Digest(), Complete: s.Complete, ContentVerified: s.ContentVerified, ConversionSupported: s.ConversionSupported, Gaps: s.Gaps}
	selected := false
	for _, c := range s.Containers {
		row := summary{Payload: c.Payload, SHA256: c.SourceSHA256, Rehashed: c.SourceRehashed, GUID: c.Header.GUID, HeaderFlags: c.Header.Flags, HeaderChunkSize: c.Header.ChunkSize, BootIndex: c.Header.BootIndex, Entries: len(c.Entries), Images: c.Images, MappingComplete: c.MappingComplete}
		shapes := map[string]shape{}
		for _, e := range c.Entries {
			if e.Kind == "metadata" || e.Kind == "solid-resource" {
				row.ResourceDescriptors = append(row.ResourceDescriptors, e)
			}
			if e.Located {
				key := fmt.Sprintf("%s/%02x/%d/%d", e.Kind, e.Descriptor.Flags, e.Location.Compression, e.Location.ChunkSize)
				v, ok := shapes[key]
				if !ok {
					v = shape{Kind: e.Kind, Flags: e.Descriptor.Flags, Compression: e.Location.Compression, ChunkSize: e.Location.ChunkSize, PhysicalMin: e.Location.PhysicalSize, LogicalMin: e.LogicalSize}
				}
				v.Count++
				v.PhysicalMin = min(v.PhysicalMin, e.Location.PhysicalSize)
				v.PhysicalMax = max(v.PhysicalMax, e.Location.PhysicalSize)
				v.LogicalMin = min(v.LogicalMin, e.LogicalSize)
				v.LogicalMax = max(v.LogicalMax, e.LogicalSize)
				shapes[key] = v
			}
			switch e.Kind {
			case "metadata":
				row.Metadata++
			case "ordinary":
				row.Ordinary++
			case "solid-resource":
				row.SolidResources++
			case "solid-blob":
				row.SolidBlobs++
			}
		}
		var keys []string
		for key := range shapes {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			row.Shapes = append(row.Shapes, shapes[key])
		}
		if !row.Rehashed {
			t.Fatal("source final rehash absent")
		}
		if c.Payload.Provenance.Name == "professional_en-us.esd" {
			if c.Payload.Size != 338670400 || c.SourceSHA256 != "edf4967f0d9f8b8703d24489f727786cd314c43a26cfdc111e5d3b8e40d13dc0" {
				t.Fatal("selected source identity changed")
			}
			for _, im := range c.Images {
				if im.Index == 3 {
					if im.Architecture != "0" || im.Edition != "Professional" || im.InstallationType != "Client" || im.Version != "10.0.19041.1" || im.MetadataEntry == 0 || !c.MappingComplete {
						t.Fatalf("selected XML/table association unresolved: %+v", im)
					}
					selected = true
				}
			}
		}
		report.Containers = append(report.Containers, row)
		report.Entries += row.Entries
		report.Metadata += row.Metadata
		report.Ordinary += row.Ordinary
		report.SolidResources += row.SolidResources
		report.SolidBlobs += row.SolidBlobs
		t.Logf("container=%s sha256=%s entries=%d metadata=%d ordinary=%d solid-resources=%d solid-blobs=%d boot=%d mapping=%v rehashed=%v", c.Payload.Provenance.Name, c.SourceSHA256, row.Entries, row.Metadata, row.Ordinary, row.SolidResources, row.SolidBlobs, row.BootIndex, row.MappingComplete, row.Rehashed)
	}
	if len(s.Containers) != 13 || !selected {
		t.Fatal("actual selection was not inspected")
	}
	for _, w := range idx.witnesses {
		report.UniqueSHA1++
		report.Witnesses += len(w)
	}
	t.Logf("index-sha256=%s containers=%d entries=%d metadata=%d ordinary=%d solid-resources=%d solid-blobs=%d unique-SHA1=%d witnesses=%d gaps=%d complete=%v content-verified=%v conversion-supported=%v", idx.Digest(), len(s.Containers), report.Entries, report.Metadata, report.Ordinary, report.SolidResources, report.SolidBlobs, report.UniqueSHA1, report.Witnesses, len(s.Gaps), s.Complete, s.ContentVerified, s.ConversionSupported)
	for _, g := range s.Gaps {
		t.Logf("gap=%s entry=%d capability=%s", g.Payload.Provenance.Name, g.Entry, g.Capability)
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 256<<10 {
		t.Fatal("private summary exceeds bounded report")
	}
	if err := os.WriteFile(filepath.Join(root, "task-6b1-actual-index.json"), append(out, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
