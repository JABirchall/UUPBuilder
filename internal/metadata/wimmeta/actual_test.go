package wimmeta

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/model"
)

// Configured source evidence is integration proof; a skip is not a pass.
func TestPreparedNestedMetadataOracle(t *testing.T) {
	root := os.Getenv("UUP_WIM_ORACLE_PREPARED_ROOT")
	if root == "" {
		t.Skip("exact private prepared source descriptor not configured")
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
	if err := json.Unmarshal(body, &prepared); err != nil {
		t.Fatal(err)
	}
	m := prepared.Manifest
	if m.Validate() != nil || m.Digest != "675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9" || m.Source != (model.SourceIdentity{UpdateID: "3d12aa3e-806a-46c9-900e-bf7613959273", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}) {
		t.Fatal("exact selected source changed")
	}
	var original struct {
		ManifestDigest, IndexDigest string
		Containers                  []struct {
			Payload model.PayloadIdentity
			SHA256  string
		}
	}
	body, err = os.ReadFile(filepath.Join(root, "task-6b1-actual-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &original); err != nil {
		t.Fatal(err)
	}
	if original.ManifestDigest != m.Digest || original.IndexDigest != "ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a" || len(original.Containers) != 13 {
		t.Fatal("original index changed")
	}
	var files []metadata.LocalResource
	for _, c := range original.Containers {
		found := false
		for _, f := range prepared.Files {
			if f.Identity == c.Payload {
				if found || f.SHA256 != c.SHA256 {
					t.Fatal("duplicate/changed source witness")
				}
				found = true
				files = append(files, metadata.LocalResource{Identity: f.Identity, Path: f.Path})
			}
		}
		if !found {
			t.Fatal("original source missing")
		}
	}
	idx, err := wimindex.Open(context.Background(), m, files, wimindex.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if idx.Digest() != original.IndexDigest {
		t.Fatal("original index not reproduced")
	}
	// Regenerate private verified artifacts from original source bytes. Retained
	// research copies/receipts never establish authority for the production API.
	as, err := wimindex.DecodeMetadata(context.Background(), m, files, idx, wimindex.DecodeLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, a := range as {
			if err := a.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	if len(as) != 15 {
		t.Fatal("wrong artifact count", len(as))
	}
	type observed struct {
		Receipt   wimindex.MetadataReceipt
		Digest    string
		Summary   Summary
		Complete  bool
		GapCounts []struct {
			Kind  string
			Count int
		}
		Gaps                 []Gap
		UnresolvedReferences []Reference
		UnresolvedUses       []struct {
			Entry, Stream      int
			Path, Kind, SHA1   string
			Offset, HardlinkID uint64
			Attributes         uint32
		}
		MissingWitnesses []struct {
			Entry        Entry
			Raw          []byte
			GroupMembers []int
		}
		TagWitnesses []struct {
			Path   string
			Offset uint64
			Tag    Tag
		}
		TagCounts []struct {
			Tag   uint32
			Count int
		}
		FinalArtifact struct {
			SHA1, SHA256 string
			Size         int64
		}
		Witnesses          []Entry
		SecurityWitness    *Security
		CallbackSecurityID int
		CallbackWitness    *Security
		HardlinkWitness    *HardlinkGroup
		Failure            string
	}
	report := struct {
		ManifestDigest, IndexDigest string
		Resources                   []observed
		FinalSources                []struct {
			Payload model.PayloadIdentity
			SHA256  string
			Size    int64
		}
		ContentVerified, ConversionSupported bool
	}{ManifestDigest: m.Digest, IndexDigest: idx.Digest()}
	selected := false
	passed := 0
	for _, a := range as {
		r := a.Receipt()
		o, err := Parse(context.Background(), a, idx, Limits{})
		row := observed{Receipt: r}
		if err != nil {
			row.Failure = err.Error()
			report.Resources = append(report.Resources, row)
			t.Errorf("metadata=%s image=%d interpretation failed: %v", r.Payload.Provenance.Name, r.Entry.ImageIndex, err)
			continue
		}
		s := &o.state
		row.Digest = o.Digest()
		row.Summary = o.Summary()
		row.Complete = s.Complete
		row.Gaps = s.Gaps
		h1, h256 := sha1.New(), sha256.New()
		n, hashErr := io.CopyBuffer(io.MultiWriter(h1, h256), io.NewSectionReader(a, 0, int64(r.Size)), make([]byte, 64<<10))
		row.FinalArtifact.SHA1 = hex.EncodeToString(h1.Sum(nil))
		row.FinalArtifact.SHA256 = hex.EncodeToString(h256.Sum(nil))
		row.FinalArtifact.Size = n
		if hashErr != nil || uint64(n) != r.Entry.LogicalSize || row.FinalArtifact.SHA1 != r.Entry.SHA1 || row.FinalArtifact.SHA256 != r.SHA256 {
			t.Fatal("independent final artifact hash failed", hashErr)
		}
		counts := map[string]int{}
		for _, g := range s.Gaps {
			counts[g.Kind]++
		}
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			row.GapCounts = append(row.GapCounts, struct {
				Kind  string
				Count int
			}{k, counts[k]})
		}
		for _, ref := range s.References {
			if !ref.SizeKnown || len(ref.Witnesses) == 0 {
				row.UnresolvedReferences = append(row.UnresolvedReferences, ref)
			}
		}
		tagCounts := map[uint32]int{}
		tagSamples := map[uint32]int{}
		for i, e := range s.Entries {
			for _, tag := range e.Tags {
				tagCounts[tag.Tag]++
				if tagSamples[tag.Tag] < 3 {
					row.TagWitnesses = append(row.TagWitnesses, struct {
						Path   string
						Offset uint64
						Tag    Tag
					}{e.Path, tag.Offset, tag})
					tagSamples[tag.Tag]++
				}
			}
			for j, stream := range e.Streams {
				if stream.Reference < 0 || len(s.References[stream.Reference].Witnesses) != 0 {
					continue
				}
				row.UnresolvedUses = append(row.UnresolvedUses, struct {
					Entry, Stream      int
					Path, Kind, SHA1   string
					Offset, HardlinkID uint64
					Attributes         uint32
				}{i, j, e.Path, stream.Kind, stream.SHA1, stream.Offset, e.HardlinkID, e.Attributes})
				if len(row.MissingWitnesses) < 8 {
					raw := make([]byte, int(e.Length))
					if _, err := a.ReadAt(raw, int64(e.Offset)); err != nil {
						t.Fatal(err)
					}
					var members []int
					for _, g := range s.Hardlinks {
						if g.ID == e.HardlinkID {
							members = append([]int(nil), g.Entries...)
							break
						}
					}
					row.MissingWitnesses = append(row.MissingWitnesses, struct {
						Entry        Entry
						Raw          []byte
						GroupMembers []int
					}{e, raw, members})
				}
			}
		}
		tags := make([]uint32, 0, len(tagCounts))
		for tag := range tagCounts {
			tags = append(tags, tag)
		}
		sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })
		for _, tag := range tags {
			row.TagCounts = append(row.TagCounts, struct {
				Tag   uint32
				Count int
			}{tag, tagCounts[tag]})
		}
		if r.Payload.Provenance.Name == "professional_en-us.esd" && r.Entry.ImageIndex == 3 {
			selected = true
			if r.SHA256 != "271d6f490baa2f90d497e0d21f721b56d4e2cfc5323feb0bfb491b9c2989201a" || r.Size != 18731096 {
				t.Fatal("selected image original bytes changed")
			}
			if len(s.Entries) != 78515 || len(s.Security) != 352 || s.Summary.ACEs != 3340 || s.Summary.Streams != 78515 || len(row.UnresolvedReferences) != 774 || counts["tag-semantics"] != 13546 || counts["ace-semantics"] != 195 || s.Complete {
				t.Fatal("selected source observations changed", s.Summary, counts)
			}
			named, reparse := false, 0
			for _, e := range s.Entries {
				pick := e.Path == "/" || strings.EqualFold(e.Path, "/Windows/System32/kernel32.dll") || strings.EqualFold(e.Path, "/Windows/explorer.exe") || strings.EqualFold(e.Path, "/Windows/System32/ntdll.dll")
				if reparse < 4 && e.ReparseTag != 0 {
					pick = true
					reparse++
				}
				for _, stream := range e.Streams {
					if !named && len(stream.Name) != 0 {
						pick = true
						named = true
					}
				}
				if pick {
					row.Witnesses = append(row.Witnesses, e)
				}
				if e.Path == "/Windows/System32/kernel32.dll" && (e.Offset != 3904096 || e.SecurityID != 5 || e.HardlinkID != 281474976756627 || len(e.Streams) != 1 || e.Streams[0].SHA1 != "9d62d08a7de5152db50a7bbac02ee36e0dc299db" || !e.Streams[0].SizeKnown || e.Streams[0].Size != 644960) {
					t.Fatal("kernel32 original witness changed")
				}
			}
			for i := range s.Security {
				for _, acl := range []*ACL{s.Security[i].DACL, s.Security[i].SACL} {
					if acl == nil {
						continue
					}
					for _, ace := range acl.ACEs {
						if ace.Type == 9 && !ace.Understood && row.CallbackWitness == nil {
							row.CallbackSecurityID = i
							row.CallbackWitness = &s.Security[i]
						}
					}
				}
			}
			if len(s.Security) > 0 {
				row.SecurityWitness = &s.Security[0]
			}
			for i := range s.Hardlinks {
				if len(s.Hardlinks[i].Entries) > 1 {
					row.HardlinkWitness = &s.Hardlinks[i]
					for _, id := range s.Hardlinks[i].Entries[:min(3, len(s.Hardlinks[i].Entries))] {
						row.Witnesses = append(row.Witnesses, s.Entries[id])
					}
					break
				}
			}
		}
		passed++
		report.Resources = append(report.Resources, row)
		t.Logf("metadata=%s image=%d digest=%s summary=%+v complete=%v metadata-verified=%v", r.Payload.Provenance.Name, r.Entry.ImageIndex, o.Digest(), o.Summary(), s.Complete, s.MetadataVerified)
	}
	if !selected {
		t.Error("selected image-3 oracle absent")
	}
	for _, f := range files {
		source, err := os.Open(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		n, hashErr := io.CopyBuffer(h, source, make([]byte, 64<<10))
		closeErr := source.Close()
		sum := hex.EncodeToString(h.Sum(nil))
		expected := ""
		for _, c := range original.Containers {
			if c.Payload == f.Identity {
				expected = c.SHA256
				break
			}
		}
		if hashErr != nil || closeErr != nil || n != f.Identity.Size || sum != expected {
			t.Fatal("final original source hash changed", hashErr, closeErr)
		}
		report.FinalSources = append(report.FinalSources, struct {
			Payload model.PayloadIdentity
			SHA256  string
			Size    int64
		}{f.Identity, sum, n})
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "task-6b3-actual-oracles.json"), append(out, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(append(out, '\n'))
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	t.Logf("parsed=%d/%d evidence-sha256=%s Go-heap-alloc=%d Go-heap-sys=%d content-verified=false conversion-supported=false", passed, len(as), hex.EncodeToString(h[:]), stats.HeapAlloc, stats.HeapSys)
}
