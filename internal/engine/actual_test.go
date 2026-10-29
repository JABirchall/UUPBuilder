package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uupbuilder/internal/engine/source"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/cabindex"
	"uupbuilder/internal/metadata/wimcontent"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

// This explicitly configured integration recreates live producers. Retained
// inventories are observations; only the original files mint new authorities.
func TestPreparedCanonicalReconstruction(t *testing.T) {
	root := os.Getenv("UUP_CANONICAL_PREPARED_ROOT")
	if root == "" {
		t.Skip("exact private prepared source not configured")
	}
	ctx := context.Background()
	var p struct {
		Manifest model.PayloadManifest
		Files    []struct {
			Path, SHA256 string
			Identity     model.PayloadIdentity
		}
	}
	b, e := os.ReadFile(filepath.Join(root, "actual-preparation", "prepared-source.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &p); e != nil {
		t.Fatal(e)
	}
	if p.Manifest.Digest != "675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9" || p.Manifest.Source != (model.SourceIdentity{UpdateID: "3d12aa3e-806a-46c9-900e-bf7613959273", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}) {
		t.Fatal("selected fixture changed")
	}
	var wims, cabs []metadata.LocalResource
	for _, f := range p.Files {
		n := strings.ToLower(f.Identity.Provenance.Name)
		r := metadata.LocalResource{Identity: f.Identity, Path: f.Path}
		if strings.HasSuffix(n, ".esd") {
			wims = append(wims, r)
		} else if strings.HasSuffix(n, ".cab") && !strings.HasPrefix(n, "ssu-") && !strings.HasPrefix(n, "windows10.0-") {
			cabs = append(cabs, r)
		}
	}
	if len(wims) != 13 || len(cabs) != 22 {
		t.Fatal("reviewed membership changed")
	}
	idx, e := wimindex.Open(ctx, p.Manifest, wims, wimindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	if idx.Digest() != "ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a" {
		t.Fatal("index changed")
	}
	content, e := wimcontent.Decode(ctx, p.Manifest, wims, idx, wimcontent.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := content.Close(); e != nil {
			t.Error(e)
		}
	}()
	t.Log("live content recreated")
	metadataArtifacts, e := wimindex.DecodeMetadata(ctx, p.Manifest, wims, idx, wimindex.DecodeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		for _, a := range metadataArtifacts {
			if e := a.Close(); e != nil {
				t.Error(e)
			}
		}
	}()
	var selected *wimindex.MetadataArtifact
	for _, a := range metadataArtifacts {
		if a.Receipt().SHA1 == "29256693076c5877942412848136d702889e3141" {
			if selected != nil {
				t.Fatal("duplicate expected metadata")
			}
			selected = a
		}
	}
	if selected == nil || selected.Receipt().SHA256 != "271d6f490baa2f90d497e0d21f721b56d4e2cfc5323feb0bfb491b9c2989201a" {
		t.Fatal("selected original metadata changed")
	}
	oracle, e := wimmeta.Parse(ctx, selected, idx, wimmeta.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	if oracle.Digest() != "55c616fbf48127e824365337ad8a509a92b43b1a79043378a20dfa417d46b019" {
		t.Fatal("oracle changed")
	}
	cab, e := cabindex.Build(ctx, p.Manifest, cabs, oracle, cabindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := cab.Close(); e != nil {
			t.Error(e)
		}
	}()
	references, e := wimcontent.BindReferences(ctx, content, oracle, cab, wimcontent.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer references.Close()
	t.Log("live exact reference union recreated")
	in := source.Inputs{Manifest: p.Manifest, Files: wims, Index: idx, Metadata: selected, Oracle: oracle, References: references}
	for _, l := range []source.Limits{{MaxReferences: 1}, {MaxWitnesses: 1}, {MaxEntries: 1}, {MaxXMLBytes: 1}, {MaxResultBytes: 1}, {MaxReadBytes: 1}} {
		if r, e := source.BindCanonical(ctx, in, l); e == nil || r != nil {
			t.Fatal("recipe lower budget bypass", l)
		}
	}
	wrong := in
	wrong.Metadata = metadataArtifacts[0]
	if wrong.Metadata != selected {
		if r, e := source.BindCanonical(ctx, wrong, source.Limits{}); e == nil || r != nil {
			t.Fatal("foreign metadata base")
		}
	}
	recipe, e := source.BindCanonical(ctx, in, source.Limits{})
	if e != nil {
		t.Fatal("recipe", e)
	}
	d := recipe.Descriptor()
	if d.Recipe.BaselineVersion != "10.0.19041.1" || d.Recipe.Edition != "Professional" || d.Recipe.ImageIndex != 3 || d.Resources != 39472 {
		t.Fatal(d)
	}
	t.Logf("recipe=%s proof=%s resources=%d bytes=%d accounted=%d baseline=%s catalog=%s", d.RecipeDigest, d.ProofDigest, d.Resources, d.ResourceBytes, d.AccountedBytes, d.Recipe.BaselineVersion, d.Recipe.Source.BuildLabel)
	a, e := Reconstruct(ctx, recipe, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := a.Close(); e != nil {
			t.Error(e)
		}
	}()
	receipt := a.Receipt()
	write := func(name string, v any) {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(root, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("task-7a-actual-recipe.json", d)
	write("task-7a-actual-output.json", receipt)
	t.Logf("independently verified standard WIM size=%d sha256=%s resources=%d reads=%d", receipt.Size, receipt.SHA256, len(receipt.Resources), receipt.ReadBytes)
	if os.Getenv("UUP_CANONICAL_NATIVE") == "1" {
		observation, e := InspectReadOnly(ctx, a)
		write("task-7a-actual-native.json", struct {
			Observation NativeObservation
			Error       string
		}{observation, errorText(e)})
		t.Logf("native operation=%s compatible=%t provider=%+v image=%+v modules=%d error=%v", observation.LastOperation, observation.FormatInteroperable, observation.Provider, observation.Image, len(observation.Modules), e)
		if e != nil {
			t.Error("first native inspection failure; no fallback", e)
		}
	} else {
		t.Log("native interoperability NOT configured")
	}
	// Receipts stay historical; a closed original producer revokes new consumers.
	references.Close()
	if _, _, e := recipe.Resource(0); e == nil {
		t.Fatal("recipe survived reference closure")
	}
}
func errorText(e error) string {
	if e != nil {
		return e.Error()
	}
	return ""
}
