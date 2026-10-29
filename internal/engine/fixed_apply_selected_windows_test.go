package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uupbuilder/internal/engine/source"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/cabindex"
	"uupbuilder/internal/metadata/wimcontent"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

// NOT RUN in U07B2B2. This entry exists only in the test executable; it is not
// a CLI/release mode or helper protocol. A later explicit execution scope must
// configure both values. Old receipts never construct its live capabilities.
func TestConfiguredFixedSelectedSourceApply(t *testing.T) {
	if os.Getenv("UUP_FIXED_SELECTED_APPLY") != "reviewed-source-contract-0x182" {
		t.Skip("NOT RUN: exact selected-source native apply is unconfigured; code-only slice")
	}
	root := os.Getenv("UUP_FIXED_SELECTED_SOURCE_ROOT")
	if root == "" || !filepath.IsAbs(root) {
		t.Fatal("exact frozen selected fixture root required")
	}
	ctx := context.Background()
	p := rebuildFixedSelectedProof(t, ctx, root)
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	provider, e := openInstalledFixedApply(ctx)
	if e != nil {
		t.Fatal(e)
	}
	providerOwned := true
	defer func() {
		if providerOwned {
			if e := provider.Close(); e != nil {
				t.Error(e)
			}
		}
	}()
	// Nil uses the real read-only installed OS mount inventory, never the
	// synthetic inventory used by ordinary unit fixtures.
	store, e := jobstore.Create(os.TempDir(), "fixed-source-contract-trial", nil)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := store.Close(); e != nil {
			t.Logf("PRESERVED durable scopes (not clean removal): %v", e)
		}
	}()
	tx, e := store.Begin(ctx, fixedApplyIntent(p, provider.ports.id, store.Identity().JobID))
	if e != nil {
		t.Fatal(e)
	}
	destination, cache, e := tx.ClaimFixedSourceApplyDirectories(ctx, p.state.Digest)
	if e != nil {
		t.Fatalf("preserve every acquired/partial destination/cache claim: destination=%v cache=%v error=%v", destination != nil, cache != nil, e)
	}
	b, e := bindFixedApply(ctx, p, x, destination, cache, provider.ports.id, platform.NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	// Build and retain the exact source-derived observer/preflight before any
	// privilege adjustment. executeFixedApply consumes this very session.
	if e = prepareFixedApplyObservation(ctx, b); e != nil {
		t.Fatal("fresh source observation preflight refused", e)
	}
	defer func() {
		if b.prepared != nil {
			b.prepared.Close()
		}
	}()
	t.Logf("FRESH selected entries=%d source=%s preflight=%+v; requested capacities are not actual disk/query bytes", len(x.entries), p.state.Source.Recipe.Source.BuildLabel, b.preflight)
	priv, e := platform.AcquireImagePreservationPrivileges(ctx) // UNCALLED in this slice.
	if e != nil {
		t.Fatal("fixed current-token profile refused; no elevation/fallback", e)
	}
	privOwned := true
	defer func() {
		if privOwned {
			if e := priv.Close(); e != nil {
				t.Error(e)
			}
		}
	}()
	r, runErr := executeFixedApply(ctx, b, provider.ports, priv, &installedApplyCallbacks)
	if r == nil {
		t.Fatal(runErr)
	}
	providerOwned = false
	privOwned = false
	var comparison []byte
	if r.comparison != nil {
		comparison, e = r.comparison.Serialize(ctx, 512<<20)
		runErr = errors.Join(runErr, e)
	}
	closeErr := r.Close()
	var observer []byte
	if r.observer != nil {
		observer, e = serializeFixedTrialObserver(ctx, r.observer.session, 512<<20)
		runErr = errors.Join(runErr, e)
	}
	// Close always reports preservation. Preserve that separately from native
	// equality; it is never whole-image cleanup or production acceptance.
	evidence := struct {
		Attempt      fixedApplyEvidence
		Run, Closure applyOperationOutcome
	}{r.evidence, applyOutcome(runErr), applyOutcome(closeErr)}
	data, e := json.Marshal(evidence)
	if e != nil {
		t.Fatal(e)
	}
	if len(data) > 8<<20 {
		t.Fatal("bounded evidence export refused")
	}
	// The test log is the explicit evidence sink; no publication or source-root
	// write, stage commit, checkpoint or assembled-media success occurs.
	t.Logf("PRIVATE COMPONENT EVIDENCE %s", data)
	if len(comparison) != 0 {
		t.Logf("PRIVATE INDEPENDENT COMPARISON %s", comparison)
	}
	if len(observer) != 0 {
		t.Logf("PRIVATE CLOSED OBSERVER EVIDENCE %s", observer)
	}
	if runErr != nil {
		t.Fatal("first native/source-contract failure; no fallback", applyOutcome(runErr))
	}
	if closeErr == nil {
		t.Fatal("native file/cache claims unexpectedly reported clean removal")
	}
	t.Fatal("component trial finished with preserved destination/cache resources; cleanup and production acceptance remain incomplete", applyOutcome(closeErr))
}

// Session.Evidence precharges its bounded copied fields. Lower that allowance
// by eight for this single JSON export and encoder scratch; no profile cap is
// raised. Exports are separate component allowances, not a process-heap bound.
func serializeFixedTrialObserver(ctx context.Context, s *platform.NativeObservationSession, allowance uint64) ([]byte, error) {
	if allowance > 512<<20 || allowance < 128<<10 {
		return nil, ErrLimit
	}
	v, e := s.Evidence(ctx, allowance/8-8192)
	if e != nil {
		return nil, e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	if uint64(len(b)) > allowance {
		return nil, ErrLimit
	}
	return b, nil
}

func rebuildFixedSelectedProof(t *testing.T, ctx context.Context, root string) *PreservationProof {
	t.Helper()
	r, e := os.OpenRoot(root)
	if e != nil {
		t.Fatal(e)
	}
	f, e := r.Open("actual-preparation/prepared-source.json")
	if e != nil {
		r.Close()
		t.Fatal(e)
	}
	data, e := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	e = errors.Join(e, f.Close(), r.Close())
	if e != nil || len(data) > 4<<20 {
		t.Fatal("bounded prepared locator refused", e)
	}
	var input struct {
		Manifest model.PayloadManifest
		Files    []struct {
			Path, SHA256 string
			Identity     model.PayloadIdentity
		}
	}
	if e = json.Unmarshal(data, &input); e != nil {
		t.Fatal(e)
	}
	if input.Manifest.Digest != "675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9" || input.Manifest.Source != (model.SourceIdentity{UpdateID: "3d12aa3e-806a-46c9-900e-bf7613959273", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}) || len(input.Files) > 1024 {
		t.Fatal("frozen selected fixture identity changed")
	}
	var wims, cabs []metadata.LocalResource
	for _, file := range input.Files {
		name := strings.ToLower(file.Identity.Provenance.Name)
		v := metadata.LocalResource{Identity: file.Identity, Path: file.Path}
		if strings.HasSuffix(name, ".esd") {
			wims = append(wims, v)
		} else if strings.HasSuffix(name, ".cab") && !strings.HasPrefix(name, "ssu-") && !strings.HasPrefix(name, "windows10.0-") {
			cabs = append(cabs, v)
		}
	}
	if len(wims) != 13 || len(cabs) != 22 {
		t.Fatal("exact selected membership changed")
	}
	index, e := wimindex.Open(ctx, input.Manifest, wims, wimindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	if index.Digest() != "ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a" {
		t.Fatal("fresh original index changed")
	}
	content, e := wimcontent.Decode(ctx, input.Manifest, wims, index, wimcontent.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := content.Close(); e != nil {
			t.Error(e)
		}
	})
	artifacts, e := wimindex.DecodeMetadata(ctx, input.Manifest, wims, index, wimindex.DecodeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		for _, a := range artifacts {
			if e := a.Close(); e != nil {
				t.Error(e)
			}
		}
	})
	var original *wimindex.MetadataArtifact
	for _, a := range artifacts {
		if a.Receipt().SHA1 == "29256693076c5877942412848136d702889e3141" {
			if original != nil {
				t.Fatal("duplicate original metadata")
			}
			original = a
		}
	}
	if original == nil || original.Receipt().SHA256 != "271d6f490baa2f90d497e0d21f721b56d4e2cfc5323feb0bfb491b9c2989201a" {
		t.Fatal("original metadata changed")
	}
	oracle, e := wimmeta.Parse(ctx, original, index, wimmeta.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	if oracle.Digest() != "55c616fbf48127e824365337ad8a509a92b43b1a79043378a20dfa417d46b019" {
		t.Fatal("fresh original oracle changed")
	}
	cab, e := cabindex.Build(ctx, input.Manifest, cabs, oracle, cabindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := cab.Close(); e != nil {
			t.Error(e)
		}
	})
	refs, e := wimcontent.BindReferences(ctx, content, oracle, cab, wimcontent.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := refs.Close(); e != nil {
			t.Error(e)
		}
	})
	recipe, e := source.BindCanonical(ctx, source.Inputs{Manifest: input.Manifest, Files: wims, Index: index, Metadata: original, Oracle: oracle, References: refs}, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	d := recipe.Descriptor()
	if d.Recipe.BaselineVersion != "10.0.19041.1" || d.Recipe.Edition != "Professional" || d.Recipe.ImageIndex != 3 || d.Resources != 39472 {
		t.Fatal("selected baseline/recipe changed")
	}
	output, e := Reconstruct(ctx, recipe, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := output.Close(); e != nil {
			t.Error(e)
		}
	})
	p, e := BindPreservationProof(ctx, recipe, output, PreservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	return p
}
