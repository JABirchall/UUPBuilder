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

// Future-only fixed child entry. Ordinary tests skip. The old environment
// string cannot grant consent; only an authenticated live approved parent can
// reach source preparation and the fixed native operation.
func TestConfiguredFixedSelectedSourceApply(t *testing.T) {
	if *fixedBootstrapValue != "" {
		fixedSelectedChild(t)
		return
	}
	if os.Getenv("UUP_FIXED_SELECTED_APPLY") != "reviewed-source-contract-0x182" {
		t.Skip("NOT RUN: exact selected-source native apply is unconfigured; code-only slice")
	}
	// An environment string is configuration, never operator consent or an
	// authenticated cross-token launch capability. Until a reviewed live launch
	// session exists, the legacy configured route cannot reach any producer,
	// native provider, privilege activation or destination claim.
	t.Fatal("native dispatch blocked: separate live exact-executable/token launch and operator approval required; use preparation-only entry after separate scope")
}

// The authenticated fixed child supplies its live preparation owner. Nil or
// configuration alone always refuses before source IO.
func fixedSelectedSourceApplyAfterLiveApproval(t *testing.T, preparation *fixedSelectedPreparation) {
	if preparation == nil || !preparation.nativeAuthorized() {
		t.Fatal("no live fixed native approval")
	}
	root := fixedPreparationSource
	if root == "" || !filepath.IsAbs(root) {
		t.Fatal("exact frozen selected fixture root required")
	}
	ctx := preparation.ctx
	p := rebuildFixedSelectedProof(t, ctx, root, preparation)
	preparation.record("live-source", struct {
		ProofDigest, WIMSHA256 string
		WIMSize                uint64
	}{p.state.Digest, p.state.WIMSHA256, p.state.WIMSize})
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		preparation.refuse(t, "source-expectations", e)
	}
	cost, e := fixedSourceDiskEstimate(x)
	if e != nil {
		preparation.refuse(t, "source-disk-estimate", e)
	}
	preparation.record("source-disk-estimate", cost)
	provider, e := openInstalledFixedApply(ctx)
	if e != nil {
		preparation.refuse(t, "installed-provider", e)
	}
	preparation.record("installed-provider", provider.ports.id)
	providerOwned := true
	defer func() {
		if providerOwned {
			preparation.closeResource(t, "installed-provider", provider.Close)
		}
	}()
	// Nil uses the real read-only installed OS mount inventory, never the
	// synthetic inventory used by ordinary unit fixtures.
	if e := preparation.check(); e != nil {
		preparation.refuse(t, "before-workspace", e)
	}
	store, e := jobstore.Create(preparation.parent.Identity().Workspace.Path, "fixed-source-contract-trial", nil)
	if e != nil {
		preparation.refuse(t, "durable-workspace", e)
	}
	defer func() {
		e := store.Close()
		preparation.record("store-close", applyOutcome(e))
		if e != nil {
			t.Logf("PRESERVED durable scopes (not clean removal): %v", e)
		}
	}()
	preparation.record("workspace", store.Identity())
	intent := fixedApplyIntent(p, provider.ports.id, store.Identity().JobID)
	preparation.record("intent", intent)
	tx, e := store.Begin(ctx, intent)
	preparation.journal(store.Identity())
	if e != nil {
		preparation.refuse(t, "begin-intent", e)
	}
	destination, cache, e := tx.ClaimFixedSourceApplyDirectories(ctx, p.state.Digest)
	// The journal locator is durable before either claim, and each surviving
	// partial claim is exported before considering a claim error.
	preparation.record("claims", struct{ Destination, Cache fixedTrialClaimEvidence }{fixedClaimEvidence(destination), fixedClaimEvidence(cache)})
	preparation.journal(store.Identity())
	if e != nil {
		preparation.refuse(t, "partial-directory-claims-preserved", e)
	}
	b, e := bindFixedApply(ctx, p, x, destination, cache, provider.ports.id, platform.NativeObservationLimits{})
	if e != nil {
		preparation.refuse(t, "fixed-binding", e)
	}
	preparedOwner := &fixedTrialPreparedOwner{binding: b}
	defer func() {
		preparation.closeResource(t, "prepared-observer", preparedOwner.Close)
	}()
	// Build and retain the exact source-derived observer/preflight before any
	// privilege adjustment. executeFixedApply consumes this very session.
	if e = prepareFixedApplyObservation(ctx, b); e != nil {
		preparation.refuse(t, "fresh-observation-preflight", e)
	}
	preparation.record("before-privileges", struct {
		Provider  platform.DLLIdentity
		WIMSHA256 string
		WIMSize   uint64
		Preflight platform.NativeObservationBudget
	}{provider.ports.id, p.state.WIMSHA256, p.state.WIMSize, b.preflight})
	if e = preparation.check(); e != nil {
		preparation.refuse(t, "before-privileges", e)
	}
	t.Logf("FRESH selected entries=%d source=%s preflight=%+v; requested capacities are not actual disk/query bytes", len(x.entries), p.state.Source.Recipe.Source.BuildLabel, b.preflight)
	priv, e := platform.AcquireImagePreservationPrivileges(ctx) // UNCALLED in this slice.
	preparation.record("privilege-acquire", applyOutcome(e))
	if e != nil {
		preparation.refuse(t, "fixed-current-token-profile-no-fallback", e)
	}
	privOwned := true
	defer func() {
		if privOwned {
			preparation.closeResource(t, "untransferred-privilege-restore", priv.Close)
		}
	}()
	preparation.nativeStarted = true
	r, runErr := executeFixedApply(ctx, b, provider.ports, priv, &installedApplyCallbacks)
	if r == nil {
		preparation.refuse(t, "native-executor-admission", runErr)
	}
	defer func() {
		closeErr := r.Close()
		data, e := json.Marshal(struct {
			Attempt      fixedApplyEvidence
			Run, Closure applyOperationOutcome
		}{r.evidence, applyOutcome(runErr), applyOutcome(closeErr)})
		if e == nil {
			v, writeErr := preparation.evidence.Blob("native.json", data)
			preparation.record("native-export", struct {
				Identity fixedBlobIdentity
				Outcome  applyOperationOutcome
			}{v, applyOutcome(writeErr)})
			e = writeErr
		}
		if e != nil {
			preparation.recordErr = errors.Join(preparation.recordErr, e)
		}
	}()
	// A nonnil executor owns its native lifetimes, even on error/quarantine.
	providerOwned = false
	privOwned = false
	if e := preparedOwner.Transfer(r); e != nil {
		preparedOwner.transferred = true // Preserve an unproved observer lifetime.
		preparation.refuse(t, "observer-transfer-preserved", errors.Join(runErr, e, r.Close()))
	}
	var comparison []byte
	if r.comparison != nil {
		comparison, e = r.comparison.Serialize(context.Background(), 512<<20)
		runErr = errors.Join(runErr, e)
	}
	closeErr := r.Close()
	var observer []byte
	if r.observer != nil {
		observer, e = serializeFixedTrialObserver(context.Background(), r.observer.session, 512<<20)
		runErr = errors.Join(runErr, e)
	}
	// Large exports go only to the private bounded durable sink.
	if len(comparison) != 0 {
		v, e := preparation.evidence.Blob("comparison.json", comparison)
		preparation.record("comparison-export", struct {
			Identity fixedBlobIdentity
			Outcome  applyOperationOutcome
		}{v, applyOutcome(e)})
	}
	if len(observer) != 0 {
		v, e := preparation.evidence.Blob("observer.json", observer)
		preparation.record("observer-export", struct {
			Identity fixedBlobIdentity
			Outcome  applyOperationOutcome
		}{v, applyOutcome(e)})
	}
	preparation.record("native-closed", struct{ Run, Closure applyOperationOutcome }{applyOutcome(runErr), applyOutcome(closeErr)})
	if runErr != nil {
		t.Fatal("first native/source-contract failure; no fallback", applyOutcome(runErr))
	}
	if closeErr == nil {
		t.Fatal("native file/cache claims unexpectedly reported clean removal")
	}
	t.Fatal("component trial finished with preserved destination/cache resources; cleanup and production acceptance remain incomplete", applyOutcome(closeErr))
}

// fixedTrialPreparedOwner is test-entry ownership only, before the executor
// accepts the same observer. Its Close reads the current binding, including a
// partially assigned observer when preparation returns an error.
type fixedTrialPreparedOwner struct {
	binding             *fixedApplyBinding
	closePrepared       func(*sourceNativeObservation) error
	transferred, closed bool
	closeErr            error
}

func (o *fixedTrialPreparedOwner) Close() error {
	if o == nil || o.transferred {
		return nil
	}
	if o.closed {
		return o.closeErr
	}
	o.closed = true
	if o.binding != nil && o.binding.prepared != nil {
		if o.closePrepared != nil {
			o.closeErr = o.closePrepared(o.binding.prepared)
		} else {
			o.closeErr = o.binding.prepared.Close()
		}
	}
	return o.closeErr
}

func (o *fixedTrialPreparedOwner) Transfer(r *fixedApplyRun) error {
	if o == nil || o.closed || o.transferred || o.binding == nil || o.binding.prepared == nil || r == nil {
		return ErrInput
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.b != o.binding || r.observer != o.binding.prepared || r.hub == nil {
		return ErrInput
	}
	r.hub.mu.Lock()
	defer r.hub.mu.Unlock()
	if r.hub.retained != r {
		return ErrInput
	}
	o.transferred = true
	return nil
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

func rebuildFixedSelectedProof(t *testing.T, ctx context.Context, root string, owner *fixedSelectedPreparation) *PreservationProof {
	t.Helper()
	r, e := os.OpenRoot(root)
	if e != nil {
		owner.refuse(t, "locator-root", e)
	}
	f, e := r.Open("actual-preparation/prepared-source.json")
	if e != nil {
		r.Close()
		owner.refuse(t, "locator-open", e)
	}
	data, e := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	e = errors.Join(e, f.Close(), r.Close())
	if e != nil || len(data) > 4<<20 {
		owner.refuse(t, "bounded-locator", errors.Join(ErrInput, e))
	}
	var input struct {
		Manifest model.PayloadManifest
		Files    []struct {
			Path, SHA256 string
			Identity     model.PayloadIdentity
		}
	}
	if e = json.Unmarshal(data, &input); e != nil {
		owner.refuse(t, "locator-json", e)
	}
	if input.Manifest.Digest != "675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9" || input.Manifest.Source != (model.SourceIdentity{UpdateID: "3d12aa3e-806a-46c9-900e-bf7613959273", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}) || len(input.Files) > 1024 {
		owner.refuse(t, "frozen-selected-identity", ErrIntegrity)
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
		owner.refuse(t, "exact-selected-membership", ErrIntegrity)
	}
	index, e := wimindex.Open(ctx, input.Manifest, wims, wimindex.Limits{})
	if e != nil {
		owner.refuse(t, "original-index", e)
	}
	if index.Digest() != "ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a" {
		owner.refuse(t, "fresh-original-index", ErrIntegrity)
	}
	content, e := wimcontent.Decode(ctx, input.Manifest, wims, index, wimcontent.Limits{})
	if e != nil {
		owner.refuse(t, "decoded-content", e)
	}
	t.Cleanup(func() {
		owner.closeResource(t, "decoded-content", content.Close)
	})
	artifacts, e := wimindex.DecodeMetadata(ctx, input.Manifest, wims, index, wimindex.DecodeLimits{})
	if e != nil {
		owner.refuse(t, "decoded-metadata", e)
	}
	t.Cleanup(func() {
		for _, a := range artifacts {
			owner.closeResource(t, "decoded-metadata", a.Close)
		}
	})
	var original *wimindex.MetadataArtifact
	for _, a := range artifacts {
		if a.Receipt().SHA1 == "29256693076c5877942412848136d702889e3141" {
			if original != nil {
				owner.refuse(t, "duplicate-original-metadata", ErrIntegrity)
			}
			original = a
		}
	}
	if original == nil || original.Receipt().SHA256 != "271d6f490baa2f90d497e0d21f721b56d4e2cfc5323feb0bfb491b9c2989201a" {
		owner.refuse(t, "original-metadata", ErrIntegrity)
	}
	oracle, e := wimmeta.Parse(ctx, original, index, wimmeta.Limits{})
	if e != nil {
		owner.refuse(t, "original-oracle", e)
	}
	if oracle.Digest() != "55c616fbf48127e824365337ad8a509a92b43b1a79043378a20dfa417d46b019" {
		owner.refuse(t, "fresh-original-oracle", ErrIntegrity)
	}
	cab, e := cabindex.Build(ctx, input.Manifest, cabs, oracle, cabindex.Limits{})
	if e != nil {
		owner.refuse(t, "cab-content", e)
	}
	t.Cleanup(func() {
		owner.closeResource(t, "cab-content", cab.Close)
	})
	refs, e := wimcontent.BindReferences(ctx, content, oracle, cab, wimcontent.Limits{})
	if e != nil {
		owner.refuse(t, "original-references", e)
	}
	t.Cleanup(func() {
		owner.closeResource(t, "original-references", refs.Close)
	})
	recipe, e := source.BindCanonical(ctx, source.Inputs{Manifest: input.Manifest, Files: wims, Index: index, Metadata: original, Oracle: oracle, References: refs}, source.Limits{})
	if e != nil {
		owner.refuse(t, "canonical-recipe", e)
	}
	d := recipe.Descriptor()
	if d.Recipe.BaselineVersion != "10.0.19041.1" || d.Recipe.Edition != "Professional" || d.Recipe.ImageIndex != 3 || d.Resources != 39472 {
		owner.refuse(t, "selected-baseline-recipe", ErrIntegrity)
	}
	output, e := Reconstruct(ctx, recipe, Limits{})
	if e != nil {
		owner.refuse(t, "reconstructed-archive", e)
	}
	t.Cleanup(func() {
		owner.closeResource(t, "reconstructed-archive", output.Close)
	})
	p, e := BindPreservationProof(ctx, recipe, output, PreservationLimits{})
	if e != nil {
		owner.refuse(t, "live-preservation-proof", e)
	}
	return p
}
