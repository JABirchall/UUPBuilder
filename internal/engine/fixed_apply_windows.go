package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"

	"uupbuilder/internal/jobstore"
	platform "uupbuilder/internal/platform/windows"
)

const fixedApplyFlags = uint32(0x182) // VERIFY | FILEINFO | NO_RP_FIX; no ACL suppression.
const fixedApplyStage = "fixed-source-contract-apply"

func fixedApplyPolicyDigest() string {
	return preservationDigest(struct {
		Provider, Privileges, Semantics string
		Flags, Image                    uint32
	}{
		"installed-system-wimgapi", platform.ImagePreservationPrivilegeProfile,
		"original-reparse-bytes;full-acls;observed-equality-only;preserve-destination-and-cache", fixedApplyFlags, 1,
	})
}
func fixedApplyIntent(p *PreservationProof, provider platform.DLLIdentity, job string) jobstore.MutationIntent {
	d := p.state.Source
	in := jobstore.MutationIntent{JobID: job, StageID: fixedApplyStage, PlanDigest: p.state.Digest, ConfigDigest: fixedApplyPolicyDigest(),
		Inputs: []jobstore.NamedDigest{{Name: "preservation-proof", Digest: p.state.Digest}, {Name: "generated-wim", Digest: p.state.WIMSHA256}, {Name: "original-manifest", Digest: d.Recipe.ManifestDigest}, {Name: "original-index", Digest: d.Index.IndexDigest}, {Name: "original-oracle", Digest: d.Oracle.Digest}, {Name: "original-references", Digest: d.ReferenceDigest}, {Name: "original-recipe", Digest: d.RecipeDigest}},
		Tools:  []jobstore.VersionedIdentity{{Name: "installed-wimgapi.dll", Version: "measured-fixed-apply", Digest: preservationDigest(provider)}},
		Rules:  []jobstore.VersionedIdentity{{Name: "fixed-apply-profile", Version: "1", Digest: fixedApplyPolicyDigest()}}, OwnedPaths: []string{"unused-component-output"},
	}
	// Match jobstore's durable canonical named-input ordering.
	slices.SortFunc(in.Inputs, func(a, b jobstore.NamedDigest) int { return strings.Compare(a.Name, b.Name) })
	return in
}

type fixedApplyBinding struct {
	proof                            *PreservationProof
	expected                         *SourceExpectations
	destination, cache               *jobstore.DirectoryClaim
	destinationID, cacheID           platform.TreeIdentity
	provider                         platform.DLLIdentity
	policy, intent, proofDigest, wim string
	profile                          platform.NativeObservationLimits
	maxSourceRead                    uint64
	prepared                         *sourceNativeObservation
	preflight                        platform.NativeObservationBudget
	executorBytes                    uint64
}

func claimApplyPath(c *jobstore.DirectoryClaim) string {
	id := c.Tree().Identity()
	return filepath.Join(id.Workspace.Path, filepath.FromSlash(id.RelativePath))
}
func bindFixedApply(ctx context.Context, p *PreservationProof, x *SourceExpectations, destination, cache *jobstore.DirectoryClaim, provider platform.DLLIdentity, limits platform.NativeObservationLimits) (*fixedApplyBinding, error) {
	if ctx == nil || p == nil || destination == nil || cache == nil {
		return nil, ErrInput
	}
	l, e := platform.NativeObservationProfile(limits)
	if e != nil {
		return nil, e
	}
	b := &fixedApplyBinding{proof: p, expected: x, destination: destination, cache: cache, provider: provider, policy: fixedApplyPolicyDigest(), profile: l, maxSourceRead: 64 << 30}
	b.destinationID = destination.Tree().Identity()
	b.cacheID = cache.Tree().Identity()
	b.proofDigest = p.state.Digest
	b.wim = p.state.WIMSHA256
	b.intent = preservationDigest(fixedApplyIntent(p, provider, b.destinationID.Workspace.JobID))
	if e = b.check(ctx, true); e != nil {
		return nil, e
	}
	return b, nil
}
func (b *fixedApplyBinding) check(ctx context.Context, empty bool) error {
	if b == nil || ctx == nil || b.proof == nil || b.expected == nil || b.destination == nil || b.cache == nil || b.destination == b.cache || b.maxSourceRead == 0 || b.maxSourceRead > 64<<30 {
		return ErrInput
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if l, e := platform.NativeObservationProfile(b.profile); e != nil || l != b.profile {
		return errors.Join(ErrInput, e)
	}
	if e := b.proof.CheckLive(); e != nil {
		return e
	}
	if e := b.expected.CheckLive(); e != nil {
		return e
	}
	if b.expected.proof != b.proof || b.proofDigest != b.proof.state.Digest || b.wim != b.proof.state.WIMSHA256 || b.policy != fixedApplyPolicyDigest() || b.provider.Name != "wimgapi.dll" || len(b.provider.SHA256) != 64 || b.provider.Size <= 0 {
		return ErrInput
	}
	if b.proof.state.OutputImage != (ImageInformation{1, "0", "Professional", "Client", "10.0.19041.1"}) {
		return ErrInput
	}
	if b.intent != preservationDigest(fixedApplyIntent(b.proof, b.provider, b.destinationID.Workspace.JobID)) {
		return ErrInput
	}
	if b.destinationID.Workspace != b.cacheID.Workspace || b.destinationID.Root == b.cacheID.Root || b.destinationID.RelativePath == b.cacheID.RelativePath {
		return ErrInput
	}
	for j, c := range []*jobstore.DirectoryClaim{b.destination, b.cache} {
		if c.Role() != []string{"destination", "wimgapi-cache"}[j] {
			return ErrInput
		}
		if e := c.CheckLive(ctx); e != nil {
			return e
		}
		want := []platform.TreeIdentity{b.destinationID, b.cacheID}[j]
		if c.Tree().Identity() != want || want.OperationID != fixedApplyStage || c.IntentDigest() != b.intent || c.SourceDigest() != b.proofDigest || want.SourceDigest != b.proofDigest {
			return ErrInput
		}
		if len(claimApplyPath(c)) > 4096 {
			return ErrLimit
		}
		if empty {
			if e := freshApplyClaim(ctx, c); e != nil {
				return e
			}
		}
	}
	return nil
}

func prepareFixedApplyObservation(ctx context.Context, b *fixedApplyBinding) error {
	if e := b.check(ctx, false); e != nil {
		return e
	}
	if b.prepared != nil {
		return ErrInput
	}
	// Reserve callback descriptors, bounded diagnostics/module/cache exports,
	// and native XML scratch beside the existing observer. Residual zero never
	// goes through a defaulting constructor and never silently raises a cap.
	cost := uint64(8 << 20)
	for _, entry := range b.expected.entries {
		n := uint64(128 + len(entry.Original.Path)*4)
		if n > b.profile.MaxResultBytes-min(cost, b.profile.MaxResultBytes) {
			return ErrLimit
		}
		cost += n
	}
	if cost >= b.profile.MaxResultBytes {
		return ErrLimit
	}
	l := b.profile
	l.MaxResultBytes -= cost
	s, e := newSourceNativeObservation(ctx, b.expected, b.destination, l)
	b.prepared = s
	if e != nil {
		return e
	}
	v, e := s.session.Evidence(ctx, 16<<10)
	if e != nil {
		return e
	}
	b.preflight = v.Preflight
	b.executorBytes = cost
	return nil
}
func freshApplyClaim(ctx context.Context, c *jobstore.DirectoryClaim) error {
	v, e := c.Tree().ObserveInventory(ctx, platform.TreeLimits{})
	if e != nil || !v.Complete || len(v.Entries) != 1 || v.Entries[0].Path != "." {
		return errors.Join(ErrInput, e)
	}
	o, e := c.Tree().Observe(ctx, ".", platform.MetadataLimits{})
	if e != nil || o.Streams.Status != "complete" || o.EAs.Status != "complete" || len(o.ExtendedAttributes) != 0 || o.Attributes&0x410 != 0x10 {
		return errors.Join(ErrInput, e)
	}
	for _, s := range o.NamedStreams {
		if string(utf16.Decode(s.Name)) != "::$DATA" || s.Size != 0 {
			return ErrInput
		}
	}
	return nil
}

// All ports are private. Synthetic ports exercise lifecycle/refusal only; they
// cannot mint the native completion seal produced inside the installed call.
type fixedApplyPorts struct {
	id            platform.DLLIdentity
	installed     *installedApplyProvider
	check         func() error
	open          func(string) (uintptr, error)
	temporary     func(uintptr, string) error
	load          func(uintptr, uint32) (uintptr, error)
	register      func(uintptr, uintptr) (uint32, error)
	apply         func(*fixedApplyBinding, uintptr, uint32) (*nativeApplyCompletion, error)
	unregister    func(uintptr) error
	closeHandle   func(uintptr) error
	modules       func(context.Context) ([]ModuleIdentity, error)
	closeProvider func() error
}
type applyPrivilegePort interface {
	CheckActive() error
	Close() error
}
type nativeApplyCompletion struct {
	provider *installedApplyProvider
	binding  *fixedApplyBinding
	image    uintptr
	success  bool
}
type applyOperationOutcome struct {
	Attempted, Failed, Preserved, LimitExceeded, Cancelled bool
	Win32                                                  uint32
}

func applyOutcome(e error) applyOperationOutcome {
	v := applyOperationOutcome{Attempted: true, Failed: e != nil, Preserved: errors.Is(e, platform.ErrTreePreserved), LimitExceeded: errors.Is(e, ErrLimit) || errors.Is(e, platform.ErrTreeLimit), Cancelled: errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded)}
	var code syscall.Errno
	if errors.As(e, &code) {
		v.Win32 = uint32(code)
	}
	return v
}

type fixedApplyEvidence struct {
	ProofDigest, WIMSHA256, IntentDigest, ProfileDigest                                 string
	Destination, Cache                                                                  platform.TreeIdentity
	Provider                                                                            platform.DLLIdentity
	Flags, ImageIndex, CallbackIndex                                                    uint32
	Started, Returned, Synthetic, NativeHandlesClosed                                   bool
	Callback                                                                            applyCallbackEvidence
	OperationModules                                                                    []ModuleIdentity // Observation, never full transitive closure proof.
	SourceVerificationReadBytes                                                         uint64
	Preflight                                                                           platform.NativeObservationBudget
	CacheInventory                                                                      platform.TreeInventory
	Preserved                                                                           []jobstore.PreservedResource
	NativeReturn, ModuleObservation, Unregister, Drain                                  applyOperationOutcome
	ImageClose, WIMClose, PrivilegeClose, ProviderClose, ObserverClose, CacheInspection applyOperationOutcome
}
type fixedApplyRun struct {
	mu                                       sync.Mutex
	b                                        *fixedApplyBinding
	n                                        *fixedApplyPorts
	priv                                     applyPrivilegePort
	hub                                      *applyCallbackHub
	callback                                 *applyCallbackSession
	observer                                 *sourceNativeObservation
	comparison                               *PreservationComparison
	completion                               *nativeApplyCompletion
	result                                   *ObservedSourceContractResult
	wim, image                               uintptr
	registered, settled, quarantined, closed bool
	evidence                                 fixedApplyEvidence
	runErr, closeErr                         error
}

func executeFixedApply(ctx context.Context, b *fixedApplyBinding, n *fixedApplyPorts, priv applyPrivilegePort, hub *applyCallbackHub) (r *fixedApplyRun, runErr error) {
	// Keep current-thread no-impersonation checks and the synchronous installed
	// call/inspection on one OS thread. Native callback threads remain separate.
	if n != nil && n.installed != nil {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}
	r, runErr = invokeFixedApply(ctx, b, n, priv, hub)
	if r != nil && runErr == nil {
		_, runErr = completeFixedApply(ctx, r)
		r.runErr = errors.Join(r.runErr, runErr)
	}
	return r, runErr
}
func invokeFixedApply(ctx context.Context, b *fixedApplyBinding, n *fixedApplyPorts, priv applyPrivilegePort, hub *applyCallbackHub) (r *fixedApplyRun, runErr error) {
	if ctx == nil || b == nil || n == nil || priv == nil || hub == nil {
		return nil, ErrInput
	}
	r = &fixedApplyRun{b: b, n: n, priv: priv, hub: hub, observer: b.prepared}
	// Ownership transfers only after taking the one process-wide native slot.
	// A refused duplicate cannot close another run's provider or token lease.
	if e := hub.reserve(r); e != nil {
		return nil, e
	}
	defer func() { r.runErr = errors.Join(r.runErr, runErr); runErr = r.runErr }()
	if e := b.check(ctx, true); e != nil {
		return r, e
	}
	r.evidence = fixedApplyEvidence{ProofDigest: b.proofDigest, WIMSHA256: b.wim, IntentDigest: b.intent, ProfileDigest: b.policy, Destination: b.destinationID, Cache: b.cacheID, Provider: b.provider, Flags: fixedApplyFlags, ImageIndex: 1, Synthetic: n.installed == nil,
		Preserved: []jobstore.PreservedResource{{Path: claimApplyPath(b.destination), Reason: "native result has no created-entry/deletion authority; durable claim unresolved"}, {Path: claimApplyPath(b.cache), Reason: "native metadata cache side effects preserved; durable claim unresolved"}}}
	if n.id != b.provider || n.check == nil || n.open == nil || n.temporary == nil || n.load == nil || n.register == nil || n.apply == nil || n.unregister == nil || n.closeHandle == nil || n.modules == nil || n.closeProvider == nil {
		return r, ErrInput
	}
	if e := errors.Join(n.check(), priv.CheckActive()); e != nil {
		return r, e
	}
	if e := r.verifySource(ctx); e != nil {
		return r, e
	}
	var e error
	if b.prepared == nil {
		e = prepareFixedApplyObservation(ctx, b)
		r.observer = b.prepared
		if e != nil {
			return r, e
		}
	}
	r.observer = b.prepared
	if r.observer == nil || r.observer.expected != b.expected || r.observer.claim != b.destination {
		return r, ErrInput
	}
	if e = r.observer.CheckObservationLive(ctx); e != nil {
		return r, e
	}
	r.evidence.Preflight = b.preflight
	known := make(map[string]bool, len(b.expected.entries))
	for _, entry := range b.expected.entries {
		name := strings.TrimPrefix(entry.Original.Path, "/")
		if name == "" {
			name = "."
		}
		known[strings.ToLower(name)] = true
	}
	r.callback, e = hub.beginFor(r, ctx, claimApplyPath(b.destination), known, applyCallbackLimits{})
	if e != nil {
		return r, e
	}
	// Native handles stay live through independent inspection. Settle callback
	// registration now, while source/provider/privilege owners remain retained.
	defer func() {
		if r.wim != 0 {
			mods, me := n.modules(context.WithoutCancel(ctx))
			r.evidence.OperationModules = mods
			r.evidence.ModuleObservation = applyOutcome(me)
			runErr = errors.Join(runErr, me)
		}
		if r.registered {
			ue := n.unregister(r.wim)
			de := hub.retire(r.callback, ue == nil)
			r.evidence.Unregister = applyOutcome(ue)
			r.evidence.Drain = applyOutcome(de)
			r.evidence.Callback = r.callback.snapshot()
			r.registered = false
			if ue != nil || de != nil {
				r.quarantined = true
				hub.mu.Lock()
				hub.retained = r
				hub.mu.Unlock()
			}
			runErr = errors.Join(runErr, ue, de)
		} else if r.callback != nil {
			runErr = errors.Join(runErr, hub.retire(r.callback, true))
			r.evidence.Callback = r.callback.snapshot()
		}
	}()
	if e = ctx.Err(); e != nil {
		return r, e
	}
	if e = errors.Join(n.check(), priv.CheckActive(), b.check(ctx, false)); e != nil {
		return r, e
	}
	a := b.proof.artifact
	r.wim, e = n.open(filepath.Join(a.store.Path(), a.name))
	if e != nil || r.wim == 0 {
		return r, errors.Join(e, ErrIntegrity)
	}
	if e = n.temporary(r.wim, claimApplyPath(b.cache)); e != nil {
		return r, e
	}
	if e = errors.Join(ctx.Err(), priv.CheckActive(), b.check(ctx, false)); e != nil {
		return r, e
	}
	r.image, e = n.load(r.wim, 1)
	if e != nil || r.image == 0 {
		return r, errors.Join(e, ErrIntegrity)
	}
	r.evidence.CallbackIndex, e = n.register(r.wim, r.callback.token)
	if e != nil {
		return r, e
	}
	r.registered = true
	if e = errors.Join(ctx.Err(), n.check(), priv.CheckActive(), b.check(ctx, false), freshApplyClaim(ctx, b.destination), r.verifySource(ctx)); e != nil {
		return r, e
	}
	r.evidence.Started = true
	r.completion, e = n.apply(b, r.image, fixedApplyFlags) // Synchronous; never races cleanup or cancellation teardown.
	r.evidence.NativeReturn = applyOutcome(e)
	r.evidence.Returned = true
	r.callback.mu.Lock()
	r.callback.v.Returned = true
	r.callback.mu.Unlock()
	if e != nil {
		return r, errors.Join(e, ctx.Err())
	}
	if e = ctx.Err(); e != nil {
		return r, e
	}
	if e = r.verifySource(ctx); e != nil {
		return r, e
	}
	// Comparison is deferred to completeFixedApply, after successful exact
	// unregister/drain. No caller completion Boolean can skip that boundary.
	return r, nil
}

func (r *fixedApplyRun) verifySource(ctx context.Context) error {
	b := r.b
	if e := b.proof.CheckLive(); e != nil {
		return e
	}
	n := b.proof.state.WIMSize + b.proof.state.Source.Metadata.Size
	if r.evidence.SourceVerificationReadBytes > b.maxSourceRead || n > b.maxSourceRead-r.evidence.SourceVerificationReadBytes {
		return ErrLimit
	}
	r.evidence.SourceVerificationReadBytes += n
	a := b.proof.artifact
	a.mu.RLock()
	if a.closed || a.file == nil || a.receipt.SHA256 != b.wim {
		a.mu.RUnlock()
		return ErrInput
	}
	e := a.file.Verify(ctx, "sha256", b.wim, b.wim)
	a.mu.RUnlock()
	return errors.Join(e, verifyOriginalMetadata(ctx, b.proof))
}

func (r *fixedApplyRun) settleHandles() error {
	if r.settled {
		return nil
	}
	r.settled = true
	if r.quarantined {
		return errors.New("native handles/provider/privileges retained after unproved callback unregister")
	}
	var e error
	if r.image != 0 {
		e = r.n.closeHandle(r.image)
		r.evidence.ImageClose = applyOutcome(e)
		if e == nil {
			r.image = 0
		}
	}
	if r.image == 0 && r.wim != 0 {
		we := r.n.closeHandle(r.wim)
		r.evidence.WIMClose = applyOutcome(we)
		e = errors.Join(e, we)
		if e == nil {
			r.wim = 0
		}
	}
	r.evidence.NativeHandlesClosed = r.image == 0 && r.wim == 0
	return e
}

func completeFixedApply(ctx context.Context, r *fixedApplyRun) (*ObservedSourceContractResult, error) {
	if r == nil || ctx == nil {
		return nil, ErrInput
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.result != nil || r.runErr != nil || r.quarantined || !r.evidence.Started || !r.evidence.Returned || r.callback == nil {
		return nil, errors.Join(ErrInput, r.runErr)
	}
	v := r.callback.snapshot()
	r.evidence.Callback = v
	if v.Failure != nil || v.CancellationRequested {
		return nil, errors.Join(ErrInput, v.Failure, ctx.Err())
	}
	if e := errors.Join(r.b.check(ctx, false), r.priv.CheckActive(), r.n.check()); e != nil {
		return nil, e
	}
	c, e := comparePreservation(ctx, r.b.expected, r.observer, ComparisonLimits{})
	r.comparison = c
	if e != nil {
		return nil, e
	}
	if e = c.live(ctx); e != nil {
		return nil, e
	}
	if !c.state.Complete {
		return nil, errors.New("independent source comparison incomplete; native destination preserved")
	}
	if e = r.verifySource(ctx); e != nil {
		return nil, e
	}
	if e = r.settleHandles(); e != nil {
		r.runErr = errors.Join(r.runErr, e)
		return nil, e
	}
	r.result, e = mintObservedSourceContract(r, c)
	return r.result, e
}

func mintObservedSourceContract(r *fixedApplyRun, c *PreservationComparison) (*ObservedSourceContractResult, error) {
	if r == nil || r.b == nil || r.n == nil || c == nil || r.closed || r.runErr != nil || r.comparison != c || c.port != r.observer || c.expected != r.b.expected || !c.state.Complete || c.state.Destination != r.b.destinationID || c.state.Source.ProofDigest != r.b.proofDigest {
		return nil, ErrInput
	}
	seal := r.completion
	if seal == nil || seal.provider == nil || seal.provider != r.n.installed || seal.provider.ports != r.n || seal.binding != r.b || !seal.success || r.evidence.Synthetic || !r.evidence.Started || !r.evidence.Returned || !r.evidence.NativeHandlesClosed {
		return nil, errors.New("synthetic or unauthenticated native completion; no observed-source capability")
	}
	return &ObservedSourceContractResult{run: r, comparison: c, completion: seal}, nil
}

// ObservedSourceContractResult is live, private-constructor component evidence.
// It proves an actual fixed installed call/return plus complete independent
// sequential equality. It grants no creator/created-entry/deletion, atomic
// snapshot/ADS namespace, Toolchain, NormalizedSource or assembly authority.
type ObservedSourceContractResult struct {
	run        *fixedApplyRun
	comparison *PreservationComparison
	completion *nativeApplyCompletion
}

func (o *ObservedSourceContractResult) CheckLive(ctx context.Context) error {
	if o == nil || o.run == nil || o.completion == nil || o.comparison == nil {
		return ErrInput
	}
	r := o.run
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.result != o || r.completion != o.completion || r.runErr != nil || !r.evidence.NativeHandlesClosed {
		return ErrInput
	}
	return errors.Join(r.b.check(ctx, false), r.priv.CheckActive(), r.n.check(), o.comparison.live(ctx))
}
func (o *ObservedSourceContractResult) Evidence(ctx context.Context, allowance uint64) (ComparisonEvidence, error) {
	if e := o.CheckLive(ctx); e != nil {
		return ComparisonEvidence{}, e
	}
	v, e := o.comparison.Evidence(ctx, allowance)
	return v, errors.Join(e, o.CheckLive(ctx))
}
func (o *ObservedSourceContractResult) Close() error {
	if o == nil {
		return nil
	}
	return o.run.Close()
}
func (r *fixedApplyRun) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	r.result = nil
	r.closeErr = errors.Join(r.runErr, platform.ErrTreePreserved)
	r.closeErr = errors.Join(r.closeErr, r.settleHandles())
	if !r.quarantined && r.b != nil && r.b.cache != nil && r.b.cache.Tree() != nil {
		v, e := r.b.cache.Tree().ObserveInventory(context.Background(), platform.TreeLimits{MaxEntries: 256})
		r.evidence.CacheInventory = v
		r.evidence.CacheInspection = applyOutcome(e)
		r.closeErr = errors.Join(r.closeErr, e)
	}
	if r.observer != nil {
		e := r.observer.Close()
		r.evidence.ObserverClose = applyOutcome(e)
		r.closeErr = errors.Join(r.closeErr, e)
	}
	if r.quarantined {
		return r.closeErr
	}
	if r.priv != nil {
		e := r.priv.Close()
		r.evidence.PrivilegeClose = applyOutcome(e)
		r.closeErr = errors.Join(r.closeErr, e)
	}
	if r.image != 0 || r.wim != 0 {
		// Callback delivery is settled but failed close leaves native objects
		// unknown. Keep their provider mapped and the single owner reachable.
		r.hub.mu.Lock()
		r.hub.retained = r
		r.hub.mu.Unlock()
		r.closeErr = errors.Join(r.closeErr, fmt.Errorf("native image/WIM handles preserved (%d/%d); provider retained", r.image, r.wim))
	} else if r.n != nil && r.n.closeProvider != nil {
		e := r.n.closeProvider()
		r.evidence.ProviderClose = applyOutcome(e)
		r.closeErr = errors.Join(r.closeErr, e)
	}
	if r.image == 0 && r.wim == 0 {
		r.hub.mu.Lock()
		if r.hub.retained == r {
			r.hub.retained = nil
		}
		r.hub.mu.Unlock()
	}
	return r.closeErr
}
