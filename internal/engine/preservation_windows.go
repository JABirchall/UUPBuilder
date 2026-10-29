package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"

	"uupbuilder/internal/engine/source"
	"uupbuilder/internal/jobstore"
	platform "uupbuilder/internal/platform/windows"
)

// PreservationProof is an immutable reduced component prerequisite, derived
// only from live production producers. No serialized descriptor/path/hash,
// NativeObservation, ReadyPlan or low-level transaction can construct it.
type PreservationProof struct {
	recipe   *source.BoundRecipe
	artifact *Artifact
	state    PreservationDescriptor
}
type PreservationLimits struct {
	MaxResources                 int
	MaxReadBytes, MaxResultBytes uint64
}
type PreservationDescriptor struct {
	Digest                                        string
	Source                                        source.Descriptor
	WIMSHA256                                     string
	WIMSize                                       uint64
	OutputImage                                   ImageInformation
	Resources                                     []source.ResourceIdentity
	Actions, ProviderRequirements, ComparisonGaps []string
	PrivilegeProfile                              string
	MetadataExpectationsComplete                  bool
}

func preservationDigest(v any) string {
	b, _ := json.Marshal(v)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
func (p *PreservationProof) Descriptor() PreservationDescriptor {
	if p == nil || p.recipe == nil || p.state.Digest == "" {
		return PreservationDescriptor{}
	}
	d := p.state
	d.Source = p.recipe.Descriptor()
	d.Resources = slices.Clone(d.Resources)
	d.Actions = slices.Clone(d.Actions)
	d.ProviderRequirements = slices.Clone(d.ProviderRequirements)
	d.ComparisonGaps = slices.Clone(d.ComparisonGaps)
	return d
}
func (p *PreservationProof) CheckLive() error {
	if p == nil || p.recipe == nil || p.artifact == nil || p.state.Digest == "" {
		return ErrInput
	}
	if e := p.recipe.CheckLive(); e != nil {
		return e
	}
	a := p.artifact
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return os.ErrClosed
	}
	if a.file == nil || a.boundRecipe != p.recipe || a.receipt.SHA256 != p.state.WIMSHA256 || !a.receipt.BytesVerified {
		return ErrInput
	}
	return nil
}

func BindPreservationProof(ctx context.Context, r *source.BoundRecipe, a *Artifact, limits PreservationLimits) (*PreservationProof, error) {
	if ctx == nil || r == nil || a == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := r.CheckLive(); e != nil {
		return nil, e
	}
	if limits.MaxResources < 0 || limits.MaxResources > 524288 || limits.MaxReadBytes > 16<<30 || limits.MaxResultBytes > 512<<20 {
		return nil, ErrLimit
	}
	if limits.MaxResources == 0 {
		limits.MaxResources = 524288
	}
	if limits.MaxReadBytes == 0 {
		limits.MaxReadBytes = 16 << 30
	}
	if limits.MaxResultBytes == 0 {
		limits.MaxResultBytes = 512 << 20
	}
	// Bound the original immutable resource/metadata descriptors before cloning.
	d := r.Descriptor()
	if d.Resources < 1 || d.Resources > limits.MaxResources || uint64(d.Resources)*1024+d.AccountedBytes+16384 > limits.MaxResultBytes {
		return nil, ErrLimit
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return nil, os.ErrClosed
	}
	if a.boundRecipe != r || a.file == nil || a.store == nil || !a.receipt.BytesVerified || a.receipt.RecipeDigest != d.RecipeDigest || a.receipt.ProofDigest != d.ProofDigest {
		return nil, ErrInput
	}
	if a.receipt.Size > limits.MaxReadBytes {
		return nil, ErrLimit
	}
	// This is a fresh bounded digest/custody verification, not trust in Receipt.
	if e := a.file.Verify(ctx, "sha256", a.receipt.SHA256, a.receipt.SHA256); e != nil {
		return nil, e
	}
	out := PreservationDescriptor{Source: d, WIMSHA256: a.receipt.SHA256, WIMSize: a.receipt.Size, OutputImage: a.expected, PrivilegeProfile: platform.ImagePreservationPrivilegeProfile,
		Actions:              []string{"future WIMApplyImage: exact output image 1; WIM_FLAG_VERIFY and WIM_FLAG_NO_RP_FIX; restore file/directory ACLs", "read-only held-handle attrs/raw FILETIMEs/IDs/link groups/security/ADS/EA/reparse inspection", "independent original-source metadata/resource comparison", "checked owned-tree cleanup or explicit preservation"},
		ProviderRequirements: []string{"installed-system wimgapi.dll exact measured lifetime and transitive operation closure", "WIMApplyImage-specific privilege and cancellation/completion proof (unproved)", "no source/target/downloaded executable, DLL, shim or script"},
		ComparisonGaps:       []string{"full original metadata interpretation and expected source topology are not yet an application allowlist", "source callback/opaque security and EA tag semantics remain unresolved", "source reparse relocation semantics and named-stream content comparison remain unproved", "sampled PathFacts are witnesses, not complete metadata comparison"}}
	out.Resources = make([]source.ResourceIdentity, 0, d.Resources)
	for n := 0; n < d.Resources; n++ {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		id, _, e := r.Resource(n)
		if e != nil {
			return nil, e
		}
		out.Resources = append(out.Resources, id)
	}
	if e := r.CheckLive(); e != nil {
		return nil, e
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	out.Digest = preservationDigest(out)
	return &PreservationProof{recipe: r, artifact: a, state: out}, nil
}

// OriginalMetadata returns a reader of the verified original metadata resource,
// never the generated WIM's own records as its comparison oracle. Every read
// checks both borrowed lifetimes; no caller path is accepted.
func (p *PreservationProof) OriginalMetadata() (source.ResourceIdentity, io.ReaderAt, error) {
	if e := p.CheckLive(); e != nil {
		return source.ResourceIdentity{}, nil, e
	}
	id, _, e := p.recipe.Resource(0)
	if e != nil {
		return id, nil, e
	}
	return id, preservationMetadataReader{p}, nil
}

type preservationMetadataReader struct{ p *PreservationProof }

func (r preservationMetadataReader) ReadAt(b []byte, off int64) (int, error) {
	if e := r.p.CheckLive(); e != nil {
		return 0, e
	}
	if len(b) > 64<<10 {
		return 0, ErrLimit
	}
	_, reader, e := r.p.recipe.Resource(0)
	if e != nil {
		return 0, e
	}
	return reader.ReadAt(b, off)
}

// ClaimSyntheticPreservationTree only creates ordinary synthetic fixtures. It
// does not permit source image application or adoption of native descendants.
// The exact proof digest must already be an input in tx's durable intent.
func ClaimSyntheticPreservationTree(ctx context.Context, p *PreservationProof, tx *jobstore.Transaction) (*jobstore.DirectoryClaim, error) {
	if ctx == nil || tx == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := p.CheckLive(); e != nil {
		return nil, e
	}
	c, e := tx.ClaimDirectory(ctx, p.state.Digest)
	if e != nil {
		return c, e
	}
	if e = p.CheckLive(); e != nil {
		return c, errors.Join(platform.ErrTreePreserved, e)
	}
	return c, nil
}

// NativeApplicationRequest fixes the next reviewable operation, but has no
// execution method or operational capability. Every listed missing prerequisite
// must be discharged in a subsequent explicit scope before any native call.
type NativeApplicationRequest struct {
	proof *PreservationProof
	claim *jobstore.DirectoryClaim
	state ApplicationSpecification
}
type ApplicationSpecification struct {
	ProofDigest, InputWIMSHA256, TransactionIntentDigest string
	InputWIMSize                                         uint64
	Image                                                ImageInformation
	Destination                                          platform.TreeIdentity
	Actions, MissingPrerequisites                        []string
}

// ApplicationResponse is the required evidence shape for the next native seam.
// A value constructed by a caller is descriptive data and grants no authority.
type ApplicationResponse struct {
	ProofDigest, InputWIMSHA256, TransactionIntentDigest         string
	Provider                                                     platform.DLLIdentity
	Destination                                                  platform.TreeIdentity
	Privileges                                                   platform.PrivilegeObservation
	NativeCallStarted, NativeCallReturned, CancellationRequested bool
	NativeFailure, PrivilegeRestoreFailure, ProviderCloseFailure string
	Metadata                                                     []platform.MetadataObservation
	ComparisonComplete, PreservationProved                       bool
	Preserved                                                    []jobstore.PreservedResource
}

func NewNativeApplicationRequest(ctx context.Context, p *PreservationProof, c *jobstore.DirectoryClaim) (*NativeApplicationRequest, error) {
	if ctx == nil || c == nil || c.Tree() == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := p.CheckLive(); e != nil {
		return nil, e
	}
	if c.SourceDigest() != p.state.Digest || c.IntentDigest() == "" {
		return nil, ErrInput
	}
	id := c.Tree().Identity()
	if id.SourceDigest != p.state.Digest || id.Root.FileIndex == 0 {
		return nil, ErrInput
	}
	// An actual closed/changed destination cannot mint even a descriptive request.
	if _, e := c.Tree().Observe(ctx, ".", platform.MetadataLimits{}); e != nil {
		return nil, e
	}
	s := ApplicationSpecification{ProofDigest: p.state.Digest, InputWIMSHA256: p.state.WIMSHA256, InputWIMSize: p.state.WIMSize, Image: p.state.OutputImage, Destination: id, TransactionIntentDigest: c.IntentDigest(), Actions: slices.Clone(p.state.Actions), MissingPrerequisites: []string{
		"explicit authorization for the exact native application experiment (B1 authorizes none)",
		"operation-specific installed WIMGAPI/provider closure and sufficiency proof",
		"required effective token privileges present/enabled, real checked acquire/restore composition and restoration evidence",
		"complete independently sourced expected descendant topology and security/EA/ADS/reparse comparison",
		"owned native application descendant claim protocol and bounded post-call inspection",
		"cancellation callback policy plus actual synchronous native-call completion before cleanup",
		"safe cleanup after arbitrary native partial application; preserve all unknown state",
		"separate production ReadyPlan/Toolchain/predecessor/worker/elevation composition"}}
	return &NativeApplicationRequest{proof: p, claim: c, state: s}, nil
}
func (r *NativeApplicationRequest) Specification() ApplicationSpecification {
	if r == nil {
		return ApplicationSpecification{}
	}
	s := r.state
	s.Actions = slices.Clone(s.Actions)
	s.MissingPrerequisites = slices.Clone(s.MissingPrerequisites)
	return s
}
