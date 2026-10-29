// Package cabindex derives source-bound CAB content witnesses for a live WIM
// metadata oracle, without granting reconstruction or conversion authority.
package cabindex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/cabformat"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

var ErrInput = errors.New("unbound CAB content input")
var ErrLimit = errors.New("CAB content limit exceeded")
var ErrIntegrity = errors.New("CAB content integrity changed")
var ErrUnsupported = errors.New("CAB content provider implementation gap")

// Zero limits select hard ceilings; callers can only lower them. Directory
// parsing uses cabformat's independent source/folder/block/name caps. Result
// accounting excludes caller accessor/JSON copies, existing oracle/index data,
// Go runtime overhead, native allocator overhead and installed DLL mappings.
type Limits struct {
	MaxVariableBytes, MaxNameBytes, MaxFolders, MaxBlocks                                                                 int
	MaxManifestPayloads, MaxQueries, MaxProjectionPayloads                                                                int
	MaxSources, MaxReferences, MaxMembers, MaxWitnesses                                                                   int
	MaxManifestBytes                                                                                                      uint64
	MaxSourceBytes, MaxTotalSourceBytes, MaxDeclaredBytes, MaxMemberBytes, MaxDiskBytes, MaxMetadataBytes, MaxResultBytes uint64
	MaxBufferBytes, MaxNativeAllocations                                                                                  int
	MaxNativeBytes, MaxNativeTotalBytes, MaxProviderReadBytes                                                             uint64
}

func bounds(l Limits) (Limits, error) {
	for i, p := range []*int{&l.MaxVariableBytes, &l.MaxNameBytes, &l.MaxFolders, &l.MaxBlocks, &l.MaxManifestPayloads, &l.MaxQueries, &l.MaxProjectionPayloads, &l.MaxSources, &l.MaxReferences, &l.MaxMembers, &l.MaxWitnesses, &l.MaxBufferBytes, &l.MaxNativeAllocations} {
		cap := []int{4096, 255, 4096, 262144, 4096, 64, 4096, 64, 524288, 262144, 16384, 1 << 20, 4096}[i]
		if *p < 0 || *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	for i, p := range []*uint64{&l.MaxManifestBytes, &l.MaxSourceBytes, &l.MaxTotalSourceBytes, &l.MaxDeclaredBytes, &l.MaxMemberBytes, &l.MaxDiskBytes, &l.MaxMetadataBytes, &l.MaxResultBytes, &l.MaxNativeBytes, &l.MaxNativeTotalBytes, &l.MaxProviderReadBytes} {
		cap := []uint64{16 << 20, 1 << 30, 2 << 30, 2 << 30, 256 << 20, 2 << 30, 64 << 20, 256 << 20, 32 << 20, 256 << 20, 8 << 30}[i]
		if *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	return l, nil
}

type ProviderIdentity struct {
	DLL                                          platform.DLLIdentity
	ABI, ProcessArchitecture, NativeArchitecture string
}
type Witness struct {
	Payload                    model.PayloadIdentity
	SourceSHA256, SHA1, SHA256 string
	Ordinal                    int
	Member                     cabformat.Member
	Size                       uint64
	SizeProvenance             string
}
type Resolution struct {
	Original                wimmeta.ReferenceClaim
	Witnesses               []int
	CABSize                 uint64
	CABSizeKnown, Ambiguous bool
}
type Missing struct{ SHA1 string }
type SourceObservation struct {
	Payload                                                  model.PayloadIdentity
	SourceSHA256, Status                                     string
	CabinetBytes, TrailingBytes, DeclaredBytes, DecodedBytes uint64
	Members, DecodedMembers, Matches                         int
	SourceRehashed                                           bool
}
type Gap struct {
	Payload model.PayloadIdentity
	Member  int
	Kind    string
}
type Snapshot struct {
	Schema                                                                                                            int
	Oracle                                                                                                            wimmeta.Claim
	Provider                                                                                                          ProviderIdentity
	Sources                                                                                                           []SourceObservation
	References                                                                                                        []Resolution
	Witnesses                                                                                                         []Witness
	Unresolved                                                                                                        []Missing
	Gaps                                                                                                              []Gap
	DeclaredBytes, ObservedBytes, RetainedBytes, ProviderReadBytes, NativePeakBytes, NativeTotalBytes, AccountedBytes uint64
	ReferenceClosure, ContentVerified, ConversionSupported                                                            bool
}

// Catalog is immutable, deterministic, location-free evidence. ReferenceClosure
// covers only references missing from this original oracle's WIM index; original
// metadata/semantic gaps remain bound by its unchanged digest and receipt.
type Catalog struct {
	state  Snapshot
	digest string
}

func (c *Catalog) Digest() string               { return c.digest }
func (c *Catalog) MarshalJSON() ([]byte, error) { return json.Marshal(c.state) }
func (c *Catalog) Snapshot() Snapshot {
	s := c.state
	s.Sources = slices.Clone(s.Sources)
	s.References = slices.Clone(s.References)
	for i := range s.References {
		s.References[i].Witnesses = slices.Clone(s.References[i].Witnesses)
	}
	s.Witnesses = slices.Clone(s.Witnesses)
	s.Unresolved = slices.Clone(s.Unresolved)
	s.Gaps = slices.Clone(s.Gaps)
	return s
}
func seal(s Snapshot) (*Catalog, error) {
	b, e := json.Marshal(s)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(b)
	return &Catalog{s, hex.EncodeToString(h[:])}, nil
}

// Build accepts the exact frozen manifest, CAB identities/locators and a live
// production oracle. Files are copied, opened read-only, verified before native
// work and rehashed before publication. No path or asserted receipt is authority.
func Build(ctx context.Context, m model.PayloadManifest, files []metadata.LocalResource, o *wimmeta.Oracle, l Limits) (*Result, error) {
	return build(ctx, m, files, o, l, openFDI)
}
