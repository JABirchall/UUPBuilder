// Package source fixes source-specific reconstruction rules and original-byte
// expectations. Recipe values describe requirements; BoundRecipe alone borrows
// live verified producers. Neither grants toolchain or transaction authority.
package source

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/wimcontent"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

var ErrInput = errors.New("canonical reconstruction source mismatch")
var ErrLimit = errors.New("canonical recipe bound exceeded")
var ErrIntegrity = errors.New("canonical reconstruction source bytes changed")

type Match struct {
	Matched                  bool
	Family                   string
	ImageIndex               int
	Edition, BaselineVersion string
}
type Requirement struct{ Operation, Provider, Contract string }
type Recipe struct {
	Family, RuleDigest                       string
	Source                                   model.SourceIdentity
	ManifestDigest, Edition, BaselineVersion string
	ImageIndex                               int
	Requirements                             []Requirement
	Gaps                                     []string
}
type PathFact struct {
	Path                   string
	Offset                 uint64
	Attributes, SecurityID uint32
	SecuritySHA256         string
	HardlinkID             uint64
	ReparseTag             uint32
	Streams, Tags          int
	RecordSHA256           string
}
type Descriptor struct {
	Recipe                                                                                    Recipe
	RecipeDigest, ProofDigest                                                                 string
	Index                                                                                     wimindex.ContentClaim
	Metadata                                                                                  wimindex.MetadataReceipt
	Oracle                                                                                    wimmeta.Claim
	ReferenceDigest, WIMDigest, CABDigest, OriginalXMLSHA256, OutputXMLSHA256, ResourceDigest string
	Resources                                                                                 int
	ResourceBytes, AccountedBytes, XMLBytes                                                   uint64
	Expected                                                                                  []PathFact
	PermittedOperations                                                                       []string
	NativeCandidate                                                                           string
}
type Inputs struct {
	Manifest   model.PayloadManifest
	Files      []metadata.LocalResource
	Index      *wimindex.Index
	Metadata   *wimindex.MetadataArtifact
	Oracle     *wimmeta.Oracle
	References *wimcontent.ReferenceView
}
type Limits struct {
	MaxReferences, MaxWitnesses, MaxEntries, MaxXMLBytes int
	MaxResultBytes, MaxReadBytes                         uint64
}
type ResourceIdentity struct {
	SHA1, SHA256, ProvenanceDigest string
	Size                           uint64
	References                     uint32
}
type boundResource struct {
	identity  ResourceIdentity
	reference int
}

func (r boundResource) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Identity  ResourceIdentity
		Reference int
	}{r.identity, r.reference})
}

type BoundRecipe struct {
	state     Descriptor
	metadata  *wimindex.MetadataArtifact
	view      *wimcontent.ReferenceView
	resources []boundResource
	xml       []byte
	flags     uint32
}

func (r *BoundRecipe) Descriptor() Descriptor {
	s := r.state
	s.Recipe.Requirements = slices.Clone(s.Recipe.Requirements)
	s.Recipe.Gaps = slices.Clone(s.Recipe.Gaps)
	s.Expected = slices.Clone(s.Expected)
	s.PermittedOperations = slices.Clone(s.PermittedOperations)
	return s
}
func (r *BoundRecipe) XML() []byte         { return slices.Clone(r.xml) }
func (r *BoundRecipe) HeaderFlags() uint32 { return r.flags }
func (r *BoundRecipe) CheckLive() error {
	if r == nil || r.metadata == nil || r.view == nil {
		return ErrInput
	}
	if _, e := r.metadata.ReadAt(nil, 0); e != nil {
		return e
	}
	return r.view.CheckLive()
}
func (r *BoundRecipe) Resource(n int) (ResourceIdentity, io.ReaderAt, error) {
	if e := r.CheckLive(); e != nil {
		return ResourceIdentity{}, nil, e
	}
	if n < 0 || n >= len(r.resources) {
		return ResourceIdentity{}, nil, ErrInput
	}
	v := r.resources[n]
	if n == 0 {
		return v.identity, r.metadata, nil
	}
	a, e := r.view.Content(v.reference, 0)
	return v.identity, a, e
}

func bounds(l Limits) (Limits, error) {
	for i, p := range []*int{&l.MaxReferences, &l.MaxWitnesses, &l.MaxEntries, &l.MaxXMLBytes} {
		cap := []int{262144, 524288, 262144, 1 << 20}[i]
		if *p < 0 || *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	for i, p := range []*uint64{&l.MaxResultBytes, &l.MaxReadBytes} {
		cap := []uint64{512 << 20, 64 << 30}[i]
		if *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	return l, nil
}
func contextValid(ctx context.Context) error {
	if ctx == nil {
		return ErrInput
	}
	return ctx.Err()
}
