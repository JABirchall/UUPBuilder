package wimcontent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/model"
	"uupbuilder/internal/rawlzms"
)

type ProviderIdentity struct {
	DLL                                     rawlzms.Identity
	ProcessArchitecture, NativeArchitecture string
	WindowsBuild                            uint32
}
type SourceReceipt struct {
	Payload  model.PayloadIdentity
	SHA256   string
	Header   wimindex.Header
	Rehashed bool
}
type BackingReceipt struct {
	Payload                                model.PayloadIdentity
	SourceSHA256                           string
	Header                                 wimindex.Header
	Entry                                  wimindex.Entry
	SHA256                                 string
	Size                                   uint64
	Chunks, CompressedChunks, StoredChunks int
}
type Witness struct {
	Payload      model.PayloadIdentity
	SourceSHA256 string
	Header       wimindex.Header
	Entry        wimindex.Entry
	SHA1, SHA256 string
	Size         uint64
	Backing      int
}
type Snapshot struct {
	Schema                                                    int
	Index                                                     wimindex.ContentClaim
	Provider                                                  ProviderIdentity
	Sources                                                   []SourceReceipt
	Backings                                                  []BackingReceipt
	Witnesses                                                 []Witness
	DecodedBytes, ReadBytes, AccountedBytes                   uint64
	ActiveNonMetadata, InactiveNonMetadata                    int
	NonMetadataVerified, ContentVerified, ConversionSupported bool
}

// Catalog contains immutable location-free evidence. NonMetadataVerified covers
// all original ordinary/solid-blob records in Index, including inactive records.
// Whole-index ContentVerified stays false without explicit B2 composition.
type Catalog struct {
	state  Snapshot
	digest string
}

func (c *Catalog) Snapshot() Snapshot {
	s := c.state
	s.Sources = slices.Clone(s.Sources)
	s.Backings = slices.Clone(s.Backings)
	s.Witnesses = slices.Clone(s.Witnesses)
	return s
}
func (c *Catalog) Digest() string {
	if c == nil {
		return ""
	}
	return c.digest
}
func (c *Catalog) MarshalJSON() ([]byte, error) { return json.Marshal(c.state) }
func seal(s Snapshot) (*Catalog, error) {
	b, e := json.Marshal(s)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(b)
	return &Catalog{s, hex.EncodeToString(h[:])}, nil
}

// Decode accepts only the frozen manifest, exact original immutable B1 index,
// and matching locals. It verifies retained source handles before live reparse
// and after every byte check. Errors discard the entire unpublished owned batch.
func Decode(ctx context.Context, m model.PayloadManifest, files []metadata.LocalResource, idx *wimindex.Index, l Limits) (*Result, error) {
	return decode(ctx, m, files, idx, l, systemCodec)
}
