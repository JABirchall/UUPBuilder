// Package wimindex indexes source-bound descriptors and separately verifies
// standard metadata-resource bytes. Neither establishes file-stream/security
// closure or authorizes conversion.
package wimindex

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

var (
	ErrInput     = errors.New("invalid WIM index source reference")
	ErrIntegrity = errors.New("WIM index source integrity changed")
	ErrLayout    = errors.New("malformed WIM resource layout")
	ErrConflict  = errors.New("conflicting WIM resource identities")
	ErrLimit     = errors.New("WIM index limit exceeded")
)

// Zero selects the hard ceilings: 64 containers, 262144 entries per container,
// 524288 total entries, and 1 MiB of XML per container. Callers may lower them.
// Records are read in 50000-byte batches and complete source hashes in 64 KiB
// blocks. No complete source or declared table is allocated.
type Limits struct{ MaxContainers, MaxEntries, MaxTotalEntries, MaxXMLBytes int }

type Descriptor struct {
	Size, Offset, Original uint64
	Flags                  byte
}
type Header struct {
	Version, Flags, ChunkSize    uint32
	GUID                         string
	Part, TotalParts             uint16
	ImageCount, BootIndex        uint32
	Lookup, XML, Boot, Integrity Descriptor
}
type Location struct {
	// ResourceEntry is a 1-based lookup-table ordinal, including for solid
	// backing resources. LogicalOffset is within the decoded backing resource;
	// only PhysicalOffset/PhysicalSize address source file bytes. Compression
	// uses 0=raw, 1=XPRESS, 2=LZX, 3=LZMS; ChunkSize=0 for a raw resource.
	ResourceEntry                                                    uint32
	PhysicalOffset, PhysicalSize, ResourceLogicalSize, LogicalOffset uint64
	ChunkSize, Compression                                           uint32
}
type Entry struct {
	Ordinal     uint32
	Descriptor  Descriptor
	Part        uint16
	References  uint32
	SHA1, Kind  string
	LogicalSize uint64
	Located     bool
	Location    Location
	ImageIndex  uint32
}
type Image struct {
	Index, MetadataEntry                             uint32
	Architecture, Edition, InstallationType, Version string
}
type Container struct {
	Payload         model.PayloadIdentity
	SourceSHA256    string
	SourceRehashed  bool
	Header          Header
	Entries         []Entry
	Images          []Image
	MappingComplete bool
}
type Gap struct {
	Payload                    model.PayloadIdentity
	Entry                      uint32
	Classification, Capability string
}
type Snapshot struct {
	Schema                                         int
	Source                                         model.SourceIdentity
	ManifestDigest                                 string
	Containers                                     []Container
	Gaps                                           []Gap
	Complete, ContentVerified, ConversionSupported bool
}
type Witness struct {
	Source         model.SourceIdentity
	ManifestDigest string
	Payload        model.PayloadIdentity
	Entry          uint32
	Kind           string
	LogicalSize    uint64
	Location       Location
}

// Index owns only immutable values; all accessors return independent copies.
// Complete means every requested descriptor was interpreted, not file closure.
type Index struct {
	state     Snapshot
	digest    string
	witnesses map[string][]Witness
}

func (i *Index) Snapshot() Snapshot {
	s := i.state
	s.Gaps = slices.Clone(s.Gaps)
	s.Containers = slices.Clone(s.Containers)
	for n := range s.Containers {
		s.Containers[n].Entries = slices.Clone(s.Containers[n].Entries)
		s.Containers[n].Images = slices.Clone(s.Containers[n].Images)
	}
	return s
}
func (i *Index) MarshalJSON() ([]byte, error) { return json.Marshal(i.state) }
func (i *Index) Digest() string               { return i.digest }
func (i *Index) Lookup(sha1 string) []Witness { return append([]Witness(nil), i.witnesses[sha1]...) }

// Open indexes exactly the supplied sources, each of which must match an exact
// identity in the frozen manifest. Their files are borrowed read-only and remain
// open from initial verification through parsing and the final rehash. Gaps are
// observations of unimplemented capabilities; malformed/conflicting data and
// failed source verification return errors and no index. No public value retains
// a local path, an open handle, a download locator, or a capability token.
func Open(ctx context.Context, manifest model.PayloadManifest, files []metadata.LocalResource, limits Limits) (*Index, error) {
	return openIndex(ctx, manifest, files, limits)
}
