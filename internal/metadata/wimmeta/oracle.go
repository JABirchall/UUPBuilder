// Package wimmeta interprets source-bound WIM metadata without reading file
// contents or granting conversion/image-operation capabilities.
package wimmeta

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"uupbuilder/internal/metadata/wimindex"
)

var (
	ErrLayout    = errors.New("malformed nested WIM metadata")
	ErrLimit     = errors.New("WIM metadata oracle limit exceeded")
	ErrInput     = errors.New("unbound WIM metadata artifact")
	ErrIntegrity = errors.New("WIM metadata artifact integrity changed")
)

// Zero values select hard ceilings; callers can only lower them: 64 MiB input,
// 512 MiB accounted result/bookkeeping, 262144 entries, depth 256, 524288 total
// streams/witnesses, 4096 streams per entry, 65536 security/extra records,
// 1048576 ACEs, and 1 MiB per variable field/security descriptor. Input is read
// and hashed in full within its separate cap. Accounting conservatively charges
// fixed record/map/slice overhead and variable copies before allocation; it is
// not a whole-process heap bound. Existing index memory, caller-owned accessor
// copies and temporary JSON encoding buffers are separate bounded allocations.
type Limits struct {
	MaxInputBytes, MaxResultBytes                                                                                  uint64
	MaxEntries, MaxDepth, MaxStreams, MaxStreamsPerEntry, MaxSecurity, MaxACEs, MaxVariableBytes, MaxSecurityBytes int
	MaxExtraFields, MaxWitnesses                                                                                   int
}
type Stream struct {
	Offset, Length, Reserved   uint64
	Name                       []uint16
	SHA1, Kind, SizeProvenance string
	Size                       uint64
	SizeKnown                  bool
	Reference                  int
	Padding                    []byte
}
type Entry struct {
	Offset, Length, ChildOffset         uint64
	Parent                              int
	Name, ShortName, PathUTF16          []uint16
	Path                                string
	PathValid                           bool
	Attributes, SecurityID              uint32
	Reserved                            [2]uint64
	CreationTime, AccessTime, WriteTime uint64
	Unknown84                           uint32
	HardlinkID                          uint64
	ReparseTag                          uint32
	ReparseReserved, ReparseFlags       uint16
	Padding                             []byte
	Tags                                []Tag
	Streams                             []Stream
}
type Tag struct {
	Offset        uint64
	Tag           uint32
	Data, Padding []byte
}
type SID struct {
	Offset uint32
	Raw    []byte
}
type ACE struct {
	Offset            uint32
	Type, Flags       byte
	Size              uint16
	Mask, ObjectFlags uint32
	SID               SID
	// Understood covers the supported stored ACE form, not host application or
	// authorization evaluation. Callback/unknown application data stays false.
	Understood bool
}
type ACL struct {
	Offset   uint32
	Revision byte
	Size     uint16
	ACEs     []ACE
}
type Security struct {
	Raw          []byte
	Owner, Group SID
	DACL, SACL   *ACL
}
type Gap struct {
	Kind   string
	Entry  int
	Offset uint64
	Detail string
}
type Reference struct {
	SHA1                 string
	Witnesses            []wimindex.Witness
	Size                 uint64
	SizeKnown, Ambiguous bool
}
type HardlinkGroup struct {
	ID         uint64
	Entries    []int
	Consistent bool
}
type Uninterpreted struct {
	Offset uint64
	Raw    []byte
}
type EndMarker struct{ Offset, Length uint64 }
type Summary struct {
	Entries, Directories, Streams, Security, ACEs, References, HardlinkGroups, Reparse, Gaps int
	AccountedBytes                                                                           uint64
}
type Snapshot struct {
	Schema                                                           int
	Receipt                                                          wimindex.MetadataReceipt
	SecurityLength                                                   uint32
	SecurityPadding                                                  []byte
	Entries                                                          []Entry
	EndMarkers                                                       []EndMarker
	Security                                                         []Security
	References                                                       []Reference
	Hardlinks                                                        []HardlinkGroup
	Uninterpreted                                                    []Uninterpreted
	Gaps                                                             []Gap
	Summary                                                          Summary
	MetadataVerified, Complete, ContentVerified, ConversionSupported bool
}

// Oracle owns immutable values only. MetadataVerified gates structural parsing
// on original bytes and exact source/index authority. Complete additionally
// requires all metadata semantics and references resolved; neither flag proves
// content or security reconstruction. Records use deterministic disk-order DFS.
type Oracle struct {
	state  Snapshot
	digest string
}

func (o *Oracle) Digest() string               { return o.digest }
func (o *Oracle) Summary() Summary             { return o.state.Summary }
func (o *Oracle) MarshalJSON() ([]byte, error) { return json.Marshal(o.state) }
func (o *Oracle) Snapshot() Snapshot {
	s := o.state
	s.SecurityPadding = slices.Clone(s.SecurityPadding)
	s.EndMarkers = slices.Clone(s.EndMarkers)
	s.Entries = slices.Clone(s.Entries)
	for i := range s.Entries {
		e := &s.Entries[i]
		e.Name = slices.Clone(e.Name)
		e.ShortName = slices.Clone(e.ShortName)
		e.PathUTF16 = slices.Clone(e.PathUTF16)
		e.Padding = slices.Clone(e.Padding)
		e.Tags = slices.Clone(e.Tags)
		for j := range e.Tags {
			e.Tags[j].Data = slices.Clone(e.Tags[j].Data)
			e.Tags[j].Padding = slices.Clone(e.Tags[j].Padding)
		}
		e.Streams = slices.Clone(e.Streams)
		for j := range e.Streams {
			e.Streams[j].Name = slices.Clone(e.Streams[j].Name)
			e.Streams[j].Padding = slices.Clone(e.Streams[j].Padding)
		}
	}
	s.Security = slices.Clone(s.Security)
	for i := range s.Security {
		v := &s.Security[i]
		v.Raw = slices.Clone(v.Raw)
		v.Owner.Raw = slices.Clone(v.Owner.Raw)
		v.Group.Raw = slices.Clone(v.Group.Raw)
		v.DACL = cloneACL(v.DACL)
		v.SACL = cloneACL(v.SACL)
	}
	s.References = slices.Clone(s.References)
	for i := range s.References {
		s.References[i].Witnesses = slices.Clone(s.References[i].Witnesses)
	}
	s.Hardlinks = slices.Clone(s.Hardlinks)
	for i := range s.Hardlinks {
		s.Hardlinks[i].Entries = slices.Clone(s.Hardlinks[i].Entries)
	}
	s.Uninterpreted = slices.Clone(s.Uninterpreted)
	for i := range s.Uninterpreted {
		s.Uninterpreted[i].Raw = slices.Clone(s.Uninterpreted[i].Raw)
	}
	s.Gaps = slices.Clone(s.Gaps)
	return s
}
func cloneACL(a *ACL) *ACL {
	if a == nil {
		return nil
	}
	v := *a
	v.ACEs = slices.Clone(v.ACEs)
	for i := range v.ACEs {
		v.ACEs[i].SID.Raw = slices.Clone(v.ACEs[i].SID.Raw)
	}
	return &v
}

// Parse borrows a B2 artifact; its caller retains ownership and must close it.
// No receipt, path, physical offset, arbitrary reader or codec can grant public
// authority. B1 construction and B2 already verified the exact source set.
func Parse(ctx context.Context, a *wimindex.MetadataArtifact, idx *wimindex.Index, l Limits) (*Oracle, error) {
	if ctx == nil || a == nil || idx == nil {
		return nil, ErrInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l, err := bounds(l)
	if err != nil {
		return nil, err
	}
	r := a.Receipt()
	if !idx.MatchesMetadataReceipt(r) {
		return nil, ErrInput
	}
	if r.Size > l.MaxInputBytes || r.Size < 8 || l.MaxResultBytes < 4096+(r.Size+63)/64 {
		return nil, ErrLimit
	}
	// A bounded full read is hashed before any semantic interpretation. Variable
	// result allocations have a separate, conservatively charged budget.
	b := make([]byte, int(r.Size))
	for off := 0; off < len(b); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := min(64<<10, len(b)-off)
		if got, err := a.ReadAt(b[off:off+n], int64(off)); err != nil || got != n {
			return nil, errors.Join(ErrIntegrity, err)
		}
		off += n
	}
	if !equalHashes(b, r) {
		return nil, ErrIntegrity
	}
	p, err := parseBytes(ctx, b, l)
	if err != nil {
		return nil, err
	}
	p.state.Receipt = r
	if err := p.resolve(idx); err != nil {
		return nil, err
	}
	p.state.MetadataVerified = true
	p.state.Complete = len(p.state.Gaps) == 0
	p.state.Summary.AccountedBytes = p.used
	serialized, err := json.Marshal(p.state)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(serialized)
	// Re-read the same artifact as the final publication gate, after traversal,
	// reference interpretation and digest construction. Errors publish nothing.
	if err := verifyArtifact(ctx, a, r); err != nil {
		return nil, err
	}
	return &Oracle{state: p.state, digest: hex.EncodeToString(digest[:])}, nil
}
func equalHashes(b []byte, r wimindex.MetadataReceipt) bool {
	h1, h256 := sha1.Sum(b), sha256.Sum256(b)
	return uint64(len(b)) == r.Size && hex.EncodeToString(h1[:]) == r.SHA1 && hex.EncodeToString(h256[:]) == r.SHA256
}
func verifyArtifact(ctx context.Context, a io.ReaderAt, r wimindex.MetadataReceipt) error {
	h1, h256 := sha1.New(), sha256.New()
	var buf [64 << 10]byte
	for off := uint64(0); off < r.Size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(uint64(len(buf)), r.Size-off)
		if got, err := a.ReadAt(buf[:n], int64(off)); err != nil || uint64(got) != n {
			return errors.Join(ErrIntegrity, err)
		}
		h1.Write(buf[:n])
		h256.Write(buf[:n])
		off += n
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if hex.EncodeToString(h1.Sum(nil)) != r.SHA1 || hex.EncodeToString(h256.Sum(nil)) != r.SHA256 {
		return ErrIntegrity
	}
	return nil
}

func bounds(l Limits) (Limits, error) {
	for i, p := range []*int{&l.MaxEntries, &l.MaxDepth, &l.MaxStreams, &l.MaxStreamsPerEntry, &l.MaxSecurity, &l.MaxACEs, &l.MaxVariableBytes, &l.MaxSecurityBytes, &l.MaxExtraFields, &l.MaxWitnesses} {
		cap := []int{262144, 256, 524288, 4096, 65536, 1048576, 1 << 20, 1 << 20, 65536, 524288}[i]
		if *p < 0 || *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	for i, p := range []*uint64{&l.MaxInputBytes, &l.MaxResultBytes} {
		cap := []uint64{64 << 20, 512 << 20}[i]
		if *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	return l, nil
}
