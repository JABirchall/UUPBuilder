package source

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"uupbuilder/internal/metadata/wimcontent"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

var ErrMediaShape = errors.New("source image is not a supported plain media file tree")

// MediaTreeDescriptor is source evidence, never an asserted Setup role or an
// operational capability. Windows security/record bytes remain in Metadata.
type MediaTreeDescriptor struct {
	Source                                                                                         model.SourceIdentity
	ManifestDigest, OriginalXMLSHA256, ReferenceDigest, ResourceDigest, EntriesDigest, ProofDigest string
	Index                                                                                          wimindex.ContentClaim
	Metadata                                                                                       wimindex.MetadataReceipt
	Oracle                                                                                         wimmeta.Claim
	Entries, Files, Directories, Resources                                                         int
	ResourceBytes, AccountedBytes                                                                  uint64
	ReservedPaths                                                                                  []string
}

// MediaEntry maps a logical ISO path to verified source bytes. RecordSHA256
// binds original timestamps, attributes and security IDs without claiming that
// an ISO file tree applies NTFS metadata. Resource -1 is directory/empty.
type MediaEntry struct {
	Path, RecordSHA256, SHA1, SHA256, ProvenanceDigest string
	Directory                                          bool
	Resource                                           int
	Size                                               uint64
}

type BoundMediaTree struct {
	state     MediaTreeDescriptor
	entries   []MediaEntry
	resources []boundResource
	metadata  *wimindex.MetadataArtifact
	oracle    *wimmeta.Oracle
	view      *wimcontent.ReferenceView
}

func (r *BoundMediaTree) Descriptor() MediaTreeDescriptor {
	if r == nil {
		return MediaTreeDescriptor{}
	}
	d := r.state
	d.ReservedPaths = slices.Clone(d.ReservedPaths)
	return d
}
func (r *BoundMediaTree) CheckLive() error {
	if r == nil || r.metadata == nil || r.oracle == nil || r.view == nil || r.oracle.Claim() != r.state.Oracle {
		return ErrInput
	}
	if _, e := r.metadata.ReadAt(nil, 0); e != nil {
		return e
	}
	return r.view.CheckLive()
}
func (r *BoundMediaTree) EntryAt(n int) (MediaEntry, error) {
	if e := r.CheckLive(); e != nil {
		return MediaEntry{}, e
	}
	if n < 0 || n >= len(r.entries) {
		return MediaEntry{}, ErrInput
	}
	return r.entries[n], nil
}
func (r *BoundMediaTree) Resource(n int) (ResourceIdentity, io.ReaderAt, error) {
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

// BindMediaTree consumes live producers for a non-Windows file image. It does
// not use NAME, index position or catalogue filenames as roles. Rich Windows
// trees must remain in WIM; this slice refuses to flatten them. Reserved image
// destinations describe outputs that have not been produced.
func BindMediaTree(ctx context.Context, in Inputs, reserved []string, limits Limits) (*BoundMediaTree, error) {
	if e := contextValid(ctx); e != nil {
		return nil, e
	}
	l, e := bounds(limits)
	if e != nil {
		return nil, e
	}
	if e = validManifestInput(in, l); e != nil {
		return nil, e
	}
	if len(reserved) == 0 || len(reserved) > 64 {
		return nil, ErrInput
	}
	targets := make([]string, 0, len(reserved))
	for _, p := range reserved {
		if len(p) > 4096 {
			return nil, ErrLimit
		}
		v, e := model.ValidateRelativePath(p)
		if e != nil || v != p {
			return nil, ErrInput
		}
		key := strings.ToLower(v)
		for _, old := range targets {
			if key == old || strings.HasPrefix(key, old+"/") || strings.HasPrefix(old, key+"/") {
				return nil, ErrInput
			}
		}
		targets = append(targets, key)
	}
	if in.Index == nil || in.Metadata == nil || in.Oracle == nil || in.References == nil {
		return nil, ErrInput
	}
	index, oracle, view := in.Index.ContentClaim(), in.Oracle.Claim(), in.References.Claim()
	receipt := in.Metadata.Receipt()
	if !index.Verified || !oracle.Verified || !oracle.MetadataComplete || !view.Verified || !view.ReferenceClosure || index.Source != in.Manifest.Source || index.ManifestDigest != in.Manifest.Digest || oracle.Receipt != receipt || view.Oracle != oracle || !in.Index.MatchesMetadataReceipt(receipt) {
		return nil, ErrInput
	}
	if view.References != oracle.References || view.References > l.MaxReferences || oracle.Summary.Entries > l.MaxEntries {
		return nil, ErrLimit
	}
	accounted := oracle.Summary.AccountedBytes + receipt.Size*2 + uint64(oracle.Summary.Entries)*2048 + uint64(oracle.References)*128 + receipt.Header.XML.Size*16 + 4096
	if accounted > l.MaxResultBytes {
		return nil, ErrLimit
	}
	resources, e := bindReferences(ctx, in, view, l, &accounted)
	if e != nil {
		return nil, e
	}
	if receipt.Size*2 > l.MaxReadBytes || uint64(receipt.Payload.Size)*2+receipt.Header.XML.Size > l.MaxReadBytes-receipt.Size*2 {
		return nil, ErrLimit
	}
	if e = verifyMetadata(ctx, in.Metadata, receipt); e != nil {
		return nil, e
	}
	_, original, inv, e := selectedXML(ctx, in, receipt, l)
	if e != nil {
		return nil, e
	}
	im := inv.Images[0]
	if im.Architecture != "" || im.Edition != "" || im.InstallationType != "" {
		return nil, ErrMediaShape
	}
	snap := in.Oracle.Snapshot()
	if len(snap.Entries) == 0 || snap.Entries[0].Path != "/" || snap.Entries[0].Attributes&16 == 0 {
		return nil, ErrMediaShape
	}
	entries := make([]MediaEntry, 0, len(snap.Entries)-1)
	seen := map[string]bool{}
	d := MediaTreeDescriptor{Source: in.Manifest.Source, ManifestDigest: in.Manifest.Digest, OriginalXMLSHA256: original, ReferenceDigest: view.Digest, Index: index, Metadata: receipt, Oracle: oracle, Resources: len(resources), AccountedBytes: accounted, ReservedPaths: slices.Clone(reserved)}
	for i, en := range snap.Entries {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		if !en.PathValid || en.Attributes&(0x400|0x4000) != 0 || en.HardlinkID != 0 || en.ReparseTag != 0 || len(en.ShortName) != 0 || len(en.Tags) != 0 || len(en.Streams) != 1 || len(en.Streams[0].Name) != 0 {
			return nil, ErrMediaShape
		}
		s := en.Streams[0]
		dir := en.Attributes&16 != 0
		if dir && (s.SHA1 != "0000000000000000000000000000000000000000" || s.Kind != "directory-placeholder") || !dir && s.Kind != "data" {
			return nil, ErrMediaShape
		}
		if i == 0 {
			continue
		}
		p := strings.TrimPrefix(en.Path, "/")
		v, e := model.ValidateRelativePath(p)
		if e != nil || v != p {
			return nil, ErrMediaShape
		}
		key := strings.ToLower(p)
		if _, exists := seen[key]; exists {
			return nil, ErrMediaShape
		}
		seen[key] = dir
		for _, target := range targets {
			if key == target || strings.HasPrefix(key, target+"/") || !dir && strings.HasPrefix(target, key+"/") {
				return nil, ErrMediaShape
			}
		}
		entry := MediaEntry{Path: p, Directory: dir, RecordSHA256: digest(en), Resource: -1}
		if !dir {
			d.Files++
			if s.SHA1 == "0000000000000000000000000000000000000000" {
				entry.SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
				entry.SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
				entry.ProvenanceDigest = digest(en)
			} else {
				n := s.Reference + 1
				if s.Reference < 0 || n >= len(resources) || resources[n].identity.SHA1 != s.SHA1 {
					return nil, ErrInput
				}
				id := resources[n].identity
				if s.SizeKnown && s.Size != id.Size {
					return nil, ErrIntegrity
				}
				entry.Resource = n
				entry.Size = id.Size
				entry.SHA1 = id.SHA1
				entry.SHA256 = id.SHA256
				entry.ProvenanceDigest = id.ProvenanceDigest
				if resources[n].identity.References == ^uint32(0) {
					return nil, ErrLimit
				}
				resources[n].identity.References++
			}
		} else {
			d.Directories++
		}
		entries = append(entries, entry)
	}
	for _, en := range entries {
		if at := strings.LastIndex(en.Path, "/"); at >= 0 {
			if dir, ok := seen[strings.ToLower(en.Path[:at])]; !ok || !dir {
				return nil, ErrMediaShape
			}
		}
	}
	for i, r := range resources {
		if i > 0 && r.identity.References == 0 {
			return nil, ErrInput
		}
		d.ResourceBytes += r.identity.Size
	}
	d.Entries = len(entries)
	d.ResourceDigest = digest(resources)
	d.EntriesDigest = digest(entries)
	d.ProofDigest = digest(d)
	r := &BoundMediaTree{state: d, entries: entries, resources: resources, metadata: in.Metadata, oracle: in.Oracle, view: in.References}
	if e = verifyMetadata(ctx, in.Metadata, receipt); e != nil {
		return nil, e
	}
	if e = r.CheckLive(); e != nil {
		return nil, e
	}
	return r, nil
}
