package wimcontent

import (
	"context"
	"slices"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/model"
)

func identityBytes(p model.PayloadIdentity) uint64 {
	return uint64(len(p.Provenance.Source) + len(p.Provenance.Name) + len(p.Digest.Value) + len(p.Digest.Algorithm) + len(p.Encryption.Method) + len(p.Encryption.Fingerprint))
}

type MetadataSnapshot struct {
	Index                                wimindex.ContentClaim
	ContentDigest                        string
	Metadata                             []wimindex.MetadataReceipt
	ReadBytes                            uint64
	ContentVerified, ConversionSupported bool
}

// MetadataComposition is an explicit whole-index byte proof. It borrows the
// nonmetadata owner and every live B2 artifact; metadata semantics remain those
// of the original oracle. Its value receipt is historical after parent Close.
type MetadataComposition struct {
	state     MetadataSnapshot
	content   *Result
	artifacts []*wimindex.MetadataArtifact
}

func (c *MetadataComposition) Snapshot() MetadataSnapshot {
	s := c.state
	s.Metadata = slices.Clone(s.Metadata)
	return s
}
func (c *MetadataComposition) CheckLive() error {
	if c == nil {
		return ErrInput
	}
	if e := c.content.live(); e != nil {
		return e
	}
	for _, a := range c.artifacts {
		if _, e := a.ReadAt(nil, 0); e != nil {
			return e
		}
	}
	return nil
}
func ComposeMetadata(ctx context.Context, r *Result, idx *wimindex.Index, artifacts []*wimindex.MetadataArtifact, limits Limits) (*MetadataComposition, error) {
	if ctx == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	l, e := bounds(limits)
	if e != nil {
		return nil, e
	}
	if e = r.live(); e != nil {
		return nil, e
	}
	claim := idx.ContentClaim()
	if !claim.Verified || claim != r.catalog.state.Index || len(artifacts) != claim.Metadata {
		return nil, ErrInput
	}
	if claim.Metadata > l.MaxResources || claim.Entries > l.MaxEntries || uint64(claim.Metadata)*4096 > l.MaxResultBytes || l.MaxBufferBytes < 64<<10 {
		return nil, ErrLimit
	}
	type key struct {
		payload model.PayloadIdentity
		ordinal uint32
	}
	expected := make(map[key]bool, claim.Metadata)
	for ci := 0; ci < claim.Containers; ci++ {
		c, _ := idx.ContentContainerAt(ci)
		for ei := 0; ei < c.Entries; ei++ {
			en, _ := idx.ContentEntryAt(ci, ei)
			if en.Kind == "metadata" {
				expected[key{c.Payload, en.Ordinal}] = false
			}
		}
	}
	var required uint64
	for _, w := range r.catalog.state.Backings {
		if w.Size > l.MaxReadBytes-required {
			return nil, ErrLimit
		}
		required += w.Size
	}
	for _, a := range artifacts {
		if a == nil {
			return nil, ErrInput
		}
		w := a.Receipt()
		k := key{w.Payload, w.Entry.Ordinal}
		seen, ok := expected[k]
		if !ok || seen || !idx.MatchesMetadataReceipt(w) {
			return nil, ErrInput
		}
		expected[k] = true
		if w.Size > l.MaxReadBytes-required {
			return nil, ErrLimit
		}
		required += w.Size
	}
	b := &readBudget{limit: l.MaxReadBytes}
	if e = r.verifyCurrent(ctx, b); e != nil {
		return nil, e
	}
	result := &MetadataComposition{state: MetadataSnapshot{Index: claim, ContentDigest: r.Catalog().Digest()}, content: r, artifacts: slices.Clone(artifacts)}
	for _, a := range artifacts {
		w := a.Receipt()
		h1, h256, e := hashInterval(ctx, a, 0, w.Size, b)
		if e != nil || h1 != w.SHA1 || h256 != w.SHA256 {
			return nil, joinIntegrity(e)
		}
		result.state.Metadata = append(result.state.Metadata, w)
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = result.CheckLive(); e != nil {
		return nil, e
	}
	result.state.ReadBytes = b.used
	result.state.ContentVerified = true
	return result, nil
}
