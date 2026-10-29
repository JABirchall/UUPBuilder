package wimindex

import (
	"context"
	"io"
	"reflect"

	"uupbuilder/internal/model"
)

// ContentClaim and ContentContainer contain values/counts only. Consumers charge
// their lower allocation budgets before traversing entries or reparsing. They
// do not assert file bytes or grant source-reader authority.
type ContentClaim struct {
	Source                                                     model.SourceIdentity
	ManifestDigest, IndexDigest                                string
	Containers, Entries, Metadata, NonMetadata, SolidResources int
	Verified, Complete                                         bool
}
type ContentContainer struct {
	Payload                         model.PayloadIdentity
	SourceSHA256                    string
	Header                          Header
	Entries                         int
	SourceRehashed, MappingComplete bool
}

func (i *Index) ContentClaim() ContentClaim {
	if i == nil || i.digest == "" {
		return ContentClaim{}
	}
	c := ContentClaim{Source: i.state.Source, ManifestDigest: i.state.ManifestDigest, IndexDigest: i.digest, Containers: len(i.state.Containers), Verified: true, Complete: i.state.Complete}
	for _, v := range i.state.Containers {
		c.Entries += len(v.Entries)
		for _, e := range v.Entries {
			switch e.Kind {
			case "metadata":
				c.Metadata++
			case "solid-resource":
				c.SolidResources++
			case "ordinary", "solid-blob":
				c.NonMetadata++
			}
		}
	}
	return c
}
func (i *Index) ContentContainerAt(n int) (ContentContainer, bool) {
	if i == nil || i.digest == "" || n < 0 || n >= len(i.state.Containers) {
		return ContentContainer{}, false
	}
	c := i.state.Containers[n]
	return ContentContainer{c.Payload, c.SourceSHA256, c.Header, len(c.Entries), c.SourceRehashed, c.MappingComplete}, true
}
func (i *Index) ContentEntryAt(container, entry int) (Entry, bool) {
	if i == nil || i.digest == "" || container < 0 || container >= len(i.state.Containers) || entry < 0 || entry >= len(i.state.Containers[container].Entries) {
		return Entry{}, false
	}
	return i.state.Containers[container].Entries[entry], true
}

// CompareContentContainer is ONLY a framing comparison against this original
// index, not verification of a source or receipt. The consumer must keep the
// exact source handle, independently verify original hashes/path identity both
// before and after, and charge the reparse allocation before calling. A zero
// entry allowance is exhausted, never the parser's default.
func (i *Index) CompareContentContainer(ctx context.Context, n int, r io.ReaderAt, entryAllowance int) error {
	c, ok := i.ContentContainerAt(n)
	if !ok || ctx == nil || r == nil {
		return ErrInput
	}
	if entryAllowance <= 0 || c.Entries > entryAllowance || entryAllowance > 524288 {
		return ErrLimit
	}
	actual, _, e := readContainer(ctx, r, uint64(c.Payload.Size), c.Payload, Limits{64, min(entryAllowance, 262144), entryAllowance, 1 << 20}, entryAllowance)
	if e != nil {
		return e
	}
	actual.SourceSHA256 = c.SourceSHA256
	actual.SourceRehashed = c.SourceRehashed
	if !reflect.DeepEqual(actual, i.state.Containers[n]) {
		return ErrIntegrity
	}
	return nil
}
