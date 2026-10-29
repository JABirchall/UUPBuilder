package wimindex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

func bounded(l Limits) (Limits, error) {
	values := []*int{&l.MaxContainers, &l.MaxEntries, &l.MaxTotalEntries, &l.MaxXMLBytes}
	ceilings := []int{64, 262144, 524288, 1 << 20}
	for i, v := range values {
		if *v < 0 || *v > ceilings[i] {
			return l, ErrLimit
		}
		if *v == 0 {
			*v = ceilings[i]
		}
	}
	return l, nil
}

func openIndex(ctx context.Context, manifest model.PayloadManifest, files []metadata.LocalResource, limits Limits) (*Index, error) {
	if ctx == nil {
		return nil, ErrInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l, err := bounded(limits)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 || len(files) > l.MaxContainers {
		return nil, ErrInput
	}
	// Freeze nested caller slices before using their identities or canonical order.
	manifest = model.PayloadManifest{Source: manifest.Source, Payloads: slices.Clone(manifest.Payloads), Queries: model.CloneSourceQueries(manifest.Queries), Digest: manifest.Digest}
	if manifest.Validate() != nil {
		return nil, ErrInput
	}
	files = slices.Clone(files)
	seen := map[model.PayloadIdentity]bool{}
	for _, f := range files {
		if f.Identity.Validate() != nil || f.Identity.Encryption.Method != "" {
			return nil, ErrInput
		}
		found := false
		for _, p := range manifest.Payloads {
			if p.Identity == f.Identity {
				found = true
				break
			}
		}
		if !found || seen[f.Identity] {
			return nil, ErrInput
		}
		seen[f.Identity] = true
	}
	slices.SortFunc(files, func(a, b metadata.LocalResource) int {
		if a.Identity.Provenance.Name < b.Identity.Provenance.Name {
			return -1
		}
		if a.Identity.Provenance.Name > b.Identity.Provenance.Name {
			return 1
		}
		if a.Identity.Key() < b.Identity.Key() {
			return -1
		}
		return 1
	})
	idx := &Index{state: Snapshot{Schema: 1, Source: manifest.Source, ManifestDigest: manifest.Digest, Complete: true}, witnesses: map[string][]Witness{}}
	total := 0
	for _, f := range files {
		c, gaps, err := inspectSource(ctx, f, l, l.MaxTotalEntries-total)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Identity.Provenance.Name, err)
		}
		total += len(c.Entries)
		idx.state.Containers = append(idx.state.Containers, c)
		idx.state.Gaps = append(idx.state.Gaps, gaps...)
	}
	for _, c := range idx.state.Containers {
		first := map[string]Witness{}
		for _, e := range c.Entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if e.Located && e.Kind != "solid-resource" && e.SHA1 == zeroSHA1 {
				idx.state.Gaps = append(idx.state.Gaps, gap(c.Payload, e.Ordinal, "missing-blob-SHA1"))
			}
			if !e.Located || e.Kind == "solid-resource" || e.SHA1 == zeroSHA1 || e.LogicalSize == 0 {
				continue
			}
			w := Witness{Source: manifest.Source, ManifestDigest: manifest.Digest, Payload: c.Payload, Entry: e.Ordinal, Kind: e.Kind, LogicalSize: e.LogicalSize, Location: e.Location}
			if all := idx.witnesses[e.SHA1]; len(all) != 0 && all[0].LogicalSize != w.LogicalSize {
				return nil, ErrConflict
			}
			if prev, ok := first[e.SHA1]; ok {
				a, b := prev.Location, w.Location
				a.ResourceEntry, b.ResourceEntry = 0, 0
				if a != b || prev.Kind != w.Kind {
					idx.state.Gaps = append(idx.state.Gaps, gap(c.Payload, e.Ordinal, "ambiguous-duplicate-location"))
				}
			} else {
				first[e.SHA1] = w
			}
			idx.witnesses[e.SHA1] = append(idx.witnesses[e.SHA1], w)
		}
	}
	idx.state.Complete = len(idx.state.Gaps) == 0
	b, err := idx.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	idx.digest = hex.EncodeToString(sum[:])
	return idx, nil
}
func gap(p model.PayloadIdentity, entry uint32, capability string) Gap {
	return Gap{Payload: p, Entry: entry, Classification: "implementation-gap", Capability: capability}
}
func inspectSource(ctx context.Context, f metadata.LocalResource, l Limits, remaining int) (Container, []Gap, error) {
	var c Container
	v, err := openSource(ctx, f)
	if err != nil {
		return c, nil, err
	}
	defer v.file.Close()
	before, err := v.rehash()
	if err != nil {
		return c, nil, err
	}
	c, gaps, err := readContainer(ctx, v, uint64(f.Identity.Size), f.Identity, l, remaining)
	if err != nil {
		return c, nil, err
	}
	after, err := v.rehash()
	if err != nil {
		return c, nil, err
	}
	if before != after {
		return c, nil, ErrIntegrity
	}
	c.SourceSHA256 = after
	c.SourceRehashed = true
	return c, gaps, nil
}
