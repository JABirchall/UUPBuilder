//go:build windows

package source

import (
	"context"
	"fmt"
	"strings"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/providers"
	"uupbuilder/internal/model"
)

type Discovery struct{ Catalog Catalog }

// Metadata routes a single bounded aggregated CAB into semantic inspection.
// Candidate member names do not establish roles, edition bases or buildability.
// Unsupported historical/future layouts remain visible implementation gaps.
func (d *Discovery) Metadata(ctx context.Context, s model.Selection) (MetadataPlan, error) {
	if ctx == nil || s.Validate() != nil {
		return MetadataPlan{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return MetadataPlan{}, err
	}
	if d == nil || d.Catalog == nil {
		return MetadataPlan{}, ErrImplementationGap
	}
	editions, err := d.Catalog.Editions(ctx, s.UpdateID, s.Language)
	if err != nil {
		return MetadataPlan{}, err
	}
	selector := ""
	for _, requested := range s.Editions {
		for _, available := range editions {
			if strings.EqualFold(available.ID, requested) {
				selector = available.ID
				break
			}
		}
		if selector != "" {
			break
		}
	}
	// A derived-only request needs U08's inspected base rules. A filename or an
	// arbitrary advertised edition cannot silently choose that base.
	if selector == "" {
		return MetadataPlan{}, fmt.Errorf("%w: requested edition has no advertised bootstrap base; semantic derivation rules are required", ErrImplementationGap)
	}
	set, err := d.Catalog.Files(ctx, s.UpdateID, s.Language, selector)
	if err != nil {
		return MetadataPlan{}, err
	}
	if set.Source.Validate() != nil || set.Source.UpdateID != s.UpdateID || set.Source.Architecture != s.Architecture || set.Source.Language != s.Language {
		return MetadataPlan{}, ErrInputIdentityChanged
	}
	if _, _, err := Union(set.Source, []catalog.FileSet{set}); err != nil {
		return MetadataPlan{}, err
	}
	p, ok := metadataCAB(set)
	if !ok {
		name := selector + "_" + s.Language + ".esd"
		var found []model.Payload
		for _, candidate := range set.Payloads {
			if strings.EqualFold(candidate.Destination, name) {
				found = append(found, candidate)
			}
		}
		if len(found) != 1 {
			return MetadataPlan{}, fmt.Errorf("%w: selected response has no unique aggregated CAB or selected WIM metadata candidate", ErrImplementationGap)
		}
		p = found[0]
		q := model.SourceQuery{UpdateID: s.UpdateID, Language: s.Language, Edition: selector, Projection: []model.Payload{p}}
		return MetadataPlan{Source: set.Source, Sets: []SourceSet{{Query: q, Files: set}}, Inputs: []MetadataInput{{Identity: p.Identity, Provider: providers.WIM{}}}}, nil
	}
	members := []string{}
	for _, edition := range s.Editions {
		members = append(members, "DesktopTargetCompDB_"+strings.ToLower(edition)+"_"+strings.ToLower(s.Language)+".xml.cab")
	}
	q := model.SourceQuery{UpdateID: s.UpdateID, Language: s.Language, Edition: selector, Projection: []model.Payload{p}}
	return MetadataPlan{Source: set.Source, Sets: []SourceSet{{Query: q, Files: set}}, Inputs: []MetadataInput{{Identity: p.Identity, Provider: providers.CAB{Members: members}}}}, nil
}

var _ metadata.ReadOnlyProvider = providers.WIM{}
