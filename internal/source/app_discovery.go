//go:build windows

package source

import (
	"context"
	"path"
	"strings"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/providers"
	"uupbuilder/internal/model"
)

// Apps consumes U03's materialized requests without rebuilding its catalog.
// Package manifests remain observations; source license/phase rules are separate.
func (*Discovery) Apps(ctx context.Context, s model.Selection, inv metadata.Inventory, sets []SourceSet) (AppDiscovery, error) {
	out := AppDiscovery{Phase: metadata.PhaseUnknown}
	if ctx == nil || s.Validate() != nil || inv.Source.Validate() != nil || inv.Manifest.Validate() != nil {
		return out, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if inv.Source.UpdateID != s.UpdateID || inv.Source.Architecture != s.Architecture || inv.Source.Language != s.Language || inv.Manifest.Source != inv.Source {
		return out, ErrInputIdentityChanged
	}
	for _, app := range inv.Apps.Packages {
		if app.Phase == metadata.PhasePostAssembly {
			if !boundEvidence(inv, app.PhaseEvidence) {
				return out, metadata.ErrInvalidEvidence
			}
			e := *app.PhaseEvidence
			out.Phase, out.Evidence = metadata.PhasePostAssembly, &e
		}
	}
	seen := map[model.PayloadIdentity]bool{}
	for _, set := range sets {
		if set.Query.Validate() != nil || set.Query.UpdateID != s.UpdateID || set.Query.Language != s.Language || set.Files.Source != inv.Source {
			return out, ErrInputIdentityChanged
		}
		frozen, _, err := Union(inv.Source, []catalog.FileSet{set.Files}, set.Query)
		if err != nil {
			return out, err
		}
		for _, p := range frozen.Payloads {
			if p.Validate() != nil {
				return out, ErrInvalidInput
			}
			if seen[p.Identity] {
				continue
			}
			seen[p.Identity] = true
			switch strings.ToLower(path.Ext(p.Destination)) {
			case ".appx", ".msix", ".appxbundle", ".msixbundle":
				out.Inputs = append(out.Inputs, MetadataInput{Identity: p.Identity, Provider: providers.Appx{}})
			}
		}
	}
	return out, nil
}
