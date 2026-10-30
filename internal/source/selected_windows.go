package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"path"
	"strings"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/providers"
	"uupbuilder/internal/model"
)

const SelectedUpdateID = "8f550c54-da87-45d3-89e3-0c03a6f16ae8"
const SelectedBaseSHA256 = "667d6741a883bb2c6b0860668784da62936a11f08090f2bee98ae561fad2c2c6"

// SelectedDocuments returns only source-bound CompDB bytes already acquired by
// this catalogue. It does not grant a semantic or mutation capability.
func (c *SourceAppCatalog) SelectedDocuments(ctx context.Context, s AppCatalogSnapshot) ([]metadata.Document, error) {
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if c.cachedID != s.CAB || !verifiedCAB(s.CAB, c.cachedCAB) {
		return nil, ErrInputIdentityChanged
	}
	var out []metadata.Document
	for _, ref := range s.Documents {
		outer, inner, ok := strings.Cut(ref.Resource.Member, "/")
		if !ok {
			return nil, ErrInputIdentityChanged
		}
		raw, e := metadata.ReadCABMetadata(ctx, c.cachedCAB, []string{outer})
		if e != nil {
			return nil, e
		}
		xmls, e := metadata.ReadCABMetadata(ctx, raw[outer], []string{inner})
		if e != nil {
			return nil, e
		}
		body := xmls[inner]
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != ref.SHA256 {
			return nil, ErrInputIdentityChanged
		}
		out = append(out, metadata.Document{Reference: ref, Format: metadata.FormatCompositionXML, Original: body, Provenance: "uupbuilder:selected-catalog-compdb-v1"})
	}
	return out, nil
}

type SelectedFetcher interface {
	Fetch(context.Context, model.PayloadManifest, model.Locators, model.Emit) (download.Materialized, error)
}

// SelectedAppPayloads follows source feature -> package ID -> payload path,
// preserving the original neutral query. It never treats filenames as families.
func SelectedAppPayloads(ctx context.Context, s AppCatalogSnapshot, documents []metadata.Document, requested []string) ([]model.Payload, error) {
	features := map[string]AppCatalogEntry{}
	for _, entry := range s.Entries {
		features[strings.ToLower(entry.FeatureID)] = entry
	}
	var queue []string
	for _, id := range requested {
		queue = append(queue, strings.ToLower(id))
	}
	seen := map[string]bool{}
	packages := map[string]bool{}
	for i := 0; i < len(queue); i++ {
		key := queue[i]
		if seen[key] {
			continue
		}
		seen[key] = true
		entry, ok := features[key]
		if !ok {
			return nil, fmt.Errorf("requested app has no source feature: %s", key)
		}
		for _, dep := range entry.Dependencies {
			if dep.Type == "Required" {
				queue = append(queue, strings.ToLower(dep.FeatureID))
			}
		}
		for _, media := range entry.Media {
			packages[media.PackageID] = true
		}
		for _, pack := range entry.Packages {
			packages[pack.ID] = true
		}
	}
	// Parse the package/path table with the existing bounded composition parser.
	// Only its observed paths/sizes select catalog identities; policy is bound
	// later from real Appx/bundle manifests and embedded licenses.
	var appDoc *metadata.Document
	for i := range documents {
		if strings.Contains(strings.ToLower(documents[i].Reference.Resource.Member), "app_neutral") {
			appDoc = &documents[i]
		}
	}
	if appDoc == nil {
		return nil, ErrInputIdentityChanged
	}
	return selectCompDBPayloads(ctx, *appDoc, s.AppManifest, packages)
}

func selectCompDBPayloads(ctx context.Context, doc metadata.Document, manifest model.PayloadManifest, selected map[string]bool) ([]model.Payload, error) {
	if _, err := metadata.ObserveAppCompDB(ctx, doc.Original); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(doc.Original)
	if hex.EncodeToString(sum[:]) != doc.Reference.SHA256 {
		return nil, ErrInputIdentityChanged
	}
	var parsed struct {
		Packages []struct {
			ID       string `xml:"ID,attr"`
			Payloads []struct {
				Path string `xml:"Path,attr"`
				Size int64  `xml:"PayloadSize,attr"`
			} `xml:"Payload>PayloadItem"`
		} `xml:"Packages>Package"`
	}
	if err := xml.Unmarshal(doc.Original, &parsed); err != nil {
		return nil, err
	}
	byName := map[string]model.Payload{}
	for _, p := range manifest.Payloads {
		byName[strings.ToLower(p.Destination)] = p
	}
	var out []model.Payload
	seen := map[model.PayloadIdentity]bool{}
	found := map[string]bool{}
	for _, pack := range parsed.Packages {
		if !selected[pack.ID] {
			continue
		}
		found[pack.ID] = true
		for _, item := range pack.Payloads {
			name := path.Base(strings.ReplaceAll(item.Path, `\`, "/"))
			p, ok := byName[strings.ToLower(name)]
			if !ok || p.Identity.Size != item.Size {
				return nil, fmt.Errorf("app CompDB payload not present in exact catalog: %s", name)
			}
			if !seen[p.Identity] {
				out = append(out, p)
				seen[p.Identity] = true
			}
		}
	}
	if len(found) != len(selected) {
		return nil, fmt.Errorf("app CompDB package closure incomplete")
	}
	return out, nil
}

// ResolveSelected is the first production family route. Unsupported variants
// retain the existing resolver's diagnostics rather than receiving guessed facts.
func ResolveSelected(ctx context.Context, cat *catalog.Client, apps *SourceAppCatalog, fetch SelectedFetcher, selection model.Selection, settings model.ResolvedSettings, emit model.Emit) (Resolution, error) {
	out := Resolution{Selection: selection, Settings: settings}
	if selection.UpdateID != SelectedUpdateID || selection.Architecture != "amd64" || selection.Language != "en-gb" || len(selection.Editions) != 1 || !strings.EqualFold(selection.Editions[0], "Professional") {
		return out, ErrImplementationGap
	}
	if settings.Apps.Preset != "" || len(settings.Apps.Include) == 0 {
		return out, fmt.Errorf("selected-source composition currently requires explicit source app family requests")
	}
	snapshot, e := apps.Load(ctx, selection)
	if e != nil {
		return out, e
	}
	if snapshot.State != AppCatalogAvailable {
		return out, ErrImplementationGap
	}
	docs, e := apps.SelectedDocuments(ctx, snapshot)
	if e != nil {
		return out, e
	}
	selected, e := SelectedAppPayloads(ctx, snapshot, docs, settings.Apps.Include)
	if e != nil {
		return out, e
	}
	base, e := cat.Files(ctx, selection.UpdateID, selection.Language, selection.Editions[0])
	if e != nil {
		return out, e
	}
	appSet, e := cat.Files(ctx, selection.UpdateID, "neutral", snapshot.AppQuery.Edition)
	if e != nil {
		return out, e
	}
	q := snapshot.AppQuery
	q.Projection = selected
	manifest, locators, e := Union(base.Source, []catalog.FileSet{base, appSet}, model.SourceQuery{UpdateID: selection.UpdateID, Language: selection.Language, Edition: selection.Editions[0]}, q)
	if e != nil {
		return out, e
	}
	files, e := fetch.Fetch(ctx, manifest, locators, emit)
	if e != nil {
		return out, e
	}
	inv, e := InspectSelected(ctx, manifest, files, docs)
	if e != nil {
		return out, e
	}
	out.Manifest = manifest
	out.Locators = locators
	out.Inventory = inv
	out.Classification = inv.Classification
	out.AppPhase = metadata.PhaseOfflineProvisioning
	return out, nil
}

// InspectSelected verifies the observed WIM/app documents and exact known
// source/update closure. Materialized paths remain borrowed, never serialized.
func InspectSelected(ctx context.Context, manifest model.PayloadManifest, files download.Materialized, docs []metadata.Document) (metadata.Inventory, error) {
	var out metadata.Inventory
	var main model.Payload
	req := metadata.InspectRequest{Source: manifest.Source, Manifest: manifest}
	for _, payload := range manifest.Payloads {
		file := files[payload.Identity]
		if file.Identity != payload.Identity {
			return out, ErrInputIdentityChanged
		}
		if payload.Identity.Digest.Value == SelectedBaseSHA256 {
			main = payload
			req.Inspections = append(req.Inspections, metadata.Inspection{Resource: metadata.LocalResource{Identity: payload.Identity, Path: file.Path}, Provider: providers.WIM{}})
		}
		switch strings.ToLower(path.Ext(payload.Destination)) {
		case ".msix", ".appx", ".msixbundle", ".appxbundle":
			req.Inspections = append(req.Inspections, metadata.Inspection{Resource: metadata.LocalResource{Identity: payload.Identity, Path: file.Path}, Provider: providers.Appx{}})
		}
	}
	if main.Identity.Size == 0 {
		return out, ErrInputIdentityChanged
	}
	inv, e := metadata.Inspect(ctx, req)
	if e != nil {
		return out, e
	}
	for _, doc := range docs {
		inv.Documents = append(inv.Documents, doc)
		if strings.Contains(strings.ToLower(doc.Reference.Resource.Member), "app_neutral") {
			inv, e = metadata.BindAppPolicies(ctx, inv, doc.Reference)
			if e != nil {
				return out, e
			}
		}
	}
	if e = completeSelectedInventory(ctx, &inv, files); e != nil {
		return out, e
	}
	return inv, nil
}
