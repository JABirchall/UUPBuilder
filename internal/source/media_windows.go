package source

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/providers"
	"uupbuilder/internal/model"
)

// MediaLayout is a candidate three-image source layout. XML detection is not
// content proof: the native inspector and assembler independently verify files.
type MediaLayout struct {
	Payload                      model.PayloadIdentity
	OSIndex, MediaIndex, PEIndex int
}

type InventoryCompleter func(context.Context, *metadata.Inventory, download.Materialized) error

// DetectMedia discovers indices from inspected semantics, never fixed indices,
// build numbers or payload digests. Reference-only WIMs cannot become media.
func DetectMedia(inv metadata.Inventory, selection model.Selection) (MediaLayout, error) {
	if selection.Validate() != nil || inv.Source.Validate() != nil || inv.Manifest.Validate() != nil || inv.Source != inv.Manifest.Source || selection.UpdateID != inv.Source.UpdateID || selection.Architecture != inv.Source.Architecture || !strings.EqualFold(selection.Language, inv.Source.Language) {
		return MediaLayout{}, ErrInputIdentityChanged
	}
	known := map[model.PayloadIdentity]bool{}
	for _, p := range inv.Manifest.Payloads {
		known[p.Identity] = true
	}
	byPayload := map[model.PayloadIdentity][]metadata.Image{}
	for _, im := range inv.Images {
		if !known[im.Resource.Payload] || im.Index <= 0 {
			return MediaLayout{}, metadata.ErrInvalidEvidence
		}
		byPayload[im.Resource.Payload] = append(byPayload[im.Resource.Payload], im)
	}
	var layouts []MediaLayout
	for id, images := range byPayload {
		var media, pe []metadata.Image
		for _, im := range images {
			if strings.EqualFold(strings.TrimSpace(im.Name), "Windows Setup Media") && im.Edition == "" && im.InstallationType == "" {
				media = append(media, im)
			}
			if strings.EqualFold(im.InstallationType, "WindowsPE") && im.Architecture == selection.Architecture && mediaLanguage(im.Languages, selection.Language) {
				pe = append(pe, im)
			}
		}
		if len(media) == 0 || len(pe) == 0 {
			continue
		}
		if len(media) != 1 || len(pe) != 1 {
			return MediaLayout{}, fmt.Errorf("%w: ambiguous Setup media/WinPE image candidates in one source container", ErrImplementationGap)
		}
		layout := MediaLayout{Payload: id, MediaIndex: media[0].Index, PEIndex: pe[0].Index}
		matches := true
		for _, edition := range selection.Editions {
			var osImages []metadata.Image
			for _, im := range images {
				osType := im.InstallationType == "Client" || im.InstallationType == "Server" || im.InstallationType == "Server Core"
				if strings.EqualFold(im.Edition, edition) && osType && im.Architecture == selection.Architecture && mediaLanguage(im.Languages, selection.Language) {
					osImages = append(osImages, im)
				}
			}
			if len(osImages) != 1 {
				matches = false
				break
			}
			if layout.OSIndex == 0 {
				layout.OSIndex = osImages[0].Index
			}
		}
		if matches {
			layouts = append(layouts, layout)
		}
	}
	if len(layouts) != 1 {
		return MediaLayout{}, fmt.Errorf("%w: expected one container with selected OS edition, matching WinPE and Setup media candidates; observed %d (split, express, encrypted or update-only sources require their source-format adapter)", ErrImplementationGap, len(layouts))
	}
	return layouts[0], nil
}

func mediaLanguage(languages []string, language string) bool {
	for _, l := range languages {
		if strings.EqualFold(l, language) {
			return true
		}
	}
	return false
}

func mediaAppRequests(snapshot AppCatalogSnapshot, settings model.AppSettings) ([]string, error) {
	if settings.Preset != "" {
		return nil, fmt.Errorf("%w: source app preset %q has no inspected definition", ErrImplementationGap, settings.Preset)
	}
	switch settings.Mode {
	case model.AppsNone:
		return nil, nil
	case model.AppsDefault:
		var out []string
		for _, entry := range snapshot.Entries {
			if entry.Type == "MSIXFramework" {
				continue
			}
			for _, hint := range entry.Media {
				if hint.Type == "CleanInstall" && hint.State == "INSTALLED" {
					out = append(out, entry.FeatureID)
					break
				}
			}
		}
		return out, nil
	case model.AppsCustom:
		for _, id := range settings.Include {
			found := false
			for _, entry := range snapshot.Entries {
				found = found || strings.EqualFold(id, entry.FeatureID)
			}
			if !found {
				return nil, fmt.Errorf("requested app has no source feature: %s", id)
			}
		}
		return slices.Clone(settings.Include), nil
	default:
		return nil, ErrInvalidInput
	}
}

// ResolveMedia probes the exact selected base before acquiring its full closure.
// Names select inspection candidates only; every role comes from verified bytes.
func ResolveMedia(ctx context.Context, cat *catalog.Client, apps *SourceAppCatalog, fetch SelectedFetcher, selection model.Selection, settings model.ResolvedSettings, emit model.Emit, complete InventoryCompleter) (Resolution, error) {
	out := Resolution{Selection: cloneSelection(selection), Settings: cloneSettings(settings), AppPhase: metadata.PhaseUnknown, Classification: metadata.ClassificationImplementationGap}
	if ctx == nil || cat == nil || fetch == nil || complete == nil || selection.Validate() != nil || settings.Validate() != nil {
		return out, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	var sets []catalog.FileSet
	var queries []model.SourceQuery
	for _, edition := range selection.Editions {
		set, err := cat.Files(ctx, selection.UpdateID, selection.Language, edition)
		if err != nil {
			return out, err
		}
		if set.Source.UpdateID != selection.UpdateID || set.Source.Architecture != selection.Architecture || !strings.EqualFold(set.Source.Language, selection.Language) {
			return out, ErrInputIdentityChanged
		}
		sets = append(sets, set)
		queries = append(queries, model.SourceQuery{UpdateID: selection.UpdateID, Language: selection.Language, Edition: edition})
	}
	baseSource := sets[0].Source
	full, locators, err := Union(baseSource, sets, queries...)
	if err != nil {
		return out, err
	}
	// Prefer edition/language candidates without downloading unrelated references.
	var candidates []model.Payload
	for _, set := range sets {
		for _, p := range set.Payloads {
			ext := strings.ToLower(path.Ext(p.Destination))
			if ext != ".esd" && ext != ".wim" {
				continue
			}
			for _, edition := range selection.Editions {
				if strings.EqualFold(p.Destination, edition+"_"+selection.Language+ext) {
					if !slices.Contains(candidates, p) {
						candidates = append(candidates, p)
					}
				}
			}
		}
	}
	if len(candidates) == 0 {
		// Retain the small verified CompDB observations even when this WIM
		// adapter cannot identify an image candidate. No full-source fetch occurs.
		discovery := &Discovery{Catalog: cat}
		resolver := &Resolver{Catalog: cat, Fetcher: mediaOneFetcher{fetch: fetch, source: baseSource}, Discover: discovery.Metadata, Emit: emit, DeferAppsOnMediaGaps: true}
		return resolver.Resolve(ctx, selection, settings)
	}
	probeQueries := model.CloneSourceQueries(queries)
	for i := range probeQueries {
		for _, p := range candidates {
			if slices.Contains(sets[i].Payloads, p) {
				probeQueries[i].Projection = append(probeQueries[i].Projection, p)
			}
		}
		if len(probeQueries[i].Projection) == 0 {
			return out, fmt.Errorf("%w: no WIM candidate for selected base edition", ErrImplementationGap)
		}
	}
	probe, probeLocators, err := Union(baseSource, sets, probeQueries...)
	if err != nil {
		return out, err
	}
	files, err := fetch.Fetch(ctx, probe, probeLocators, emit)
	if err != nil {
		return out, err
	}
	inv, err := inspectMediaFiles(ctx, probe, files, nil)
	if err != nil {
		return out, fmt.Errorf("inspect selected media candidate (%d payloads): %w", len(probe.Payloads), err)
	}
	out.Manifest = probe
	out.Locators = probeLocators
	out.Inventory = inv
	if _, err = DetectMedia(inv, selection); err != nil {
		out.gap("media-layout-unresolved", err.Error())
		return out, nil
	}
	var docs []metadata.Document
	if settings.Apps.Mode != model.AppsNone {
		if apps == nil {
			return out, fmt.Errorf("%w: source app catalogue inspector unavailable", ErrImplementationGap)
		}
		snapshot, loadErr := apps.Load(ctx, selection)
		if loadErr != nil {
			return out, loadErr
		}
		if snapshot.State != AppCatalogAvailable {
			return out, fmt.Errorf("%w: source app composition remains unexamined: %s", ErrImplementationGap, strings.Join(snapshot.Gaps, "; "))
		}
		docs, err = apps.SelectedDocuments(ctx, snapshot)
		if err != nil {
			return out, err
		}
		requested, requestErr := mediaAppRequests(snapshot, settings.Apps)
		if requestErr != nil {
			return out, requestErr
		}
		if len(requested) > 0 {
			selected, selectErr := SelectedAppPayloads(ctx, snapshot, docs, requested)
			if selectErr != nil {
				return out, selectErr
			}
			if len(selected) == 0 {
				return out, fmt.Errorf("%w: %d requested app features have no inspected payload projection; an empty projection cannot authorize the complete neutral app set", ErrImplementationGap, len(requested))
			}
			appSet, appErr := cat.Files(ctx, selection.UpdateID, "neutral", snapshot.AppQuery.Edition)
			if appErr != nil {
				return out, appErr
			}
			q := snapshot.AppQuery
			q.Projection = selected
			sets = append(sets, appSet)
			queries = append(queries, q)
		}
	}
	full, locators, err = Union(baseSource, sets, queries...)
	if err != nil {
		return out, err
	}
	files, err = fetch.Fetch(ctx, full, locators, emit)
	if err != nil {
		return out, err
	}
	inv, err = inspectMediaFiles(ctx, full, files, docs)
	if err != nil {
		return out, fmt.Errorf("inspect full selected source/apps (%d payloads): %w", len(full.Payloads), err)
	}
	if err = complete(ctx, &inv, files); err != nil {
		return out, err
	}
	if _, err = DetectMedia(inv, selection); err != nil {
		return out, err
	}
	out.Manifest = full
	out.Locators = locators
	out.Inventory = inv
	out.Classification = inv.Classification
	out.AppPhase = metadata.PhaseOfflineProvisioning
	return out, nil
}

type mediaOneFetcher struct {
	fetch  SelectedFetcher
	source model.SourceIdentity
}

func (f mediaOneFetcher) FetchOne(ctx context.Context, p model.Payload, locator download.Locator, emit model.Emit) (download.CachedFile, error) {
	m, err := model.NewPayloadManifest(f.source, []model.Payload{p})
	if err != nil {
		return download.CachedFile{}, err
	}
	files, err := f.fetch.Fetch(ctx, m, model.Locators{p.Identity: locator}, emit)
	if err != nil {
		return download.CachedFile{}, err
	}
	file, ok := files[p.Identity]
	if !ok || file.Identity != p.Identity {
		return download.CachedFile{}, ErrInputIdentityChanged
	}
	return file, nil
}

func inspectMediaFiles(ctx context.Context, manifest model.PayloadManifest, files download.Materialized, docs []metadata.Document) (metadata.Inventory, error) {
	req := metadata.InspectRequest{Source: manifest.Source, Manifest: manifest}
	for _, p := range manifest.Payloads {
		f, ok := files[p.Identity]
		if !ok || f.Identity != p.Identity {
			return metadata.Inventory{}, ErrInputIdentityChanged
		}
		var provider metadata.ReadOnlyProvider
		switch strings.ToLower(path.Ext(p.Destination)) {
		case ".esd", ".wim":
			provider = providers.WIM{}
		case ".msix", ".appx", ".msixbundle", ".appxbundle":
			provider = providers.Appx{}
		}
		if provider != nil {
			req.Inspections = append(req.Inspections, metadata.Inspection{Resource: metadata.LocalResource{Identity: p.Identity, Path: f.Path}, Provider: mediaNamedProvider{provider: provider, name: p.Destination}})
		}
	}
	inv, err := inspectMediaBatches(ctx, req)
	if err != nil {
		return inv, err
	}
	for _, doc := range docs {
		if err = retainMediaDocument(&inv, doc); err != nil {
			return inv, fmt.Errorf("retain source composition %q: %w", doc.Reference.Resource.Member, err)
		}
	}
	for _, doc := range docs {
		if strings.Contains(strings.ToLower(doc.Reference.Resource.Member), "app_neutral") && len(inv.Apps.Packages) > 0 {
			var bound metadata.Inventory
			bound, err = metadata.BindAppPolicies(ctx, inv, doc.Reference)
			if err != nil {
				return inv, fmt.Errorf("bind source app policies %q (%d packages, %d bundles, %d original documents): %w", doc.Reference.Resource.Member, len(inv.Apps.Packages), len(inv.Apps.Bundles), len(inv.Documents), err)
			}
			inv = bound
		}
	}
	return inv, nil
}
