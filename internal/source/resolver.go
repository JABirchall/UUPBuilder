//go:build windows

package source

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

type Catalog interface {
	Files(context.Context, string, string, string) (catalog.FileSet, error)
	Editions(context.Context, string, string) ([]catalog.Edition, error)
}
type Fetcher interface {
	FetchOne(context.Context, model.Payload, download.Locator, model.Emit) (download.CachedFile, error)
}

// SourceSet binds a complete catalog response to the exact replayable query.
// A discovery adapter must not describe a filtered response as a complete set.
type SourceSet struct {
	Query model.SourceQuery
	Files catalog.FileSet `json:"-" toml:"-"`
}
type MetadataInput struct {
	Identity model.PayloadIdentity
	Format   metadata.Format
	Gzip     bool
	Provider metadata.ReadOnlyProvider
}
type MetadataPlan struct {
	Source model.SourceIdentity
	Sets   []SourceSet
	Inputs []MetadataInput
}

// AppDiscovery describes metadata inputs, not app identities. PhasePostAssembly
// requires source-bound evidence and declares deferred inspection; it never
// claims an absent app inventory is complete.
type AppDiscovery struct {
	Inputs   []MetadataInput
	Phase    metadata.AppPhase
	Evidence *metadata.Evidence
}
type Resolver struct {
	Catalog      Catalog
	Fetcher      Fetcher
	Discover     func(context.Context, model.Selection) (MetadataPlan, error)
	DiscoverApps func(context.Context, model.Selection, metadata.Inventory, []SourceSet) (AppDiscovery, error)
	Inspect      func(context.Context, metadata.InspectRequest) (metadata.Inventory, error)
	Emit         model.Emit
}

// Resolve performs small, verified semantic inspection before choosing base
// payloads. Configure ports before concurrent use. The supplied M1 static
// inspector is the default; native discovery/providers remain injected ports.
func (r *Resolver) Resolve(ctx context.Context, selection model.Selection, settings model.ResolvedSettings) (Resolution, error) {
	res := Resolution{Selection: cloneSelection(selection), Settings: cloneSettings(settings), Classification: metadata.ClassificationImplementationGap, AppPhase: metadata.PhaseUnknown, Locators: make(model.Locators)}
	if ctx == nil {
		return res, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if selection.Validate() != nil || settings.Validate() != nil {
		return res, ErrInvalidInput
	}
	if r == nil || r.Discover == nil {
		res.gap("metadata-discovery-unavailable", "A read-only producer must discover small semantic metadata for this exact source revision.")
		return res, nil
	}
	plan, err := r.Discover(ctx, cloneSelection(selection))
	if err != nil {
		return res, res.failure(ctx, "metadata discovery", err)
	}
	if plan.Source.Validate() != nil || plan.Source.UpdateID != selection.UpdateID || plan.Source.Architecture != selection.Architecture || plan.Source.Language != selection.Language {
		return res, ErrInputIdentityChanged
	}
	sets := slices.Clone(plan.Sets)
	res.Manifest, res.Locators, err = unionSets(plan.Source, sets)
	if err != nil {
		return res, res.failure(ctx, "metadata source union", err)
	}
	if len(plan.Inputs) == 0 {
		res.gap("metadata-inputs-unavailable", "Discovery supplied no semantic metadata inputs; roles, bases and app families cannot be inferred from filenames.")
		return res, nil
	}
	if r.Fetcher == nil {
		res.gap("metadata-materializer-unavailable", "Verified small metadata materialization requires a download FetchOne producer.")
		return res, nil
	}
	req := metadata.InspectRequest{Source: plan.Source, Manifest: res.Manifest}
	if err = r.addInputs(ctx, &req, plan.Inputs, res.Locators); err != nil {
		return res, res.failure(ctx, "metadata materialization", err)
	}
	res.Inventory, err = r.inspect(ctx, req)
	if err != nil {
		return res, res.failure(ctx, "metadata inspection", err)
	}
	res.Classification = res.Inventory.Classification
	if r.Catalog == nil {
		res.gap("catalog-producer-unavailable", "A catalog producer is required to resolve downloadable edition bases and app sets.")
		res.inventoryGaps()
		return res, nil
	}
	editions, err := r.Catalog.Editions(ctx, selection.UpdateID, selection.Language)
	if err != nil {
		return res, res.failure(ctx, "catalog edition discovery", err)
	}
	bases, ok := res.downloadBases(editions)
	if !ok {
		res.inventoryGaps()
		return res, nil
	}
	for _, base := range bases {
		q := model.SourceQuery{UpdateID: selection.UpdateID, Language: selection.Language, Edition: base}
		files, err := r.Catalog.Files(ctx, q.UpdateID, q.Language, q.Edition)
		if err != nil {
			return res, res.failure(ctx, "edition payload discovery", err)
		}
		sets = append(sets, SourceSet{Query: q, Files: files})
	}
	// Upstream's APP query already includes APP_MOMENT when both are present.
	// Probe only selectors advertised by this exact source/language listing.
	var appSets []SourceSet
	appSelector := ""
	for _, e := range editions {
		if e.ID == "APP" {
			appSelector = "APP"
			break
		}
		if e.ID == "APP_MOMENT" {
			appSelector = "APP_MOMENT"
		}
	}
	if appSelector != "" {
		q := model.SourceQuery{UpdateID: selection.UpdateID, Language: selection.Language, Edition: appSelector}
		files, err := r.Catalog.Files(ctx, q.UpdateID, q.Language, q.Edition)
		if err != nil {
			return res, res.failure(ctx, "app payload discovery", err)
		}
		appSets = append(appSets, SourceSet{Query: q, Files: files})
		sets = append(sets, appSets...)
	}
	res.Manifest, res.Locators, err = unionSets(plan.Source, sets)
	if err != nil {
		return res, res.failure(ctx, "source union", err)
	}
	req.Manifest = res.Manifest
	var apps AppDiscovery
	if r.DiscoverApps == nil {
		res.gap("app-metadata-discovery-unavailable", "A source-aware read-only producer must discover app manifests, licenses and any post-materialization inspection requirements.")
	} else {
		apps, err = r.DiscoverApps(ctx, cloneSelection(selection), res.Inventory, appSets)
		if err != nil {
			return res, res.failure(ctx, "app metadata discovery", err)
		}
		if len(apps.Inputs) > 0 {
			if err = r.addInputs(ctx, &req, apps.Inputs, res.Locators); err != nil {
				return res, res.failure(ctx, "app metadata materialization", err)
			}
		}
		if apps.Phase != "" && apps.Phase != metadata.PhaseUnknown && apps.Phase != metadata.PhasePostAssembly && apps.Phase != metadata.PhaseOfflineProvisioning {
			return res, ErrInvalidInput
		}
		if apps.Phase == metadata.PhasePostAssembly {
			if !boundEvidence(res.Inventory, apps.Evidence) {
				return res, metadata.ErrInvalidEvidence
			}
			res.AppPhase = metadata.PhasePostAssembly
			res.gap("apps-require-materialized-inspection", "Semantic evidence requires inspection of provisioned apps after image materialization; the preflight app inventory is incomplete.")
		}
	}
	res.Inventory, err = r.inspect(ctx, req)
	if err != nil {
		return res, res.failure(ctx, "combined metadata inspection", err)
	}
	if res.AppPhase != metadata.PhasePostAssembly {
		res.AppPhase = inventoryAppPhase(res.Inventory.Apps)
	}
	if len(settings.Apps.Include) > 0 || settings.Apps.Preset != "" {
		res.gap("app-selection-rules-unresolved", "Requested app families/preset are retained. Package family selection and edition defaults require verified source rules; filenames and Appx display names cannot establish those rules.")
	}
	res.inventoryGaps()
	return res, nil
}

func unionSets(source model.SourceIdentity, sets []SourceSet) (model.PayloadManifest, model.Locators, error) {
	files := make([]catalog.FileSet, 0, len(sets))
	queries := make([]model.SourceQuery, 0, len(sets))
	for _, set := range sets {
		files = append(files, set.Files)
		queries = append(queries, set.Query)
	}
	return Union(source, files, queries...)
}

func (r *Resolver) addInputs(ctx context.Context, req *metadata.InspectRequest, inputs []MetadataInput, locators model.Locators) error {
	known := make(map[model.PayloadIdentity]model.Payload)
	seen := make(map[model.PayloadIdentity]bool)
	for _, p := range req.Manifest.Payloads {
		known[p.Identity] = p
	}
	for _, f := range req.Files {
		seen[f.Resource.Identity] = true
	}
	for _, i := range req.Inspections {
		seen[i.Resource.Identity] = true
	}
	for _, input := range inputs {
		p, ok := known[input.Identity]
		if !ok || seen[input.Identity] || input.Format == "" && input.Provider == nil {
			return ErrInvalidInput
		}
		seen[input.Identity] = true
		file, err := r.Fetcher.FetchOne(ctx, p, locators[p.Identity], r.Emit)
		if err != nil {
			return err
		}
		if file.Identity != p.Identity || file.Path == "" {
			return ErrInputIdentityChanged
		}
		resource := metadata.LocalResource{Identity: p.Identity, Path: file.Path}
		if input.Format != "" {
			req.Files = append(req.Files, metadata.MetadataFile{Resource: resource, Format: input.Format, Gzip: input.Gzip})
		}
		if input.Provider != nil {
			req.Inspections = append(req.Inspections, metadata.Inspection{Resource: resource, Provider: input.Provider})
		}
	}
	return nil
}

func (r *Resolver) inspect(ctx context.Context, req metadata.InspectRequest) (metadata.Inventory, error) {
	inspect := r.Inspect
	if inspect == nil {
		inspect = metadata.Inspect
	}
	inv, err := inspect(ctx, req)
	if err != nil {
		return inv, err
	}
	if inv.Source != req.Source || inv.Manifest.Validate() != nil || inv.Manifest.Digest != req.Manifest.Digest {
		return metadata.Inventory{}, ErrInputIdentityChanged
	}
	return inv, nil
}

func (res *Resolution) downloadBases(editions []catalog.Edition) ([]string, bool) {
	available := make(map[string]string)
	for _, edition := range editions {
		available[strings.ToUpper(edition.ID)] = edition.ID
	}
	relations := make(map[string]string)
	for _, base := range res.Inventory.EditionBases {
		relations[strings.ToUpper(base.Edition)] = base.Base
	}
	requested := append(slices.Clone(res.Selection.Editions), res.Settings.Conversion.Editions.Derived...)
	chosen := make(map[string]bool)
	for _, edition := range requested {
		seen := make(map[string]bool)
		for {
			key := strings.ToUpper(edition)
			if seen[key] {
				res.gap("edition-base-cycle", "Semantic edition relationships contain a cycle; requested editions are retained.")
				return nil, false
			}
			seen[key] = true
			if direct, ok := available[key]; ok {
				chosen[direct] = true
				break
			}
			base, ok := relations[key]
			if !ok {
				res.gap("edition-base-unresolved", "A requested edition lacks an advertised downloadable source or an inspected derivation relationship; the target choice is retained.")
				return nil, false
			}
			edition = base
		}
	}
	result := make([]string, 0, len(chosen))
	for edition := range chosen {
		result = append(result, edition)
	}
	sort.Strings(result)
	return result, true
}

func (res *Resolution) gap(code, message string) {
	res.Diagnostics = append(res.Diagnostics, model.Diagnostic{Code: code, Severity: model.SeverityError, Message: message, Selection: selectionPointer(res.Selection)})
	if res.Classification != metadata.ClassificationSourceUnavailable && res.Classification != metadata.ClassificationUpdateOnly {
		res.Classification = metadata.ClassificationImplementationGap
	}
}
func (res *Resolution) inventoryGaps() {
	if res.Inventory.Classification == metadata.ClassificationSourceUnavailable || res.Inventory.Classification == metadata.ClassificationUpdateOnly {
		res.Classification = res.Inventory.Classification
	}
	for _, gap := range res.Inventory.Gaps {
		res.gap("metadata-"+gap.Code, gap.Detail)
	}
	if res.Inventory.Classification == metadata.ClassificationMetadataIncomplete && len(res.Inventory.Gaps) == 0 {
		res.gap("metadata-incomplete", "Semantic metadata inspection is incomplete.")
	}
}
func (res *Resolution) failure(ctx context.Context, operation string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if upstreamUnavailable(err) {
		res.Classification = metadata.ClassificationSourceUnavailable
		res.Diagnostics = append(res.Diagnostics, model.Diagnostic{Code: "payload-unavailable", Severity: model.SeverityError, Message: "Required upstream payload material is unavailable for the exact frozen source query.", Selection: selectionPointer(res.Selection)})
		return fmt.Errorf("%w: %w", ErrPayloadUnavailable, portError(ctx, operation, err))
	}
	if errors.Is(err, ErrImplementationGap) {
		res.gap("producer-unavailable", operation+" requires an unavailable read-only source producer; target choices and explicit settings are retained.")
	}
	return portError(ctx, operation, err)
}

// Port errors are public diagnostics. Never forward arbitrary provider error
// strings, which can contain a request URL or credentials.
func portError(ctx context.Context, operation string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var api *catalog.APIError
	if errors.As(err, &api) {
		code := "UPSTREAM_ERROR"
		valid := len(api.Code) > 0 && len(api.Code) <= 96 && api.Code[0] >= 'A' && api.Code[0] <= 'Z'
		for _, r := range api.Code {
			valid = valid && (r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_')
		}
		if valid {
			code = api.Code
		}
		endpoint := "catalog"
		if api.Endpoint == "get.php" || api.Endpoint == "listeditions.php" {
			endpoint = api.Endpoint
		}
		return fmt.Errorf("%s: %w", operation, &catalog.APIError{Endpoint: endpoint, StatusCode: api.StatusCode, Code: code})
	}
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded, ErrInvalidInput, ErrInputIdentityChanged, ErrConflictingDestinations, ErrImplementationGap, ErrPayloadUnavailable, download.ErrIntegrity, download.ErrRefresh, metadata.ErrIntegrity, metadata.ErrLimit, metadata.ErrMalformedMetadata, metadata.ErrConflictingMetadata, metadata.ErrInvalidEvidence, metadata.ErrInvalidInput} {
		if errors.Is(err, sentinel) {
			return fmt.Errorf("%s: %w", operation, sentinel)
		}
	}
	return fmt.Errorf("%s failed", operation)
}
func boundEvidence(inv metadata.Inventory, e *metadata.Evidence) bool {
	if e == nil || e.Source != inv.Source || strings.TrimSpace(e.Selector) == "" {
		return false
	}
	for _, doc := range inv.Documents {
		if doc.Reference == e.Document {
			return true
		}
	}
	return false
}
func inventoryAppPhase(apps metadata.AppInventory) metadata.AppPhase {
	phase := metadata.PhaseUnknown
	for _, app := range apps.Packages {
		if app.Phase == metadata.PhaseUnknown || app.Phase == "" {
			return metadata.PhaseUnknown
		}
		if phase == metadata.PhaseUnknown {
			phase = app.Phase
		} else if phase != app.Phase {
			return metadata.PhaseUnknown
		}
	}
	return phase
}
func cloneSelection(s model.Selection) model.Selection {
	s.Editions = slices.Clone(s.Editions)
	return s
}
func selectionPointer(s model.Selection) *model.Selection { copy := cloneSelection(s); return &copy }
func cloneSettings(s model.ResolvedSettings) model.ResolvedSettings {
	s.Conversion.Drivers.Targets = slices.Clone(s.Conversion.Drivers.Targets)
	s.Conversion.Editions.Derived = slices.Clone(s.Conversion.Editions.Derived)
	s.Apps.Include = slices.Clone(s.Apps.Include)
	s.Output.EditionOrder = slices.Clone(s.Output.EditionOrder)
	return s
}

// RefreshLinks works after restart using only the frozen query provenance. It
// deliberately does not enumerate editions, repeat semantic discovery or use
// resolver memory to infer a different source selection.
func (r *Resolver) RefreshLinks(ctx context.Context, frozen model.PayloadManifest) (model.Locators, error) {
	if ctx == nil {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if frozen.Validate() != nil {
		return nil, ErrInvalidInput
	}
	if r == nil || r.Catalog == nil || len(frozen.Queries) == 0 {
		return nil, fmt.Errorf("%w: frozen catalog query provenance and catalog producer are required", ErrImplementationGap)
	}
	frozen.Payloads = slices.Clone(frozen.Payloads)
	frozen.Queries = slices.Clone(frozen.Queries)
	sets := make([]catalog.FileSet, 0, len(frozen.Queries))
	for _, q := range frozen.Queries {
		set, err := r.Catalog.Files(ctx, q.UpdateID, q.Language, q.Edition)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if upstreamUnavailable(err) {
				return nil, fmt.Errorf("%w: %w", ErrPayloadUnavailable, portError(ctx, "catalog link refresh", err))
			}
			return nil, portError(ctx, "catalog link refresh", err)
		}
		sets = append(sets, set)
	}
	manifest, locators, err := Union(frozen.Source, sets, frozen.Queries...)
	if err != nil {
		if errors.Is(err, ErrConflictingDestinations) {
			return nil, ErrInputIdentityChanged
		}
		return nil, err
	}
	return Refresh(ctx, frozen, Resolution{Manifest: manifest, Locators: locators})
}
