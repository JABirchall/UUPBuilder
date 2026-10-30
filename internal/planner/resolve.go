package planner

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

func (p *Planner) Resolve(ctx context.Context, req Request) (ReadyPlan, error) {
	if ctx == nil {
		return ReadyPlan{}, ErrInvalidPlan
	}
	if err := ctx.Err(); err != nil {
		return ReadyPlan{}, err
	}
	if err := req.Selection.Validate(); err != nil {
		return ReadyPlan{}, err
	}
	if err := req.Settings.Validate(); err != nil {
		return ReadyPlan{}, err
	}
	if req.Intent != BuildMedia && req.Intent != DownloadOnly {
		return ReadyPlan{}, fmt.Errorf("%w: job intent required", ErrInvalidPlan)
	}
	res := req.Resolution
	appsResolved := false
	if req.Intent == BuildMedia {
		apps, e := PlanApps(res.Inventory, req.Settings.Apps)
		appsResolved = e == nil && !apps.Deferred
	}
	if !reflect.DeepEqual(req.Selection, res.Selection) || !reflect.DeepEqual(req.Settings, res.Settings) {
		return ReadyPlan{}, ErrIdentityChanged
	}
	applicability, err := settingsApplicability(req.Settings)
	if err != nil {
		return ReadyPlan{}, err
	}
	if req.Intent == BuildMedia {
		for _, d := range res.Diagnostics {
			if d.Severity == model.SeverityError && !(appsResolved && d.Code == "metadata-app-dependency-unresolved") && !(res.AppPhase == metadata.PhasePostAssembly && deferredDiagnostic(d.Code)) {
				return ReadyPlan{}, fmt.Errorf("%w: %s: %s", ErrBlocked, d.Code, d.Message)
			}
		}
	}
	if res.Manifest.Validate() != nil || res.Manifest.Source.UpdateID != req.Selection.UpdateID || res.Manifest.Source.Architecture != req.Selection.Architecture || res.Manifest.Source.Language != req.Selection.Language {
		return ReadyPlan{}, ErrIdentityChanged
	}
	if req.Host.WindowsBuild < 10240 || req.Host.NativeArchitecture.Validate() != nil || req.Host.ProcessArchitecture.Validate() != nil {
		return ReadyPlan{}, fmt.Errorf("%w: observed Windows 10+ host required", ErrBlocked)
	}
	if req.Intent == BuildMedia {
		if res.Inventory.Source != res.Manifest.Source || res.Inventory.Manifest.Validate() != nil || res.Inventory.Manifest.Digest != res.Manifest.Digest {
			return ReadyPlan{}, ErrIdentityChanged
		}
		for _, gap := range res.Inventory.Gaps {
			if !(appsResolved && gap.Code == "app-dependency-unresolved") && !(res.AppPhase == metadata.PhasePostAssembly && deferredGap(gap.Code)) {
				return ReadyPlan{}, fmt.Errorf("%w: metadata-%s: %s", ErrBlocked, gap.Code, gap.Detail)
			}
		}
		if res.Classification == metadata.ClassificationUpdateOnly || res.Classification == metadata.ClassificationSourceUnavailable {
			return ReadyPlan{}, fmt.Errorf("%w: %s cannot provide ISO source material", ErrBlocked, res.Classification)
		}
		if res.Classification != metadata.ClassificationSemanticInventory && !(appsResolved && len(res.Inventory.Gaps) > 0 && res.Classification == metadata.ClassificationMetadataIncomplete) && res.AppPhase != metadata.PhasePostAssembly {
			return ReadyPlan{}, fmt.Errorf("%w: semantic discovery incomplete (%s)", ErrBlocked, res.Classification)
		}
		if res.AppPhase != metadata.PhasePostAssembly && res.AppPhase != metadata.PhaseOfflineProvisioning {
			return ReadyPlan{}, fmt.Errorf("%w: app applicability discovery unavailable", ErrBlocked)
		}
	}
	f := frozen{Version: 1, Selection: req.Selection, Requested: req.Settings, Effective: req.Settings, Manifest: res.Manifest, Host: req.Host, InventoryDigest: hash(res.Inventory), AppPhase: string(res.AppPhase), DraftRevision: req.DraftRevision, Intent: req.Intent, Applicability: applicability}
	if req.Intent == BuildMedia {
		serviceSettings := copyOf(req.Settings)
		if serviceSettings.Output.EditionOrder, err = finalEditionOrder(req.Selection, req.Settings); err != nil {
			return ReadyPlan{}, err
		}
		service, err := BuildServicePlan(res.Inventory, serviceSettings)
		if err != nil {
			return ReadyPlan{}, fmt.Errorf("%w: %v", ErrBlocked, err)
		}
		f.Servicing = &service
		customization, err := BuildCustomizationPlan(res.Inventory, req.Settings, serviceSettings.Output.EditionOrder)
		if err != nil {
			return ReadyPlan{}, fmt.Errorf("%w: %v", ErrBlocked, err)
		}
		f.Customization = &customization
		if customization.Apps.Deferred {
			f.AppPhase = string(metadata.PhasePostAssembly)
		}
	}
	if p != nil {
		if f.Effective.Storage.Workspace == "auto" {
			f.Effective.Storage.Workspace = p.DefaultWorkspace
		}
		if f.Effective.Storage.Cache == "auto" {
			f.Effective.Storage.Cache = p.DefaultCache
		}
	}
	if f.Tools, err = p.dependencies(req); err != nil {
		return ReadyPlan{}, err
	}
	storageRequest := req
	storageRequest.Settings = f.Effective
	if f.Estimate, f.Storage, err = p.space(ctx, storageRequest); err != nil {
		return ReadyPlan{}, err
	}
	f.Operations = graph(f)
	if err := ctx.Err(); err != nil {
		return ReadyPlan{}, err
	}
	return freeze(f), nil
}
func deferredGap(code string) bool {
	return code == "app-inventory-unresolved" || code == "app-selection-rules-unresolved" || code == "app-phase-unresolved" || code == "app-license-unresolved" || code == "app-dependency-unresolved"
}
func deferredDiagnostic(code string) bool {
	return code == "apps-require-materialized-inspection" || deferredGap(strings.TrimPrefix(code, "metadata-"))
}
