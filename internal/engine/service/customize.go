package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
)

type DriverFile struct{ Path, SHA256 string }
type DriverInput struct {
	Target model.DriverTarget
	INF    string
	Files  []DriverFile
}
type CustomizationRequest struct {
	Plan planner.CustomizationPlan
	// ResolvedApps is the mandatory barrier result for a frozen deferred plan.
	// It resolves observations only; Requested never replaces the frozen request.
	ResolvedApps       *planner.AppPlan
	Images, BootImages []InspectedImage
	Payloads           []UpdateInput
	FeatureSources     []UpdateInput
	Drivers            []DriverInput
	Transaction        *jobstore.Transaction
}
type CustomizedImages struct {
	PlanDigest                     string
	WIMPath, BootWIMPath           string
	Images, BootImages             []ImageIdentity
	Observations, BootObservations []CustomizationObservation
	Outputs                        []jobstore.OutputIdentity
}
type CustomizationBackend interface {
	Backend
	AddApp(context.Context, platform.OwnedMount, planner.AppProvision, AppFiles, model.Emit) error
	RemoveApp(context.Context, platform.OwnedMount, string, model.Emit) error
	EnableFeature(context.Context, platform.OwnedMount, planner.FeatureOperation, []UpdateInput, model.Emit) error
	DriverInfo(context.Context, platform.OwnedMount, string, model.Emit) (DriverObservation, error)
	AddDriver(context.Context, platform.OwnedMount, string, model.Emit) error
	InspectCustomization(context.Context, platform.OwnedMount, model.DriverTarget, []planner.FeatureOperation, model.Emit) (CustomizationObservation, error)
}
type AppFiles struct {
	Main, License string
	Dependencies  []string
	External      map[string]string
}

func appPath(paths map[metadata.ResourceReference]string, ref metadata.ResourceReference) string {
	if p := paths[ref]; p != "" {
		return p
	}
	return paths[metadata.ResourceReference{Payload: ref.Payload}]
}

type CustomizationExecutor struct{ Backend CustomizationBackend }

func (e *CustomizationExecutor) Execute(ctx context.Context, req CustomizationRequest, emit model.Emit) (out CustomizedImages, err error) {
	if ctx == nil || req.Transaction == nil || req.Plan.Validate() != nil {
		return out, planner.ErrInvalidPlan
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if e == nil || e.Backend == nil {
		return out, ErrProviderUnavailable
	}
	if _, err = req.Transaction.ScratchPath("customized.wim"); err != nil {
		return out, err
	}
	apps := req.Plan.Apps
	if apps.Deferred {
		if req.ResolvedApps == nil || req.ResolvedApps.Deferred || req.ResolvedApps.Source != apps.Source || req.ResolvedApps.ManifestDigest != apps.ManifestDigest || !reflect.DeepEqual(req.ResolvedApps.Requested, apps.Requested) {
			return out, fmt.Errorf("mandatory post-assembly app inspection incomplete")
		}
		apps = *req.ResolvedApps
	}
	if err = e.Backend.Check(ctx, ServiceRequest{Plan: planner.ServicePlan{Source: req.Plan.Source, Generation: req.Plan.Generation}}); err != nil {
		return out, err
	}
	paths := map[metadata.ResourceReference]string{}
	for _, input := range append(append([]UpdateInput(nil), req.Payloads...), req.FeatureSources...) {
		known := false
		for _, p := range req.Plan.Manifest.Payloads {
			known = known || p.Identity == input.Resource.Payload
		}
		if !known {
			return out, fmt.Errorf("customization input not in frozen manifest")
		}
		if err = verifyUpdateFile(ctx, input.Resource.Payload, input.Path); err != nil {
			return out, err
		}
		if old, ok := paths[input.Resource]; ok && old != input.Path {
			return out, fmt.Errorf("ambiguous app input")
		}
		paths[input.Resource] = input.Path
		paths[metadata.ResourceReference{Payload: input.Resource.Payload}] = input.Path
	}
	// Verify the entire app closure before the first export/mount/mutation.
	for _, op := range apps.Provision {
		refs := append([]metadata.ResourceReference{op.Source()}, op.Dependencies...)
		refs = append(refs, op.Resources...)
		for _, external := range op.External {
			refs = append(refs, external.Resource)
		}
		if op.License != nil && len(op.LicenseXML) == 0 {
			refs = append(refs, *op.License)
		}
		for _, ref := range refs {
			if appPath(paths, ref) == "" {
				return out, fmt.Errorf("requested app payload missing: %s", op.Package.Identity.Name)
			}
		}
	}
	if len(req.Plan.Features) > 0 && len(req.FeatureSources) == 0 {
		return out, fmt.Errorf("NetFx3 matching source payloads unavailable")
	}
	for _, feature := range req.Plan.Features {
		if len(feature.Sources) == 0 {
			return out, fmt.Errorf("NetFx3 matching source identity unavailable")
		}
		for _, ref := range feature.Sources {
			found := false
			for _, input := range req.FeatureSources {
				found = found || input.Resource == ref
			}
			if !found {
				return out, fmt.Errorf("NetFx3 matching source file missing")
			}
		}
	}
	for _, d := range req.Plan.Drivers {
		found := false
		for _, input := range req.Drivers {
			if input.Target != d.Target {
				continue
			}
			found = true
			if err = validateDriverInput(ctx, d.Source, input); err != nil {
				return out, err
			}
		}
		if !found {
			return out, fmt.Errorf("driver source has no verified INF for %s", d.Target)
		}
	}
	for _, input := range req.Drivers {
		allowed := false
		for _, d := range req.Plan.Drivers {
			allowed = allowed || input.Target == d.Target
		}
		if !allowed {
			return out, fmt.Errorf("unrequested driver target %s", input.Target)
		}
	}
	needPE := false
	for _, d := range req.Plan.Drivers {
		needPE = needPE || d.Target == model.DriverWinPE
	}
	if len(req.Images) != len(req.Plan.Editions) || needPE && (len(req.BootImages) < 1 || len(req.BootImages) > 2) {
		return out, fmt.Errorf("customization image closure incomplete")
	}
	validateImage := func(image InspectedImage, edition string, winpe bool) error {
		if image.Index < 1 || image.Identity.Index != image.Index || !strings.EqualFold(image.Identity.Edition, edition) || image.Identity.Architecture != req.Plan.Source.Architecture || image.Identity.Language == "" || !winpe && !strings.EqualFold(image.Identity.Language, req.Plan.Source.Language) {
			return ErrVerification
		}
		if err := verifySHA256(ctx, image.WIMPath, image.SHA256); err != nil {
			return err
		}
		observed, err := e.Backend.InspectWIM(ctx, image.WIMPath, emit)
		if err != nil {
			return err
		}
		if image.Index > len(observed) || !sameImage(observed[image.Index-1], image.Identity) {
			return ErrVerification
		}
		if winpe && len(observed) != len(req.BootImages) {
			return fmt.Errorf("WinPE driver target requires every inspected boot WIM index")
		}
		return nil
	}
	for i, image := range req.Images {
		if err = validateImage(image, req.Plan.Editions[i], false); err != nil {
			return out, err
		}
	}
	if needPE {
		for i, image := range req.BootImages {
			if image.Index != i+1 || image.WIMPath != req.BootImages[0].WIMPath {
				return out, ErrVerification
			}
			if err = validateImage(image, "WindowsPE", true); err != nil {
				return out, err
			}
		}
	}
	out.PlanDigest = req.Plan.Digest
	groups := []struct {
		images []InspectedImage
		target model.DriverTarget
		name   string
	}{{req.Images, model.DriverOS, "customized.wim"}}
	if needPE {
		groups = append(groups, struct {
			images []InspectedImage
			target model.DriverTarget
			name   string
		}{req.BootImages, model.DriverWinPE, "customized-boot.wim"})
	}
	for _, group := range groups {
		finalPath, pathErr := req.Transaction.ScratchPath(group.name)
		if pathErr != nil {
			return CustomizedImages{}, pathErr
		}
		var identities []ImageIdentity
		for i, image := range group.images {
			if err = ctx.Err(); err != nil {
				return CustomizedImages{}, err
			}
			name := fmt.Sprintf("customize-%s-%03d.wim", map[model.DriverTarget]string{model.DriverOS: "os", model.DriverWinPE: "pe"}[group.target], i+1)
			path, pathErr := req.Transaction.ScratchPath(name)
			if pathErr != nil {
				return CustomizedImages{}, pathErr
			}
			if err = e.Backend.Export(ctx, image.ImageRef, path, emit); err != nil {
				return CustomizedImages{}, err
			}
			observation, customErr := e.customizeOne(ctx, req, apps, paths, path, fmt.Sprintf("customize-%s-%d", group.target, i+1), group.target, image.Identity, emit)
			if customErr != nil {
				return CustomizedImages{}, customErr
			}
			if err = e.Backend.Export(ctx, ImageRef{WIMPath: path, Index: 1, Name: image.Identity.Edition}, finalPath, emit); err != nil {
				return CustomizedImages{}, err
			}
			identity := image.Identity
			identity.Packages = observation.Packages
			identity.Index = i + 1
			identities = append(identities, identity)
			if group.target == model.DriverOS {
				out.Observations = append(out.Observations, observation)
			} else {
				out.BootObservations = append(out.BootObservations, observation)
			}
		}
		observed, inspectErr := e.Backend.InspectWIM(ctx, finalPath, emit)
		if inspectErr != nil {
			return CustomizedImages{}, inspectErr
		}
		if len(observed) != len(identities) {
			return CustomizedImages{}, ErrVerification
		}
		for i, image := range observed {
			if !sameImage(image, identities[i]) {
				return CustomizedImages{}, ErrVerification
			}
		}
		output, outputErr := fileOutput(ctx, finalPath, group.name, "customized-"+string(group.target)+"-image")
		if outputErr != nil {
			return CustomizedImages{}, outputErr
		}
		out.Outputs = append(out.Outputs, output)
		if group.target == model.DriverOS {
			out.WIMPath = finalPath
			out.Images = identities
		} else {
			out.BootWIMPath = finalPath
			out.BootImages = identities
		}
	}
	return out, ctx.Err()
}

func (e *CustomizationExecutor) customizeOne(ctx context.Context, req CustomizationRequest, apps planner.AppPlan, paths map[metadata.ResourceReference]string, path, name string, target model.DriverTarget, expected ImageIdentity, emit model.Emit) (out CustomizationObservation, err error) {
	mount, err := req.Transaction.ClaimMount(name)
	if err != nil {
		return out, err
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
			defer cancel()
			err = errors.Join(err, req.Transaction.Unmount(cleanup, mount, func() error {
				return e.Backend.Unmount(cleanup, mount, false, emit)
			}))
		}
	}()
	if err = e.Backend.Mount(ctx, path, mount, emit); err != nil {
		return out, err
	}
	features := req.Plan.Features
	if target == model.DriverWinPE {
		features = nil
		apps = planner.AppPlan{}
	}
	out, err = e.Backend.InspectCustomization(ctx, mount, target, features, emit)
	if err != nil {
		return out, err
	}
	if target == model.DriverOS {
		for _, actual := range out.Apps {
			known := false
			for _, planned := range apps.Provision {
				known = known || strings.EqualFold(actual.Name, planned.Package.Identity.Name) && actual.PublisherID == publisherID(planned.Package.Identity.Publisher)
			}
			for _, removed := range apps.Remove {
				known = known || strings.EqualFold(actual.Name, removed.Name) && actual.PublisherID == publisherID(removed.Publisher)
			}
			if !known {
				return out, fmt.Errorf("post-assembly app inventory omitted provisioned package %s", actual.PackageName)
			}
		}
	}
	for _, removed := range apps.Remove {
		for _, a := range out.Apps {
			if strings.EqualFold(a.Name, removed.Name) && a.PublisherID == publisherID(removed.Publisher) {
				if err = e.Backend.RemoveApp(ctx, mount, a.PackageName, emit); err != nil {
					return out, err
				}
			}
		}
	}
	for _, op := range apps.Provision {
		files := AppFiles{Main: appPath(paths, op.Source()), External: map[string]string{}}
		for _, ref := range append(append([]metadata.ResourceReference(nil), op.Dependencies...), op.Resources...) {
			files.Dependencies = append(files.Dependencies, appPath(paths, ref))
		}
		if op.License != nil {
			files.License = appPath(paths, *op.License)
		}
		for _, external := range op.External {
			files.External[external.Name] = appPath(paths, external.Resource)
		}
		if err = e.Backend.AddApp(ctx, mount, op, files, emit); err != nil {
			return out, err
		}
	}
	for _, feature := range features {
		var sources []UpdateInput
		for _, input := range req.FeatureSources {
			for _, ref := range feature.Sources {
				if input.Resource == ref {
					sources = append(sources, input)
				}
			}
		}
		if err = e.Backend.EnableFeature(ctx, mount, feature, sources, emit); err != nil {
			return out, err
		}
	}
	var expectedDrivers []DriverObservation
	for _, input := range req.Drivers {
		if input.Target != target {
			continue
		}
		expected, infoErr := e.Backend.DriverInfo(ctx, mount, input.INF, emit)
		if infoErr != nil {
			return out, infoErr
		}
		if err = e.Backend.AddDriver(ctx, mount, input.INF, emit); err != nil {
			return out, err
		}
		expectedDrivers = append(expectedDrivers, expected)
	}
	out, err = e.Backend.InspectCustomization(ctx, mount, target, features, emit)
	if err != nil {
		return out, err
	}
	if err = verifyCustomization(apps, features, expectedDrivers, out); err != nil {
		return out, err
	}
	inspection, inspectErr := e.Backend.Inspect(ctx, mount, emit)
	if inspectErr != nil {
		return out, inspectErr
	}
	if !strings.EqualFold(inspection.Edition, expected.Edition) {
		return out, ErrVerification
	}
	var required []metadata.PackageIdentity
	for _, p := range expected.Packages {
		// Staged or absent FoDs such as OneSync are not installed requirements.
		// Keep strict verification for every other state, including unknown ones.
		if strings.EqualFold(p.State, "Staged") || strings.EqualFold(p.State, "Not Present") {
			continue
		}
		required = append(required, p.Identity)
	}
	if err = verifyPackages(inspection.Packages, required); err != nil {
		return out, err
	}
	out.Edition = inspection.Edition
	out.Packages = inspection.Packages
	if err = req.Transaction.Unmount(ctx, mount, func() error {
		return e.Backend.Unmount(ctx, mount, true, emit)
	}); err != nil {
		return out, err
	}
	committed = true
	return out, nil
}
func validateDriverInput(ctx context.Context, source string, input DriverInput) error {
	if !filepath.IsAbs(source) || !filepath.IsAbs(input.INF) || !strings.EqualFold(filepath.Ext(input.INF), ".inf") {
		return fmt.Errorf("absolute driver source/INF required")
	}
	contained := func(path string) bool {
		relative, e := filepath.Rel(source, path)
		return e == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
	}
	found := false
	for _, file := range input.Files {
		if !contained(file.Path) {
			return fmt.Errorf("driver file outside selected source")
		}
		if err := verifySHA256(ctx, file.Path, file.SHA256); err != nil {
			return err
		}
		found = found || strings.EqualFold(file.Path, input.INF)
	}
	if !found {
		return fmt.Errorf("verified INF missing")
	}
	return nil
}
