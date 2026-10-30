package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
)

func (d *DISM) AddApp(ctx context.Context, m platform.OwnedMount, op planner.AppProvision, files AppFiles, emit model.Emit) error {
	source := op.Source()
	path, e := d.stageAppFile(ctx, "packages/apps/"+source.Payload.Key()+"/"+filepath.Base(source.Payload.Provenance.Name), source.Payload, files.Main)
	if e != nil {
		return e
	}
	for _, external := range op.External {
		if _, e = d.stageAppFile(ctx, "packages/apps/"+source.Payload.Key()+"/"+external.Name, external.Resource.Payload, files.External[external.Name]); e != nil {
			return e
		}
	}
	var deps []string
	refs := append(append([]metadata.ResourceReference(nil), op.Dependencies...), op.Resources...)
	if len(refs) != len(files.Dependencies) {
		return ErrVerification
	}
	for i, ref := range refs {
		staged, err := d.stageAppFile(ctx, "packages/apps/"+ref.Payload.Key()+"/"+filepath.Base(ref.Payload.Provenance.Name), ref.Payload, files.Dependencies[i])
		if err != nil {
			return err
		}
		deps = append(deps, staged)
	}
	license := files.License
	if len(op.LicenseXML) > 0 {
		name := "packages/apps/" + source.Payload.Key() + "/license.xml"
		file, err := d.workspace.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if errors.Is(err, os.ErrExist) {
			license = filepath.Join(d.workspace.Path(), filepath.FromSlash(name))
			if err = verifySHA256(ctx, license, rawSHA256(op.LicenseXML)); err != nil {
				return err
			}
		} else {
			if err != nil {
				return err
			}
			_, writeErr := file.Write(op.LicenseXML)
			if err = errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
				return err
			}
			license = filepath.Join(d.workspace.Path(), filepath.FromSlash(name))
		}
	} else if op.License != nil {
		license, e = d.stageAppFile(ctx, "packages/apps/"+source.Payload.Key()+"/license.xml", op.License.Payload, files.License)
		if e != nil {
			return e
		}
	}
	args, e := appArguments(op, path, deps, license)
	if e != nil {
		return e
	}
	_, e = d.offline(ctx, m, emit, args...)
	return e
}

func (d *DISM) stageAppFile(ctx context.Context, name string, id model.PayloadIdentity, path string) (string, error) {
	clean, e := model.ValidateRelativePath(name)
	if e != nil || clean != name {
		return "", ErrVerification
	}
	if e = d.workspace.MkdirAll(filepath.ToSlash(filepath.Dir(name))); e != nil {
		return "", e
	}
	staged := filepath.Join(d.workspace.Path(), filepath.FromSlash(name))
	file, e := d.workspace.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(e, os.ErrExist) {
		return staged, verifyUpdateFile(ctx, id, staged)
	}
	if e != nil {
		return "", e
	}
	src, e := os.Open(path)
	if e != nil {
		file.Close()
		return "", e
	}
	_, copyErr := io.Copy(file, &contextReader{ctx, src})
	e = errors.Join(copyErr, src.Close(), file.Sync(), file.Close())
	if e != nil {
		return "", e
	}
	return staged, verifyUpdateFile(ctx, id, staged)
}
func (d *DISM) RemoveApp(ctx context.Context, m platform.OwnedMount, name string, emit model.Emit) error {
	if len(strings.Split(name, "_")) != 5 || strings.ContainsAny(name, "/\\:\r\n\x00") {
		return ErrVerification
	}
	_, e := d.offline(ctx, m, emit, "/Remove-ProvisionedAppxPackage", "/PackageName:"+name)
	return e
}
func (d *DISM) EnableFeature(ctx context.Context, m platform.OwnedMount, op planner.FeatureOperation, sources []UpdateInput, emit model.Emit) error {
	if op.Name != "NetFx3" || !op.Enable || len(sources) == 0 {
		return fmt.Errorf("NetFx3 requires verified matching source files")
	}
	args := []string{"/Enable-Feature", "/FeatureName:NetFx3", "/All", "/LimitAccess"}
	for _, source := range sources {
		name := filepath.Base(source.Resource.Payload.Provenance.Name)
		if !strings.EqualFold(filepath.Ext(name), ".cab") {
			return fmt.Errorf("NetFx3 source is not a verified CAB")
		}
		if _, e := d.stageAppFile(ctx, "packages/netfx3/"+name, source.Resource.Payload, source.Path); e != nil {
			return e
		}
	}
	args = append(args, "/Source:"+filepath.Join(d.workspace.Path(), "packages", "netfx3"))
	_, e := d.offline(ctx, m, emit, args...)
	return e
}
func (d *DISM) DriverInfo(ctx context.Context, m platform.OwnedMount, path string, emit model.Emit) (DriverObservation, error) {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".inf") {
		return DriverObservation{}, ErrVerification
	}
	text, e := d.offline(ctx, m, emit, "/Get-DriverInfo", "/Driver:"+path)
	if e != nil {
		return DriverObservation{}, e
	}
	out, e := parseDrivers(text)
	if e != nil || len(out) != 1 {
		return DriverObservation{}, fmt.Errorf("%w: INF metadata unavailable", ErrVerification)
	}
	return out[0], nil
}
func (d *DISM) AddDriver(ctx context.Context, m platform.OwnedMount, path string, emit model.Emit) error {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".inf") {
		return ErrVerification
	}
	_, e := d.offline(ctx, m, emit, "/Add-Driver", "/Driver:"+path)
	return e
}
func (d *DISM) InspectCustomization(ctx context.Context, m platform.OwnedMount, target model.DriverTarget, features []planner.FeatureOperation, emit model.Emit) (CustomizationObservation, error) {
	out := CustomizationObservation{Features: map[string]string{}}
	var text string
	var e error
	if target == model.DriverOS {
		text, e = d.offline(ctx, m, emit, "/Get-ProvisionedAppxPackages")
		if e != nil {
			return out, e
		}
		if out.Apps, e = parseProvisionedApps(text); e != nil {
			return out, e
		}
	}
	for _, f := range features {
		if f.Name != "NetFx3" {
			return out, ErrVerification
		}
		text, e = d.offline(ctx, m, emit, "/Get-FeatureInfo", "/FeatureName:NetFx3")
		if e != nil {
			return out, e
		}
		name, state := "", ""
		for _, line := range strings.Split(text, "\n") {
			k, v, ok := strings.Cut(line, ":")
			if ok {
				switch strings.TrimSpace(k) {
				case "Feature Name":
					name = strings.TrimSpace(v)
				case "State":
					state = strings.TrimSpace(v)
				}
			}
		}
		if name != f.Name || state == "" {
			return out, ErrVerification
		}
		out.Features[name] = state
	}
	text, e = d.offline(ctx, m, emit, "/Get-Drivers", "/All", "/Format:List")
	if e != nil {
		return out, e
	}
	out.Drivers, e = parseDrivers(text)
	return out, e
}
func parseDrivers(text string) ([]DriverObservation, error) {
	var out []DriverObservation
	var current DriverObservation
	flush := func() error {
		if current.OriginalName == "" {
			return nil
		}
		if current.Provider == "" || current.Class == "" || current.Version == "" {
			return ErrVerification
		}
		out = append(out, current)
		current = DriverObservation{}
		return nil
	}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "Published Name", "Driver":
			if e := flush(); e != nil {
				return nil, e
			}
			current.PublishedName = v
		case "Original File Name":
			if current.OriginalName != "" {
				if e := flush(); e != nil {
					return nil, e
				}
			}
			current.OriginalName = filepath.Base(v)
		case "Provider Name":
			current.Provider = v
		case "Class Name":
			current.Class = v
		case "Version":
			current.Version = v
		}
	}
	if e := flush(); e != nil {
		return nil, e
	}
	return out, nil
}
