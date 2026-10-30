package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
)

type ProvisionedApp struct {
	Name, Version, ResourceID, PublisherID, PackageName string
	Architecture                                        model.Architecture
}
type DriverObservation struct{ PublishedName, OriginalName, Provider, Class, Version string }
type CustomizationObservation struct {
	Edition  string
	Packages []PackageObservation
	Apps     []ProvisionedApp
	Features map[string]string
	Drivers  []DriverObservation
}

func rawSHA256(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// Windows package publisher IDs are the first 64 SHA256 bits of the UTF-16LE
// publisher, encoded with Windows' filename-safe base32 alphabet.
func publisherID(publisher string) string {
	return metadata.PublisherID(publisher)
}
func matchesApp(a ProvisionedApp, b metadata.AppIdentity) bool {
	return strings.EqualFold(a.Name, b.Name) && a.Version == b.Version && strings.EqualFold(a.ResourceID, b.ResourceID) && a.PublisherID == publisherID(b.Publisher) && normalizeArchitecture(a.Architecture) == normalizeArchitecture(b.Architecture)
}
func normalizeArchitecture(a model.Architecture) model.Architecture {
	if a == "x64" {
		return "amd64"
	}
	return a
}
func verifyCustomization(apps planner.AppPlan, features []planner.FeatureOperation, drivers []DriverObservation, observed CustomizationObservation) error {
	for _, op := range apps.Provision {
		found := false
		for _, a := range observed.Apps {
			found = found || matchesApp(a, op.ObservedIdentity())
		}
		if !found {
			return fmt.Errorf("%w: provisioned app %s %s missing", ErrVerification, op.Package.Identity.Name, op.Package.Identity.Version)
		}
	}
	for _, removed := range apps.Remove {
		for _, a := range observed.Apps {
			if strings.EqualFold(a.Name, removed.Name) && a.PublisherID == publisherID(removed.Publisher) {
				return fmt.Errorf("%w: removed app %s still provisioned", ErrVerification, removed.Name)
			}
		}
	}
	for _, f := range features {
		state := observed.Features[f.Name]
		if f.Enable && state != "Enabled" && state != "Enable Pending" {
			return fmt.Errorf("%w: feature %s is %q", ErrVerification, f.Name, state)
		}
	}
	for _, want := range drivers {
		found := false
		for _, a := range observed.Drivers {
			found = found || sameDriver(a, want)
		}
		if !found {
			return fmt.Errorf("%w: driver %s %s missing", ErrVerification, want.OriginalName, want.Version)
		}
	}
	return nil
}
func sameDriver(a, b DriverObservation) bool {
	return strings.EqualFold(a.OriginalName, b.OriginalName) && strings.EqualFold(a.Provider, b.Provider) && strings.EqualFold(a.Class, b.Class) && a.Version == b.Version
}

func appArguments(op planner.AppProvision, path string, dependencies []string, license string) ([]string, error) {
	if path == "" {
		return nil, ErrVerification
	}
	args := []string{"/Add-ProvisionedAppxPackage", "/PackagePath:" + path}
	for _, p := range dependencies {
		args = append(args, "/DependencyPackagePath:"+p)
	}
	if op.SkipLicense {
		if license != "" {
			return nil, ErrVerification
		}
		args = append(args, "/SkipLicense")
	} else {
		if license == "" {
			return nil, fmt.Errorf("offline app license required")
		}
		args = append(args, "/LicensePath:"+license)
	}
	switch op.Stub {
	case model.AppStub:
		args = append(args, "/StubPackageOption:installstub")
	case model.AppFull:
		args = append(args, "/StubPackageOption:installfull")
	case model.AppStubAuto:
	default:
		return nil, ErrVerification
	}
	return args, nil
}

func parseProvisionedApps(text string) ([]ProvisionedApp, error) {
	var result []ProvisionedApp
	var current ProvisionedApp
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "DisplayName":
			if current.Name != "" {
				return nil, ErrVerification
			}
			current.Name = value
		case "Version":
			current.Version = value
		case "Architecture":
			current.Architecture = model.Architecture(value)
		case "ResourceId", "ResourceID":
			current.ResourceID = value
		case "PackageName":
			parts := strings.Split(value, "_")
			if len(parts) != 5 || current.Name == "" || !strings.EqualFold(parts[0], current.Name) || parts[1] != current.Version || normalizeArchitecture(model.Architecture(parts[2])) != normalizeArchitecture(current.Architecture) || parts[3] != current.ResourceID || len(parts[4]) != 13 {
				return nil, ErrVerification
			}
			current.PackageName = value
			current.PublisherID = parts[4]
			result = append(result, current)
			current = ProvisionedApp{}
		}
	}
	if current.Name != "" {
		return nil, ErrVerification
	}
	return result, nil
}
