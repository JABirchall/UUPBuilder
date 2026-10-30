package metadata

import (
	"context"
	"strings"

	"uupbuilder/internal/model"
)

// These are raw source declarations, not manifest identities or applicability.
type AppFeatureDependency struct{ FeatureID, Type, FMID, Group string }
type AppMediaHint struct{ PackageID, Type, State string }
type AppLicenseObservation struct {
	PFM, Version, Usage, Category string
	FamilyMatchesIgnoringCase     bool
}
type AppFeatureObservation struct {
	FeatureID, Type, FMID, Group, Selector string
	Dependencies                           []AppFeatureDependency
	Packages                               []CompositionPackageReference
	InitialIntents                         []string
	Media                                  []AppMediaHint
	Licenses                               []AppLicenseObservation
}
type AppCompDBObservation struct {
	BuildID, BaselineOSVersion, Edition, Language string
	Architecture                                  model.Architecture
	Features                                      []AppFeatureObservation
}

// ObserveAppCompDB uses M1's bounded, namespace-aware XML reader. It does not
// infer family identities from filenames or interpret source hints as policy.
func ObserveAppCompDB(ctx context.Context, original []byte) (AppCompDBObservation, error) {
	var out AppCompDBObservation
	if ctx == nil {
		return out, ErrInvalidInput
	}
	if len(original) > 16<<20 {
		return out, ErrLimit
	}
	limits, err := inspectionLimits(Limits{})
	if err != nil {
		return out, err
	}
	// Keep the existing M1 document ceiling and token/depth limits.
	if int64(len(original)) > limits.MaxDocumentBytes {
		return out, ErrLimit
	}
	data, err := decodeMetadata(ctx, original, false, limits.MaxDocumentBytes)
	if err != nil {
		return out, err
	}
	root, err := parseXML(ctx, data, limits)
	if err != nil {
		return out, err
	}
	if root.Name.Local != "CompDB" || root.Name.Space != "http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" || root.attr("SchemaVersion") != "1.2" || root.attr("Type") != "Build" || root.attr("Product") != "Desktop" {
		return out, ErrMalformedMetadata
	}
	if err = singletonChildren(root, "Tags", "Features", "Packages"); err != nil {
		return out, err
	}
	out.BuildID = root.attr("BuildID")
	out.BaselineOSVersion = root.attr("OSVersion")
	out.Architecture = model.Architecture(root.attr("BuildArch"))
	if out.BuildID == "" || out.BaselineOSVersion == "" || out.Architecture.Validate() != nil {
		return out, ErrMalformedMetadata
	}
	tags := map[string]bool{}
	for _, tag := range root.child("Tags").children("Tag") {
		name := tag.attr("Name")
		if tags[name] {
			return out, ErrConflictingMetadata
		}
		tags[name] = true
		if name == "Edition" {
			out.Edition = tag.attr("Value")
		}
		if name == "Language" {
			out.Language = tag.attr("Value")
		}
	}
	seen := map[string]bool{}
	for _, node := range root.child("Features").children("Feature") {
		f := AppFeatureObservation{FeatureID: node.attr("FeatureID"), Type: node.attr("Type"), FMID: node.attr("FMID"), Group: node.attr("Group")}
		if f.FeatureID == "" || seen[strings.ToLower(f.FeatureID)] {
			return out, ErrConflictingMetadata
		}
		seen[strings.ToLower(f.FeatureID)] = true
		f.Selector = "/CompDB/Features/Feature[@FeatureID='" + f.FeatureID + "']"
		if err = singletonChildren(node, "Dependencies", "InitialIntents", "CustomInformation", "Packages"); err != nil {
			return out, err
		}
		for _, d := range node.child("Dependencies").children("Feature") {
			if d.attr("FeatureID") == "" {
				return out, ErrMalformedMetadata
			}
			f.Dependencies = append(f.Dependencies, AppFeatureDependency{FeatureID: d.attr("FeatureID"), Type: d.attr("Type"), FMID: d.attr("FMID"), Group: d.attr("Group")})
		}
		for _, intent := range node.child("InitialIntents").children("InitialIntent") {
			f.InitialIntents = append(f.InitialIntents, intent.attr("Value"))
		}
		for _, p := range node.child("Packages").children("Package") {
			if p.attr("ID") == "" {
				return out, ErrMalformedMetadata
			}
			f.Packages = append(f.Packages, CompositionPackageReference{ID: p.attr("ID"), Type: p.attr("PackageType"), UpdateType: p.attr("UpdateType")})
			for _, m := range p.children("Media") {
				f.Media = append(f.Media, AppMediaHint{PackageID: p.attr("ID"), Type: m.attr("Type"), State: m.attr("State")})
			}
		}
		for _, info := range node.child("CustomInformation").children("CustomInfo") {
			if info.attr("Key") != "licensedata" {
				continue
			}
			license, parseErr := parseXML(ctx, []byte(info.text()), limits)
			if parseErr != nil {
				return out, parseErr
			}
			if license.Name.Local != "License" || license.Name.Space != "urn:schemas-microsoft-com:windows:store:licensing:ls" {
				return out, ErrMalformedMetadata
			}
			if err = singletonChildren(license, "Binding", "LicenseInfo"); err != nil {
				return out, err
			}
			binding := license.child("Binding")
			if err = singletonChildren(binding, "PFM"); err != nil {
				return out, err
			}
			pfm := binding.child("PFM").text()
			f.Licenses = append(f.Licenses, AppLicenseObservation{PFM: pfm, Version: license.attr("Version"), Usage: license.child("LicenseInfo").attr("LicenseUsage"), Category: license.child("LicenseInfo").attr("LicenseCategory"), FamilyMatchesIgnoringCase: pfm != "" && strings.EqualFold(pfm, f.FeatureID)})
		}
		out.Features = append(out.Features, f)
	}
	return out, nil
}
