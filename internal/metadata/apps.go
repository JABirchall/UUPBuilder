package metadata

import (
	"fmt"
	"strconv"
	"strings"
	"uupbuilder/internal/model"
)

// AppFamily retains the documented family-defining name/publisher pair. It is
// not a guessed Windows PackageFamilyName string or a translated display name.
type AppFamily struct{ Name, Publisher string }
type AppIdentity struct {
	Name, Publisher, Version, ResourceID string
	Architecture                         model.Architecture
}
type AppDependency struct {
	Family                            AppFamily
	MinVersion, MaxMajorVersionTested string
	Optional                          bool
}
type AppPhase string

const (
	PhaseUnknown             AppPhase = "unknown"
	PhaseOfflineProvisioning AppPhase = "offline-provisioning"
	PhasePostAssembly        AppPhase = "post-assembly"
)

type AppPackage struct {
	Identity                   AppIdentity
	Family                     AppFamily
	DisplayName                string
	Framework, ResourcePackage bool
	Dependencies               []AppDependency
	Languages                  []string
	TargetDeviceFamilies       []TargetDeviceFamily
	Applications               []ApplicationIdentity
	Licenses                   []LicenseEvidence
	Phase                      AppPhase
	PhaseEvidence              *Evidence
	Evidence                   Evidence
}
type TargetDeviceFamily struct{ Name, MinVersion, MaxVersionTested string }
type ApplicationIdentity struct{ ID, Executable, EntryPoint string }
type AppInventory struct {
	Packages         []AppPackage
	RequiredFamilies []AppFamily
	LicenseDocuments []AppLicense
}

// AppLicense is an observation of declared licensing metadata, not signature,
// entitlement, validity or permission-to-provision verification.
type AppLicense struct {
	PackageFamilyName, BindingType, Usage, Category, Type, LicenseID, ContentID string
	Resource                                                                    ResourceReference
	Evidence                                                                    Evidence
}
type LicenseEvidence struct {
	Family   AppFamily
	Resource ResourceReference
	Evidence Evidence
}
type AppPhaseEvidence struct {
	Family   AppFamily
	Phase    AppPhase
	Evidence Evidence
}

func (inv *Inventory) parseStoreLicense(root *xmlNode, doc DocumentReference) error {
	if root.Name.Local != "License" || root.Name.Space != "urn:schemas-microsoft-com:windows:store:licensing:ls" || root.attr("Version") != "3" {
		inv.gap("unsupported-schema", "Store license namespace/version", &doc)
		return nil
	}
	if err := singletonChildren(root, "Binding", "LicenseInfo"); err != nil {
		return err
	}
	binding, info := root.child("Binding"), root.child("LicenseInfo")
	if err := singletonChildren(binding, "PFM"); err != nil {
		return err
	}
	license := AppLicense{PackageFamilyName: binding.child("PFM").text(), BindingType: binding.attr("Binding_Type"), Usage: info.attr("LicenseUsage"), Category: info.attr("LicenseCategory"), Type: info.attr("Type"), LicenseID: root.attr("LicenseID"), ContentID: root.attr("ContentID"), Resource: doc.Resource, Evidence: inv.evidence(doc, "/License/Binding/PFM")}
	if license.PackageFamilyName == "" {
		return fmt.Errorf("%w: Store license PFM", ErrMalformedMetadata)
	}
	inv.Apps.LicenseDocuments = append(inv.Apps.LicenseDocuments, license)
	inv.gap("license-linkage-unresolved", license.PackageFamilyName+": no verified linkage to an app identity", &doc)
	return nil
}

func validVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 16); err != nil {
			return false
		}
	}
	return true
}
func versionAtLeast(value, minimum string) bool {
	if !validVersion(value) || !validVersion(minimum) {
		return false
	}
	left, right := strings.Split(value, "."), strings.Split(minimum, ".")
	for i := range left {
		a, _ := strconv.ParseUint(left[i], 10, 16)
		b, _ := strconv.ParseUint(right[i], 10, 16)
		if a != b {
			return a > b
		}
	}
	return true
}
func boolProperty(node *xmlNode) (bool, error) {
	if node == nil {
		return false, nil
	}
	value, err := strconv.ParseBool(node.text())
	if err != nil {
		return false, fmt.Errorf("%w: app boolean", ErrMalformedMetadata)
	}
	return value, nil
}
func (inv *Inventory) parseAppx(root *xmlNode, doc DocumentReference) error {
	if root.Name.Local != "Package" || (root.Name.Space != "http://schemas.microsoft.com/appx/manifest/foundation/windows10" && root.Name.Space != "http://schemas.microsoft.com/appx/2010/manifest") {
		inv.gap("unsupported-schema", "Appx package namespace", &doc)
		return nil
	}
	if err := singletonChildren(root, "Identity", "Properties", "Dependencies", "Resources", "Applications"); err != nil {
		return err
	}
	if len(root.children("Identity")) != 1 {
		return fmt.Errorf("%w: Appx identity", ErrMalformedMetadata)
	}
	node := root.child("Identity")
	id := AppIdentity{Name: node.attr("Name"), Publisher: node.attr("Publisher"), Version: node.attr("Version"), ResourceID: node.attr("ResourceId"), Architecture: model.Architecture(node.attr("ProcessorArchitecture"))}
	if id.Name == "" || id.Publisher == "" || !validVersion(id.Version) {
		return fmt.Errorf("%w: Appx identity", ErrMalformedMetadata)
	}
	properties := root.child("Properties")
	if err := singletonChildren(properties, "DisplayName", "Framework", "ResourcePackage"); err != nil {
		return err
	}
	framework, err := boolProperty(properties.child("Framework"))
	if err != nil {
		return err
	}
	resourcePackage, err := boolProperty(properties.child("ResourcePackage"))
	if err != nil {
		return err
	}
	app := AppPackage{Identity: id, Family: AppFamily{Name: id.Name, Publisher: id.Publisher}, DisplayName: properties.child("DisplayName").text(), Framework: framework, ResourcePackage: resourcePackage, Phase: PhaseUnknown, Evidence: inv.evidence(doc, "/Package/Identity")}
	seen := make(map[string]bool)
	for _, dependency := range root.child("Dependencies").children("PackageDependency") {
		dep := AppDependency{Family: AppFamily{Name: dependency.attr("Name"), Publisher: dependency.attr("Publisher")}, MinVersion: dependency.attr("MinVersion"), MaxMajorVersionTested: dependency.attr("MaxMajorVersionTested")}
		if dep.Family.Name == "" || !validVersion(dep.MinVersion) || seen[dep.Family.Name] {
			return fmt.Errorf("%w: Appx dependency", ErrMalformedMetadata)
		}
		seen[dep.Family.Name] = true
		for _, attr := range dependency.Attr {
			if attr.Name.Space == "http://schemas.microsoft.com/appx/manifest/uap/windows10/6" && attr.Name.Local == "Optional" {
				value, err := strconv.ParseBool(attr.Value)
				if err != nil {
					return ErrMalformedMetadata
				}
				dep.Optional = value
			}
		}
		app.Dependencies = append(app.Dependencies, dep)
	}
	for _, family := range root.child("Dependencies").children("TargetDeviceFamily") {
		app.TargetDeviceFamilies = append(app.TargetDeviceFamilies, TargetDeviceFamily{Name: family.attr("Name"), MinVersion: family.attr("MinVersion"), MaxVersionTested: family.attr("MaxVersionTested")})
	}
	for _, language := range root.child("Resources").children("Resource") {
		if value := language.attr("Language"); value != "" {
			app.Languages = append(app.Languages, value)
		}
	}
	for _, application := range root.child("Applications").children("Application") {
		app.Applications = append(app.Applications, ApplicationIdentity{ID: application.attr("Id"), Executable: application.attr("Executable"), EntryPoint: application.attr("EntryPoint")})
	}
	for _, old := range inv.Apps.Packages {
		if old.Identity == app.Identity {
			return fmt.Errorf("%w: duplicate Appx identity", ErrConflictingMetadata)
		}
	}
	inv.Apps.Packages = append(inv.Apps.Packages, app)
	return nil
}

func appArchitectureCompatible(target model.Architecture, app, framework model.Architecture) bool {
	if framework == "neutral" {
		return true
	}
	if app == "neutral" {
		app = target
	}
	if app == "" || framework == "" {
		return false
	}
	if app == "x64" {
		app = "amd64"
	}
	if framework == "x64" {
		framework = "amd64"
	}
	return app == framework
}
