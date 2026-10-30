package metadata

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"unicode/utf16"
)

// PublisherID and AppFamilyName derive the Windows package identity from the
// manifest's publisher. Neither a translated display name nor a filename is used.
func PublisherID(publisher string) string {
	units := utf16.Encode([]rune(publisher))
	raw := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], u)
	}
	sum := sha256.Sum256(raw)
	return base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding).EncodeToString(sum[:8])
}
func AppFamilyName(f AppFamily) string { return f.Name + "_" + PublisherID(f.Publisher) }
func AppFullName(id AppIdentity) string {
	arch := string(id.Architecture)
	if arch == "amd64" {
		arch = "x64"
	}
	return id.Name + "_" + id.Version + "_" + arch + "_" + id.ResourceID + "_" + PublisherID(id.Publisher)
}

// BindAppPolicies interprets this generation's CompDB declarations against
// already inspected app manifests. It retains the exact source document and
// embedded license bytes. Native DISM validates signed packages/licenses when
// applying the plan; parsing alone does not prove provisionability.
func BindAppPolicies(ctx context.Context, inv Inventory, sourceDoc DocumentReference) (Inventory, error) {
	fail := func(s string) (Inventory, error) { return Inventory{}, fmt.Errorf("app source policy: %s", s) }
	if ctx == nil || inv.Source.Validate() != nil || inv.Manifest.Validate() != nil || inv.Manifest.Source != inv.Source {
		return fail("invalid source")
	}
	var raw []byte
	for _, d := range inv.Documents {
		if d.Reference == sourceDoc {
			raw = d.Original
		}
	}
	sum := sha256.Sum256(raw)
	if len(raw) == 0 || hex.EncodeToString(sum[:]) != sourceDoc.SHA256 {
		return fail("source document identity changed")
	}
	observation, e := ObserveAppCompDB(ctx, raw)
	if e != nil {
		return Inventory{}, e
	}
	if observation.Architecture != inv.Source.Architecture || !strings.HasPrefix(observation.BaselineOSVersion, "10.0.28000.") {
		return fail("rules unavailable for this source generation")
	}
	limits, _ := inspectionLimits(Limits{})
	root, e := parseXML(ctx, raw, limits)
	if e != nil {
		return Inventory{}, e
	}
	inv.Apps.Packages = slices.Clone(inv.Apps.Packages)
	inv.Apps.LicenseDocuments = slices.Clone(inv.Apps.LicenseDocuments)
	inv.Apps.SelectionRules = nil
	inv.Apps.DefaultIDs = nil
	familyByID := map[string]AppFamily{}
	for _, feature := range observation.Features {
		for _, app := range inv.Apps.Packages {
			if strings.EqualFold(AppFamilyName(app.Family), feature.FeatureID) {
				familyByID[feature.FeatureID] = app.Family
				break
			}
		}
	}
	for _, feature := range observation.Features {
		installed := false
		for _, m := range feature.Media {
			installed = installed || m.Type == "CleanInstall" && m.State == "INSTALLED"
		}
		if installed && feature.Type != "MSIXFramework" {
			inv.Apps.DefaultIDs = append(inv.Apps.DefaultIDs, feature.FeatureID)
		}
		family, ok := familyByID[feature.FeatureID]
		if !ok {
			continue
		}
		if feature.Type != "MSIX" && feature.Type != "MSIXBundle" && feature.Type != "MSIXFramework" {
			return fail("unsupported app feature type " + feature.Type)
		}
		evidence := inv.evidence(sourceDoc, feature.Selector)
		rule := AppSelectionRule{ID: feature.FeatureID, Family: family, Default: installed, Evidence: evidence}
		for _, intent := range feature.InitialIntents {
			rule.StubSupported = rule.StubSupported || intent == "PREFERSTUB"
		}
		for i := range inv.Apps.Packages {
			app := &inv.Apps.Packages[i]
			if app.Family != family {
				continue
			}
			app.Dependencies = slices.Clone(app.Dependencies)
			app.Licenses = slices.Clone(app.Licenses)
			// Link the complete source package identity, including bundle version, to
			// its declaration. Resource manifests are linked through their bundle.
			declared := app.ResourcePackage
			for _, media := range feature.Media {
				declared = declared || strings.EqualFold(media.PackageID, AppFullName(app.Identity))
				for _, bundle := range inv.Apps.Bundles {
					if bundle.Identity.Name == family.Name && bundle.Identity.Publisher == family.Publisher {
						declared = declared || strings.EqualFold(media.PackageID, AppFullName(bundle.Identity))
					}
				}
			}
			if !declared {
				return fail("manifest identity not declared by source feature " + feature.FeatureID)
			}
			if feature.Type == "MSIXFramework" && app.Framework {
				rule.LicenseFree = true
			}
			app.Phase = PhaseOfflineProvisioning
			phaseEvidence := evidence
			app.PhaseEvidence = &phaseEvidence
			for _, dep := range feature.Dependencies {
				if dep.Type != "Required" {
					continue
				}
				dependencyFamily, ok := familyByID[dep.FeatureID]
				if !ok {
					return fail("required framework manifest missing: " + dep.FeatureID)
				}
				exists := false
				for _, d := range app.Dependencies {
					exists = exists || d.Family == dependencyFamily
				}
				if !exists {
					app.Dependencies = append(app.Dependencies, AppDependency{Family: dependencyFamily, MinVersion: "0.0.0.0"})
				}
			}
		}
		inv.Apps.SelectionRules = append(inv.Apps.SelectionRules, rule)
		for _, node := range root.child("Features").children("Feature") {
			if node.attr("FeatureID") != feature.FeatureID {
				continue
			}
			for _, info := range node.child("CustomInformation").children("CustomInfo") {
				if info.attr("Key") != "licensedata" {
					continue
				}
				licenseRaw := []byte(info.text())
				licenseRoot, err := parseXML(ctx, licenseRaw, limits)
				if err != nil {
					return Inventory{}, err
				}
				temp := Inventory{Source: inv.Source}
				if err = temp.parseStoreLicense(licenseRoot, sourceDoc); err != nil {
					return Inventory{}, err
				}
				if len(temp.Apps.LicenseDocuments) != 1 {
					return fail("license document unresolved")
				}
				license := temp.Apps.LicenseDocuments[0]
				if !strings.EqualFold(license.PackageFamilyName, AppFamilyName(family)) {
					return fail("license family mismatch: " + feature.FeatureID)
				}
				license.Resource = ResourceReference{Payload: sourceDoc.Resource.Payload, Member: sourceDoc.Resource.Member + "/licenses/" + feature.FeatureID + ".xml"}
				license.Evidence = evidence
				license.Original = slices.Clone(licenseRaw)
				inv.Apps.LicenseDocuments = append(inv.Apps.LicenseDocuments, license)
				for i := range inv.Apps.Packages {
					if inv.Apps.Packages[i].Family == family {
						inv.Apps.Packages[i].Licenses = append(inv.Apps.Packages[i].Licenses, LicenseEvidence{Family: family, Resource: license.Resource, Evidence: evidence})
					}
				}
			}
		}
	}
	retained := make([]Gap, 0, len(inv.Gaps))
	for _, gap := range inv.Gaps {
		switch gap.Code {
		case "app-inventory-unresolved", "app-selection-rules-unresolved", "app-phase-unresolved", "app-license-unresolved", "app-dependency-unresolved", "license-linkage-unresolved":
		default:
			retained = append(retained, gap)
		}
	}
	inv.Gaps = retained
	inv.appGaps()
	if len(inv.Gaps) == 0 && inv.Classification == ClassificationMetadataIncomplete {
		inv.Classification = ClassificationSemanticInventory
	}
	return inv, ctx.Err()
}
