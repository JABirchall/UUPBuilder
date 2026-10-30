package metadata

import (
	"fmt"
	"strings"
	"uupbuilder/internal/model"
)

type AppBundlePackage struct {
	FileName, Type, Version, ResourceID string
	Architecture                        model.Architecture
	Languages                           []string
}
type AppBundle struct {
	Identity AppIdentity
	Packages []AppBundlePackage
	Evidence Evidence
}

func (inv *Inventory) parseAppBundle(root *xmlNode, doc DocumentReference) error {
	if root.Name.Local != "Bundle" || (root.Name.Space != "http://schemas.microsoft.com/appx/2016/bundle" && root.Name.Space != "http://schemas.microsoft.com/appx/2013/bundle") {
		return fmt.Errorf("%w: Appx bundle namespace", ErrMalformedMetadata)
	}
	if err := singletonChildren(root, "Identity", "Packages"); err != nil {
		return err
	}
	id := root.child("Identity")
	bundle := AppBundle{Identity: AppIdentity{Name: id.attr("Name"), Publisher: id.attr("Publisher"), Version: id.attr("Version"), Architecture: "neutral", ResourceID: "~"}, Evidence: inv.evidence(doc, "/Bundle/Identity")}
	if bundle.Identity.Name == "" || bundle.Identity.Publisher == "" || !validVersion(bundle.Identity.Version) {
		return ErrMalformedMetadata
	}
	seen := map[string]bool{}
	for _, node := range root.child("Packages").children("Package") {
		p := AppBundlePackage{FileName: node.attr("FileName"), Type: node.attr("Type"), Version: node.attr("Version"), ResourceID: node.attr("ResourceId"), Architecture: model.Architecture(node.attr("Architecture"))}
		clean, e := model.ValidateRelativePath(p.FileName)
		if e != nil || clean != p.FileName || strings.Contains(clean, "/") || seen[strings.ToLower(clean)] || !validVersion(p.Version) || (p.Type != "application" && p.Type != "resource") {
			return ErrMalformedMetadata
		}
		seen[strings.ToLower(clean)] = true
		if p.Architecture == "" {
			p.Architecture = "neutral"
		}
		if p.Architecture != "neutral" && p.Architecture != "x64" && p.Architecture.Validate() != nil {
			return ErrMalformedMetadata
		}
		for _, r := range node.child("Resources").children("Resource") {
			if lang := r.attr("Language"); lang != "" {
				p.Languages = append(p.Languages, lang)
			}
		}
		bundle.Packages = append(bundle.Packages, p)
	}
	if len(bundle.Packages) == 0 {
		return ErrMalformedMetadata
	}
	inv.Apps.Bundles = append(inv.Apps.Bundles, bundle)
	return nil
}
