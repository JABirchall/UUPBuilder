package metadata

import (
	"fmt"
	"uupbuilder/internal/model"
)

type PackageIdentity struct {
	Name, Version, PublicKeyToken, Language string
	Architecture                            model.Architecture
}
type PackageDependency struct {
	Identity PackageIdentity
	Type     string
}
type Package struct {
	Identity                PackageIdentity
	Identifier, ReleaseType string
	Dependencies            []PackageDependency
	Evidence                Evidence
}

func assemblyIdentity(node *xmlNode) PackageIdentity {
	return PackageIdentity{Name: node.attr("name"), Version: node.attr("version"), PublicKeyToken: node.attr("publicKeyToken"), Language: node.attr("language"), Architecture: model.Architecture(node.attr("processorArchitecture"))}
}
func (inv *Inventory) parseCBS(root *xmlNode, doc DocumentReference) error {
	if root.Name.Local != "assembly" || root.Name.Space != "urn:schemas-microsoft-com:asm.v3" || root.attr("manifestVersion") != "1.0" {
		inv.gap("unsupported-schema", "CBS assembly schema/version", &doc)
		return nil
	}
	if len(root.children("assemblyIdentity")) != 1 {
		return fmt.Errorf("%w: CBS identity", ErrMalformedMetadata)
	}
	identity := assemblyIdentity(root.child("assemblyIdentity"))
	if identity.Name == "" || identity.Version == "" {
		return fmt.Errorf("%w: CBS identity", ErrMalformedMetadata)
	}
	pack := root.child("package")
	result := Package{Identity: identity, Identifier: pack.attr("identifier"), ReleaseType: pack.attr("releaseType"), Evidence: inv.evidence(doc, "/assembly/assemblyIdentity")}
	for _, dependency := range root.children("dependency") {
		for _, dependent := range dependency.children("dependentAssembly") {
			id := assemblyIdentity(dependent.child("assemblyIdentity"))
			if id.Name == "" {
				return fmt.Errorf("%w: CBS dependency identity", ErrMalformedMetadata)
			}
			result.Dependencies = append(result.Dependencies, PackageDependency{Identity: id, Type: dependent.attr("dependencyType")})
		}
	}
	for _, parent := range root.children("parent") {
		for _, node := range parent.children("assemblyIdentity") {
			result.Dependencies = append(result.Dependencies, PackageDependency{Identity: assemblyIdentity(node), Type: "parent"})
		}
	}
	inv.Packages = append(inv.Packages, result)
	return nil
}
