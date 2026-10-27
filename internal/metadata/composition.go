package metadata

import (
	"fmt"
	"strconv"
	"uupbuilder/internal/model"
)

type Composition struct {
	Name, Revision, Type, BuildID, BuildInfo, OSVersion                string
	Product, TagsType, TargetBuildID, TargetBuildInfo, TargetOSVersion string
	Architecture                                                       model.Architecture
	Tags                                                               []CompositionTag
	Packages                                                           []CompositionPackage
	Features                                                           []CompositionFeature
	Evidence                                                           Evidence
}
type CompositionTag struct{ Name, Value string }
type CompositionPackage struct {
	ID, Type           string
	Version            string
	InstalledSize      int64
	InstalledSizeKnown bool
	Payloads           []CompositionPayload
}
type CompositionFeature struct {
	ID, Type, FMID, Group, Family string
	Dependencies                  []string
	Packages                      []CompositionPackageReference
}
type CompositionPackageReference struct{ ID, Type, UpdateType string }
type PayloadBinding struct {
	PackageID, PayloadHash string
	Resource               ResourceReference
	Evidence               Evidence
}
type CompositionPayload struct {
	Path, Hash, HashAlgorithm string
	Type                      string
	Size                      int64
	Resource                  *ResourceReference
	Binding                   *PayloadBinding
}

func (inv *Inventory) parseComposition(root *xmlNode, doc DocumentReference, known map[model.PayloadIdentity]bool) error {
	if root.Name.Local != "CompDB" || root.Name.Space != "http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" || root.attr("SchemaVersion") != "1.2" {
		inv.gap("unsupported-schema", "CompDB namespace/schema version", &doc)
		return nil
	}
	if err := singletonChildren(root, "Tags", "Features", "Packages"); err != nil {
		return err
	}
	comp := Composition{Name: root.attr("Name"), Revision: root.attr("Revision"), Type: root.attr("Type"), BuildID: root.attr("BuildID"), BuildInfo: root.attr("BuildInfo"), OSVersion: root.attr("OSVersion"), Architecture: model.Architecture(root.attr("BuildArch")), Product: root.attr("Product"), TargetBuildID: root.attr("TargetBuildID"), TargetBuildInfo: root.attr("TargetBuildInfo"), TargetOSVersion: root.attr("TargetOSVersion"), Evidence: inv.evidence(doc, "/CompDB")}
	if err := inv.architecture(comp.Architecture); err != nil {
		return err
	}
	if comp.Architecture == "" {
		inv.gap("composition-architecture-unresolved", "CompDB lacks BuildArch", &doc)
	}
	comp.TagsType = root.child("Tags").attr("Type")
	for _, tag := range root.child("Tags").children("Tag") {
		comp.Tags = append(comp.Tags, CompositionTag{Name: tag.attr("Name"), Value: tag.attr("Value")})
	}
	featureIDs := make(map[string]bool)
	for _, node := range root.child("Features").children("Feature") {
		if err := singletonChildren(node, "Dependencies", "Packages"); err != nil {
			return err
		}
		feature := CompositionFeature{ID: node.attr("FeatureID"), Type: node.attr("Type"), FMID: node.attr("FMID"), Group: node.attr("Group"), Family: node.attr("Family")}
		if feature.ID == "" || featureIDs[feature.ID] {
			return fmt.Errorf("%w: CompDB feature ID", ErrMalformedMetadata)
		}
		featureIDs[feature.ID] = true
		for _, dependency := range node.child("Dependencies").children("Feature") {
			if dependency.attr("FeatureID") == "" {
				return ErrMalformedMetadata
			}
			feature.Dependencies = append(feature.Dependencies, dependency.attr("FeatureID"))
		}
		for _, pack := range node.child("Packages").children("Package") {
			if pack.attr("ID") == "" {
				return ErrMalformedMetadata
			}
			feature.Packages = append(feature.Packages, CompositionPackageReference{ID: pack.attr("ID"), Type: pack.attr("PackageType"), UpdateType: pack.attr("UpdateType")})
		}
		comp.Features = append(comp.Features, feature)
	}
	packageIDs := make(map[string]bool)
	for _, node := range root.child("Packages").children("Package") {
		if err := singletonChildren(node, "Payload"); err != nil {
			return err
		}
		pack := CompositionPackage{ID: node.attr("ID"), Type: node.attr("PackageType"), Version: node.attr("Version")}
		if pack.ID == "" || packageIDs[pack.ID] {
			return fmt.Errorf("%w: CompDB package ID", ErrMalformedMetadata)
		}
		packageIDs[pack.ID] = true
		if raw := node.attr("InstalledSize"); raw != "" {
			value, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || value < 0 {
				return ErrMalformedMetadata
			}
			pack.InstalledSize = value
			pack.InstalledSizeKnown = true
		}
		for _, item := range node.child("Payload").children("PayloadItem") {
			payload := CompositionPayload{Path: item.attr("Path"), Hash: item.attr("PayloadHash"), Type: item.attr("PayloadType")}
			size, err := strconv.ParseInt(item.attr("PayloadSize"), 10, 64)
			if err != nil || size < 0 || payload.Hash == "" {
				return fmt.Errorf("%w: CompDB payload identity", ErrMalformedMetadata)
			}
			payload.Size = size
			// PayloadHash is deliberately opaque. The observed base64 width and
			// upstream consumer variable names do not establish an algorithm.
			pack.Payloads = append(pack.Payloads, payload)
		}
		comp.Packages = append(comp.Packages, pack)
	}
	inv.Compositions = append(inv.Compositions, comp)
	return nil
}

func (inv *Inventory) bindPayload(binding PayloadBinding, known map[model.PayloadIdentity]bool) error {
	if binding.PackageID == "" || binding.PayloadHash == "" || !validReference(binding.Resource, known) || inv.validateEvidence(binding.Evidence) != nil {
		return ErrInvalidEvidence
	}
	found := false
	for ci := range inv.Compositions {
		comp := &inv.Compositions[ci]
		if comp.Evidence.Document != binding.Evidence.Document {
			continue
		}
		for pi := range comp.Packages {
			pack := &comp.Packages[pi]
			if pack.ID != binding.PackageID {
				continue
			}
			for ii := range pack.Payloads {
				item := &pack.Payloads[ii]
				if item.Hash != binding.PayloadHash {
					continue
				}
				if binding.Resource.Member == "" && item.Size != binding.Resource.Payload.Size {
					return ErrInvalidEvidence
				}
				if item.Resource != nil && *item.Resource != binding.Resource {
					return ErrConflictingMetadata
				}
				ref := binding.Resource
				item.Resource = &ref
				claim := binding
				item.Binding = &claim
				found = true
			}
		}
	}
	if !found {
		return fmt.Errorf("%w: CompDB package/raw-hash binding mismatch", ErrInvalidEvidence)
	}
	return nil
}

func (inv *Inventory) compositionGaps() {
	features := make(map[string]bool)
	packages := make(map[string]bool)
	for _, comp := range inv.Compositions {
		for _, feature := range comp.Features {
			features[feature.ID] = true
		}
		for _, pack := range comp.Packages {
			packages[pack.ID] = true
		}
	}
	for ci := range inv.Compositions {
		comp := &inv.Compositions[ci]
		for _, feature := range comp.Features {
			for _, dependency := range feature.Dependencies {
				if !features[dependency] {
					inv.gap("feature-dependency-unresolved", feature.ID+" -> "+dependency, &comp.Evidence.Document)
				}
			}
			for _, pack := range feature.Packages {
				if !packages[pack.ID] {
					inv.gap("package-reference-unresolved", feature.ID+" -> "+pack.ID, &comp.Evidence.Document)
				}
			}
		}
		for _, pack := range comp.Packages {
			if len(pack.Payloads) == 0 {
				inv.gap("package-payload-unresolved", pack.ID, &comp.Evidence.Document)
			}
			for _, item := range pack.Payloads {
				if item.Resource == nil {
					inv.gap("payload-resource-unresolved", pack.ID+": opaque hash "+item.Hash, &comp.Evidence.Document)
				}
			}
		}
	}
}
