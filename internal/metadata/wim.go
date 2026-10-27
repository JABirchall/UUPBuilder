package metadata

import (
	"fmt"
	"strconv"
	"strings"
	"uupbuilder/internal/model"
)

type Image struct {
	Resource                         ResourceReference
	Index                            int
	Name, Description, Flags         string
	Architecture                     model.Architecture
	RawArchitecture                  string
	Edition, InstallationType, Build string
	Languages                        []string
	Evidence                         Evidence
}

func (inv *Inventory) parseWIM(root *xmlNode, doc DocumentReference) error {
	if root.Name.Local != "WIM" || root.Name.Space != "" {
		inv.gap("unsupported-schema", "WIM XML root/namespace", &doc)
		return nil
	}
	seen := make(map[int]bool)
	for _, node := range root.children("IMAGE") {
		if err := singletonChildren(node, "WINDOWS", "NAME", "DESCRIPTION", "FLAGS"); err != nil {
			return err
		}
		index, err := strconv.Atoi(node.attr("INDEX"))
		if err != nil || index <= 0 || seen[index] {
			return fmt.Errorf("%w: invalid/duplicate WIM image index", ErrMalformedMetadata)
		}
		seen[index] = true
		windows := node.child("WINDOWS")
		if err := singletonChildren(windows, "ARCH", "EDITIONID", "INSTALLATIONTYPE", "VERSION", "LANGUAGES"); err != nil {
			return err
		}
		rawArchitecture := windows.child("ARCH").text()
		architecture := model.Architecture(rawArchitecture)
		switch rawArchitecture {
		case "0":
			architecture = "x86"
		case "5":
			architecture = "arm"
		case "9":
			architecture = "amd64"
		case "12":
			architecture = "arm64"
		}
		image := Image{Resource: doc.Resource, Index: index, Name: node.child("NAME").text(), Description: node.child("DESCRIPTION").text(), Flags: node.child("FLAGS").text(), RawArchitecture: rawArchitecture, Architecture: architecture, Edition: windows.child("EDITIONID").text(), InstallationType: windows.child("INSTALLATIONTYPE").text(), Evidence: inv.evidence(doc, fmt.Sprintf("/WIM/IMAGE[@INDEX='%d']/WINDOWS", index))}
		version := windows.child("VERSION")
		if err := singletonChildren(version, "MAJOR", "MINOR", "BUILD", "SPBUILD"); err != nil {
			return err
		}
		parts := []string{version.child("MAJOR").text(), version.child("MINOR").text(), version.child("BUILD").text(), version.child("SPBUILD").text()}
		if parts[0] != "" && parts[1] != "" && parts[2] != "" {
			image.Build = strings.Join(parts[:3], ".")
			if parts[3] != "" {
				image.Build += "." + parts[3]
			}
		}
		for _, language := range windows.child("LANGUAGES").children("LANGUAGE") {
			image.Languages = append(image.Languages, language.text())
		}
		inv.Images = append(inv.Images, image)
		// Edition + client/server installation semantics identify an OS image.
		// WindowsPE, NAME and FLAGS do not distinguish Setup from recovery.
		if image.Edition != "" && (image.InstallationType == "Client" || image.InstallationType == "Server" || image.InstallationType == "Server Core") {
			if err := inv.architecture(image.Architecture); err != nil {
				return err
			}
			if image.Architecture == "" {
				inv.gap("image-architecture-unresolved", "OS image has no architecture", &doc)
			}
			inv.Roles = append(inv.Roles, RoleEvidence{Role: RoleOS, Resource: doc.Resource, ImageIndex: index, Evidence: image.Evidence})
		}
	}
	return nil
}
