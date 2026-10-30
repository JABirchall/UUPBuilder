package source

import (
	"fmt"
	"strconv"
	"strings"

	"uupbuilder/internal/metadata"
)

// Parent alternatives and their comparison semantics remain bound to the
// original CBS document. A parent edition is an OS baseline requirement, not
// an exact Package_for_RollupFix dependency.
type mediaCBSParent struct {
	Identities                                            []metadata.PackageIdentity
	BuildCompare, RevisionCompare, Integrate, Disposition string
	Evidence                                              metadata.Evidence
}

type mediaCBSParentXML struct {
	Identities      []mediaCBSIdentity `xml:"urn:schemas-microsoft-com:asm.v3 assemblyIdentity"`
	BuildCompare    string             `xml:"buildCompare,attr"`
	RevisionCompare string             `xml:"revisionCompare,attr"`
	Integrate       string             `xml:"integrate,attr"`
	Disposition     string             `xml:"disposition,attr"`
}

func mediaCBSParentContext(update string, pack metadata.Package, group mediaCBSParent) string {
	var parents []string
	for _, id := range group.Identities {
		parents = append(parents, fmt.Sprintf("%s/%s/%s/%s/%s", id.Name, id.Version, id.Architecture, id.Language, id.PublicKeyToken))
	}
	return fmt.Sprintf("update %s package %s document %s selector %s buildCompare=%q revisionCompare=%q integrate=%q disposition=%q parents [%s]", update, pack.Identity.Name, pack.Evidence.Document.Resource.Member, group.Evidence.Selector, group.BuildCompare, group.RevisionCompare, group.Integrate, group.Disposition, strings.Join(parents, ", "))
}

func mediaCBSParentGroups(inv *metadata.Inventory) (map[metadata.DocumentReference][]mediaCBSParent, error) {
	groups := map[metadata.DocumentReference][]mediaCBSParent{}
	for _, doc := range inv.Documents {
		if doc.Format != metadata.FormatCBSXML {
			continue
		}
		text, err := decodeMediaText(string(doc.Original))
		if err != nil {
			return nil, err
		}
		var parsed struct {
			Parents []mediaCBSParentXML `xml:"urn:schemas-microsoft-com:asm.v3 parent"`
			Package struct {
				Parents []mediaCBSParentXML `xml:"urn:schemas-microsoft-com:asm.v3 parent"`
			} `xml:"urn:schemas-microsoft-com:asm.v3 package"`
		}
		if err := mediaXMLDecoder([]byte(text)).Decode(&parsed); err != nil {
			return nil, err
		}
		for _, location := range []struct {
			parents  []mediaCBSParentXML
			selector string
		}{{parsed.Parents, "/assembly/parent"}, {parsed.Package.Parents, "/assembly/package/parent"}} {
			for i, parent := range location.parents {
				group := mediaCBSParent{BuildCompare: parent.BuildCompare, RevisionCompare: parent.RevisionCompare, Integrate: parent.Integrate, Disposition: parent.Disposition, Evidence: metadata.Evidence{Source: inv.Source, Document: doc.Reference, Selector: fmt.Sprintf("%s[%d]", location.selector, i+1)}}
				for _, id := range parent.Identities {
					group.Identities = append(group.Identities, id.identity())
				}
				groups[doc.Reference] = append(groups[doc.Reference], group)
			}
		}
	}
	return groups, nil
}

type mediaCBSVersion [4]uint32

func mediaParseCBSVersion(raw string) (mediaCBSVersion, error) {
	var version mediaCBSVersion
	parts := strings.Split(raw, ".")
	if len(parts) != len(version) {
		return version, fmt.Errorf("%w: incomplete CBS/OS baseline version %q", ErrImplementationGap, raw)
	}
	for i, part := range parts {
		if part == "" || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return version, fmt.Errorf("%w: invalid CBS/OS baseline version %q", ErrImplementationGap, raw)
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return version, fmt.Errorf("%w: invalid CBS/OS baseline version %q", ErrImplementationGap, raw)
		}
		version[i] = uint32(n)
	}
	return version, nil
}

func mediaSameCBSFamily(a, b metadata.PackageIdentity) bool {
	neutral := func(s string) string {
		if strings.EqualFold(s, "neutral") {
			return ""
		}
		return strings.ToLower(s)
	}
	return strings.EqualFold(a.Name, b.Name) && a.Architecture == b.Architecture && strings.EqualFold(a.PublicKeyToken, b.PublicKeyToken) && neutral(a.Language) == neutral(b.Language)
}

func mediaCheckpointEditionScope(inv *metadata.Inventory, update metadata.Update, edition string, groups map[metadata.DocumentReference][]mediaCBSParent) bool {
	found := false
	for _, pack := range inv.Packages {
		if !strings.EqualFold(pack.Identity.Name, "Package_for_RollupFix") {
			continue
		}
		matches := false
		for _, id := range update.Packages {
			matches = matches || id == pack.Identity
		}
		if !matches {
			continue
		}
		for _, group := range groups[pack.Evidence.Document] {
			hasEditions, allows := false, false
			for _, parent := range group.Identities {
				if strings.HasPrefix(parent.Name, "Microsoft-Windows-") && strings.HasSuffix(parent.Name, "Edition") {
					hasEditions = true
					allows = allows || strings.EqualFold(parent.Name, "Microsoft-Windows-"+edition+"Edition")
				}
			}
			if hasEditions && !allows {
				return false
			}
			found = found || hasEditions
		}
	}
	return found
}

// RollupFix's version schema is <OS build>.<OS revision>.<package revision>.
// It supplies the edition baseline named by a later GE parent. This rule uses
// inspected identities and image versions; neither KBs nor build pins qualify
// a provider. The predecessor's own parent groups are checked by the caller.
func bindMediaCheckpointBaseline(inv *metadata.Inventory, index int, pack metadata.Package, group mediaCBSParent, groups map[metadata.DocumentReference][]mediaCBSParent, images []metadata.Image) error {
	if !strings.EqualFold(pack.Identity.Name, "Package_for_RollupFix") || group.Evidence.Document.SHA256 == "" {
		return nil
	}
	if group.BuildCompare != "" && group.BuildCompare != "EQ" || group.RevisionCompare != "GE" || group.Integrate != "standalone" || group.Disposition != "detect" {
		return fmt.Errorf("%w: unsupported RollupFix parent build/revision/integration comparison (%s)", ErrImplementationGap, group.Evidence.Selector)
	}
	target, err := mediaParseCBSVersion(pack.Identity.Version)
	if err != nil {
		return err
	}
	for _, image := range images {
		if image.Edition == "" || image.Architecture != pack.Identity.Architecture || image.InstallationType != "Client" && image.InstallationType != "Server" && image.InstallationType != "Server Core" {
			continue
		}
		var alternatives []metadata.PackageIdentity
		for _, parent := range group.Identities {
			if strings.EqualFold(parent.Name, "Microsoft-Windows-"+image.Edition+"Edition") {
				alternatives = append(alternatives, parent)
			}
		}
		if len(alternatives) == 0 {
			continue
		}
		base, err := mediaParseCBSVersion(image.Build)
		if err != nil {
			return err
		}
		var predecessor string
		var bestRevision uint32
		satisfied, ambiguous := false, false
		for _, parent := range alternatives {
			want, err := mediaParseCBSVersion(parent.Version)
			if err != nil {
				return err
			}
			if parent.Architecture != pack.Identity.Architecture || !strings.EqualFold(parent.PublicKeyToken, pack.Identity.PublicKeyToken) || !strings.EqualFold(parent.Language, pack.Identity.Language) || parent.PublicKeyToken == "" || base[0] != want[0] || base[1] != want[1] || base[2] != want[2] || target[0] != want[2] || target[1] < want[3] {
				return fmt.Errorf("%w: incompatible RollupFix edition baseline %s %s", ErrImplementationGap, parent.Name, parent.Version)
			}
			if base[3] >= want[3] {
				satisfied = true
				break
			}
			for j, prior := range inv.Updates {
				if j == index || prior.Kind != metadata.UpdateCumulative && prior.Kind != metadata.UpdateCheckpoint || !mediaCheckpointEditionScope(inv, prior, image.Edition, groups) {
					continue
				}
				for _, identity := range prior.Packages {
					if !mediaSameCBSFamily(identity, pack.Identity) {
						continue
					}
					provided, err := mediaParseCBSVersion(identity.Version)
					if err != nil {
						return err
					}
					if provided[0] != want[2] || provided[1] < want[3] || provided[1] >= target[1] {
						continue
					}
					if predecessor == "" || provided[1] < bestRevision {
						predecessor, bestRevision, ambiguous = prior.ID, provided[1], false
					} else if provided[1] == bestRevision && prior.ID != predecessor {
						ambiguous = true
					}
				}
			}
		}
		if satisfied {
			continue
		}
		if predecessor == "" || ambiguous {
			return fmt.Errorf("%w: required RollupFix baseline for %s has no unique inspected checkpoint provider (%s)", ErrImplementationGap, image.Edition, group.Evidence.Selector)
		}
		update := &inv.Updates[index]
		if !slicesContainsFold(update.Predecessors, predecessor) {
			update.Predecessors = append(update.Predecessors, predecessor)
		}
	}
	return nil
}
