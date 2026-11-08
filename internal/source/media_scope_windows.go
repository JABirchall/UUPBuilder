package source

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"uupbuilder/internal/metadata"
)

// The SafeOS CBS installation family and original Rejuv parents establish WinRE
// scope. Some packages list edition and WinPE alternatives in Rejuv's detection group.
// https://learn.microsoft.com/windows/deployment/update/media-dynamic-update
func mediaUpdateTarget(inv *metadata.Inventory, pack metadata.Package) (metadata.Role, error) {
	if !strings.EqualFold(pack.Identity.Name, "Package_for_SafeOSDU") {
		return metadata.RoleOS, nil
	}
	if pack.Evidence.Source != inv.Source {
		return "", metadata.ErrInvalidEvidence
	}
	bound := false
	for _, doc := range inv.Documents {
		if doc.Reference != pack.Evidence.Document {
			continue
		}
		sum := sha256.Sum256(doc.Original)
		if doc.Format != metadata.FormatCBSXML || hex.EncodeToString(sum[:]) != doc.Reference.SHA256 || doc.Provenance == "" {
			return "", metadata.ErrInvalidEvidence
		}
		bound = true
	}
	if !bound {
		return "", metadata.ErrInvalidEvidence
	}
	groups, err := mediaCBSParentGroups(inv)
	if err != nil {
		return "", err
	}
	parents := groups[pack.Evidence.Document]
	if len(parents) == 0 {
		return "", fmt.Errorf("%w: SafeOS CBS scope has no original parent evidence", ErrImplementationGap)
	}
	neutral := func(language string) string {
		if strings.EqualFold(language, "neutral") {
			return ""
		}
		return strings.ToLower(language)
	}
	for _, group := range parents {
		if len(group.Identities) == 0 {
			return "", fmt.Errorf("%w: SafeOS CBS scope has an empty parent group", ErrImplementationGap)
		}
		hasRejuv := false
		for _, parent := range group.Identities {
			if parent.Architecture != pack.Identity.Architecture || !strings.EqualFold(parent.PublicKeyToken, pack.Identity.PublicKeyToken) || parent.PublicKeyToken == "" || neutral(parent.Language) != neutral(pack.Identity.Language) {
				return "", fmt.Errorf("%w: SafeOS CBS scope has ambiguous parent identity %s", ErrImplementationGap, parent.Name)
			}
			if _, err = mediaParseCBSVersion(parent.Version); err != nil {
				return "", err
			}
			if strings.EqualFold(parent.Name, "WinPE-Rejuv-Package") {
				hasRejuv = true
			} else if !mediaSafeOSDetectionAlternative(group, parent.Name) {
				return "", fmt.Errorf("%w: SafeOS CBS scope has ambiguous parent identity %s", ErrImplementationGap, parent.Name)
			}
		}
		if !hasRejuv {
			return "", fmt.Errorf("%w: SafeOS CBS scope parent group lacks WinPE-Rejuv-Package", ErrImplementationGap)
		}
	}
	return metadata.RoleWinRE, nil
}

func mediaSafeOSDetectionAlternative(group mediaCBSParent, name string) bool {
	if group.Integrate != "separate" || group.Disposition != "detect" {
		return false
	}
	name = strings.ToLower(name)
	return name == "microsoft-windows-winpe-package" ||
		strings.HasPrefix(name, "winpe-") && strings.HasSuffix(name, "-package") ||
		strings.HasPrefix(name, "microsoft-windows-") && strings.HasSuffix(name, "edition")
}

func mediaVerifyWinREUpdate(inv *metadata.Inventory, update metadata.Update) error {
	for _, identity := range update.Packages {
		found := false
		for _, pack := range inv.Packages {
			if pack.Identity != identity {
				continue
			}
			found = true
			target, err := mediaUpdateTarget(inv, pack)
			if err != nil {
				return err
			}
			if target != metadata.RoleWinRE {
				return metadata.ErrInvalidEvidence
			}
		}
		if !found {
			return metadata.ErrInvalidEvidence
		}
	}
	if len(update.Packages) == 0 {
		return metadata.ErrInvalidEvidence
	}
	return nil
}
