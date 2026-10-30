package source

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"uupbuilder/internal/metadata"
)

// SafeOS is a WinRE update, not an OS-edition package. Both the recognized CBS
// installation family and its exclusive original Rejuv parents establish scope.
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
		for _, parent := range group.Identities {
			if !strings.EqualFold(parent.Name, "WinPE-Rejuv-Package") || parent.Architecture != pack.Identity.Architecture || !strings.EqualFold(parent.PublicKeyToken, pack.Identity.PublicKeyToken) || parent.PublicKeyToken == "" || neutral(parent.Language) != neutral(pack.Identity.Language) {
				return "", fmt.Errorf("%w: SafeOS CBS scope has ambiguous parent identity %s", ErrImplementationGap, parent.Name)
			}
			if _, err = mediaParseCBSVersion(parent.Version); err != nil {
				return "", err
			}
		}
	}
	return metadata.RoleWinRE, nil
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
