package source

import (
	"fmt"
	"strings"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
)

// Union deduplicates only identical full package identities at the same Windows
// destination. Equal content with different original provenance remains distinct.
// Missing locators are valid for a metadata-only manifest.
func Union(source model.SourceIdentity, sets []catalog.FileSet, queries ...model.SourceQuery) (model.PayloadManifest, model.Locators, error) {
	if source.Validate() != nil {
		return model.PayloadManifest{}, nil, ErrInvalidInput
	}
	for _, q := range queries {
		if q.Validate() != nil || q.UpdateID != source.UpdateID || q.Language != source.Language {
			return model.PayloadManifest{}, nil, ErrInvalidInput
		}
		if len(q.Projection) > 0 && len(queries) != len(sets) {
			return model.PayloadManifest{}, nil, ErrInvalidInput
		}
	}
	byIdentity := make(map[model.PayloadIdentity]int)
	byDestination := make(map[string]model.PayloadIdentity)
	var payloads []model.Payload
	locators := make(model.Locators)
	for index, set := range sets {
		if set.Source != source {
			return model.PayloadManifest{}, nil, ErrInputIdentityChanged
		}
		// Validate the complete producer response before applying any projection.
		if _, err := model.NewPayloadManifest(source, set.Payloads); err != nil {
			return model.PayloadManifest{}, nil, ErrConflictingDestinations
		}
		full := make(map[model.PayloadIdentity]bool)
		for _, p := range set.Payloads {
			full[p.Identity] = true
		}
		for id, loc := range set.Locators {
			if !full[id] || !validLocator(loc) {
				return model.PayloadManifest{}, nil, ErrInvalidInput
			}
		}
		if index < len(queries) && len(queries[index].Projection) > 0 {
			if len(queries) != len(sets) {
				return model.PayloadManifest{}, nil, ErrInvalidInput
			}
			projected := queries[index].Projection
			selected := make(model.Locators)
			for _, want := range projected {
				found := false
				for _, actual := range set.Payloads {
					if actual == want {
						found = true
						break
					}
					if strings.EqualFold(actual.Destination, want.Destination) || actual.Identity == want.Identity {
						return model.PayloadManifest{}, nil, ErrInputIdentityChanged
					}
				}
				if !found {
					return model.PayloadManifest{}, nil, ErrPayloadUnavailable
				}
				if loc, ok := set.Locators[want.Identity]; ok {
					selected[want.Identity] = loc
				}
			}
			set.Payloads, set.Locators = projected, selected
		}
		members := make(map[model.PayloadIdentity]bool)
		for _, p := range set.Payloads {
			if p.Validate() != nil {
				return model.PayloadManifest{}, nil, ErrInvalidInput
			}
			members[p.Identity] = true
			key := strings.ToLower(p.Destination)
			if other, ok := byDestination[key]; ok && other != p.Identity {
				return model.PayloadManifest{}, nil, ErrConflictingDestinations
			}
			if index, ok := byIdentity[p.Identity]; ok {
				if !strings.EqualFold(payloads[index].Destination, p.Destination) {
					return model.PayloadManifest{}, nil, ErrConflictingDestinations
				}
				if p.Destination < payloads[index].Destination {
					payloads[index].Destination = p.Destination
				}
			} else {
				byIdentity[p.Identity] = len(payloads)
				payloads = append(payloads, p)
			}
			byDestination[key] = p.Identity
		}
		for id, loc := range set.Locators {
			if !members[id] || !validLocator(loc) {
				return model.PayloadManifest{}, nil, ErrInvalidInput
			}
			// A stable tie-break makes a union independent of query iteration order.
			old, ok := locators[id]
			if !ok || loc.ExpiresAt.After(old.ExpiresAt) || (loc.ExpiresAt.Equal(old.ExpiresAt) && loc.URL < old.URL) {
				locators[id] = loc
			}
		}
	}
	if len(payloads) == 0 {
		return model.PayloadManifest{}, nil, ErrPayloadUnavailable
	}
	manifest, err := model.NewPayloadManifest(source, payloads, queries...)
	if err != nil {
		return model.PayloadManifest{}, nil, fmt.Errorf("%w: invalid Windows destination union", ErrConflictingDestinations)
	}
	return manifest, locators, nil
}

func DigestManifest(manifest model.PayloadManifest) (string, error) {
	if err := manifest.Validate(); err != nil {
		return "", fmt.Errorf("%w: frozen manifest does not validate", ErrInvalidInput)
	}
	return manifest.Digest, nil
}
