package source

import (
	"context"
	"slices"
	"strings"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// Refresh is a pure identity check: it never performs discovery, modifies a
// manifest or reads a clock. The downloader validates runtime expiry on use.
func Refresh(ctx context.Context, frozen model.PayloadManifest, fresh Resolution) (model.Locators, error) {
	if ctx == nil {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if frozen.Validate() != nil {
		return nil, ErrInvalidInput
	}
	if fresh.Classification == metadata.ClassificationSourceUnavailable {
		return nil, ErrPayloadUnavailable
	}
	if fresh.Manifest.Validate() != nil {
		return nil, ErrInputIdentityChanged
	}
	a, _ := model.NewPayloadManifest(frozen.Source, frozen.Payloads, frozen.Queries...)
	b, _ := model.NewPayloadManifest(fresh.Manifest.Source, fresh.Manifest.Payloads, fresh.Manifest.Queries...)
	if a.Source != b.Source || !slices.Equal(a.Queries, b.Queries) {
		return nil, ErrInputIdentityChanged
	}
	if a.Digest != b.Digest {
		byPath := make(map[string]model.PayloadIdentity)
		byID := make(map[model.PayloadIdentity]bool)
		for _, p := range b.Payloads {
			byPath[strings.ToLower(p.Destination)] = p.Identity
			byID[p.Identity] = true
		}
		missing := false
		for _, p := range a.Payloads {
			other, ok := byPath[strings.ToLower(p.Destination)]
			if ok && other != p.Identity || !ok && byID[p.Identity] {
				return nil, ErrInputIdentityChanged
			}
			missing = missing || !ok
		}
		if missing && len(b.Payloads) < len(a.Payloads) {
			return nil, ErrPayloadUnavailable
		}
		return nil, ErrInputIdentityChanged
	}
	locators := make(model.Locators)
	for _, p := range a.Payloads {
		loc, ok := fresh.Locators[p.Identity]
		if !ok || !validLocator(loc) {
			return nil, ErrPayloadUnavailable
		}
		locators[p.Identity] = loc
	}
	if len(locators) != len(fresh.Locators) {
		return nil, ErrInputIdentityChanged
	}
	return locators, nil
}
