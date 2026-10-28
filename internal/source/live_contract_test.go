//go:build windows && liveapi

package source

import (
	"context"
	"errors"
	"testing"
	"time"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
)

// This is real API contract evidence only: no native semantic producer or image
// conversion is exercised, and signed URLs are never printed or persisted.
func TestLiveAppSetsAndLinkRefresh(t *testing.T) {
	for _, tc := range []struct {
		name, search, id string
		arch             model.Architecture
	}{
		{"legacy-arm64", "22000.1 arm64", "a1b78728-530f-443f-b672-d742e7c14bcb", "arm64"},
		{"current-amd64", "26300.9807 amd64", "", "amd64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			metadataClient := catalog.New(nil, "")
			metadataClient.MetadataOnly = true
			builds, err := metadataClient.Search(ctx, tc.search)
			if err != nil {
				t.Fatalf("live catalog: %v", err)
			}
			var chosen catalog.Build
			for _, b := range builds {
				if b.Architecture == tc.arch && (tc.id == "" || b.UpdateID == tc.id) {
					chosen = b
					break
				}
			}
			if chosen.UpdateID == "" {
				t.Fatal("research source no longer available in the real catalog; contract unverified")
			}
			t.Logf("research update_id=%s build=%s arch=%s language=en-us", chosen.UpdateID, chosen.Build, chosen.Architecture)
			editions, err := metadataClient.Editions(ctx, chosen.UpdateID, "en-us")
			if err != nil {
				t.Fatalf("live editions: %v", err)
			}
			base, app := "", ""
			for _, e := range editions {
				if e.ID == "PROFESSIONAL" {
					base = e.ID
				}
				if e.ID == "APP" {
					app = e.ID
				}
			}
			if app == "" {
				for _, e := range editions {
					if e.ID == "APP_MOMENT" {
						app = e.ID
					}
				}
			}
			if base == "" {
				t.Fatal("research source does not advertise PROFESSIONAL; contract unverified")
			}
			selectors := []string{base}
			if app != "" {
				selectors = append(selectors, app)
			} else {
				t.Log("upstream-app-combination=not-advertised; no app families or legacy customization inferred")
			}
			var sets []catalog.FileSet
			var queries []model.SourceQuery
			for _, selector := range selectors {
				set, err := metadataClient.Files(ctx, chosen.UpdateID, "en-us", selector)
				if err != nil {
					t.Fatalf("live noLinks selector=%s: %v", selector, err)
				}
				if len(set.Locators) != 0 {
					t.Fatal("metadata-only request unexpectedly returned runtime locators")
				}
				sets = append(sets, set)
				queries = append(queries, model.SourceQuery{UpdateID: chosen.UpdateID, Language: "en-us", Edition: selector})
				t.Logf("selector=%s metadata_payloads=%d", selector, len(set.Payloads))
			}
			frozen, _, err := Union(sets[0].Source, sets, queries...)
			if err != nil {
				t.Fatalf("live frozen union: %v", err)
			}
			r := &Resolver{Catalog: catalog.New(nil, "")}
			locators, err := r.RefreshLinks(ctx, frozen)
			if errors.Is(err, ErrPayloadUnavailable) {
				t.Fatalf("upstream-online-material=unavailable; metadata success does not prove link availability: %v", err)
			}
			if err != nil {
				t.Fatalf("live link refresh: %v", err)
			}
			t.Logf("UTC=%s origin=%s update_id=%s build=%s arch=%s language=en-us frozen_queries=%d payloads=%d refreshed_locators=%d manifest_sha256=%s; API evidence only; native metadata discovery and conversion unverified", time.Now().UTC().Format(time.RFC3339), catalog.DefaultBaseURL, chosen.UpdateID, chosen.Build, chosen.Architecture, len(frozen.Queries), len(frozen.Payloads), len(locators), frozen.Digest)
		})
	}
}
