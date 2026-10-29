//go:build windows

package source

import (
	"context"
	"errors"
	"testing"
	"uupbuilder/internal/download"
	"uupbuilder/internal/model"
)

type manifestMetadataFetcher struct{ fixtureFetcher }

func (f manifestMetadataFetcher) FetchOne(context.Context, model.Payload, download.Locator, model.Emit) (download.CachedFile, error) {
	return download.CachedFile{}, errors.New("FetchOne cannot refresh expired metadata links")
}
func (f manifestMetadataFetcher) Fetch(ctx context.Context, m model.PayloadManifest, _ model.Locators, _ model.Emit) (download.Materialized, error) {
	if m.Validate() != nil || len(m.Payloads) != 1 || len(m.Queries) != 1 || len(m.Queries[0].Projection) != 1 || m.Queries[0].Projection[0] != m.Payloads[0] {
		return nil, errors.New("metadata refresh received broadened/unbound source")
	}
	p := m.Payloads[0]
	return download.Materialized{p.Identity: {Identity: p.Identity, Path: f.paths[p.Identity], SHA256: p.Identity.Digest.Value}}, ctx.Err()
}

func TestMetadataMaterializationUsesExactProjectedFetch(t *testing.T) {
	r, _ := configuredResolver(t)
	r.Fetcher = manifestMetadataFetcher{r.Fetcher.(fixtureFetcher)}
	s, settings := selectionAndSettings(t)
	got, err := r.Resolve(context.Background(), s, settings)
	if err != nil || len(got.Inventory.Images) != 1 {
		t.Fatalf("metadata cannot use manifest-aware expiry refresh: images=%d %v", len(got.Inventory.Images), err)
	}
}
