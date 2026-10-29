//go:build windows

package source

import (
	"context"
	"errors"
	"testing"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
)

// Selecting a bootstrap CAB must not pull unrelated source editions into the job.
func TestExactProjectionNarrowsDownloadsAndRefreshRejectsChangedSelection(t *testing.T) {
	meta, unrelated := sourcePayload("metadata.cab", "a"), sourcePayload("other.esd", "b")
	q := query("all")
	q.Projection = []model.Payload{meta}
	set := sourceSet(meta, unrelated)
	set.Locators[meta.Identity] = model.Locator{URL: "https://example.invalid/metadata"}
	set.Locators[unrelated.Identity] = model.Locator{URL: "https://example.invalid/unrelated"}
	frozen, locators, err := Union(sourceIdentity(), []catalog.FileSet{set}, q)
	if err != nil || len(frozen.Payloads) != 1 || frozen.Payloads[0] != meta || len(locators) != 1 {
		t.Fatalf("projection broadened: %+v %v", frozen, err)
	}
	q.Projection[0] = unrelated
	if frozen.Queries[0].Projection[0] != meta || frozen.Validate() != nil {
		t.Fatal("caller mutated frozen projection")
	}
	c := &fixtureCatalog{sets: map[string]catalog.FileSet{"all": set}}
	r := &Resolver{Catalog: c}
	got, err := r.RefreshLinks(context.Background(), frozen)
	if err != nil || len(got) != 1 {
		t.Fatalf("exact projected refresh: %v", err)
	}
	changed := meta
	changed.Identity.Provenance.Name = "different-origin"
	c.sets["all"] = sourceSet(changed, unrelated)
	if _, err := r.RefreshLinks(context.Background(), frozen); !errors.Is(err, ErrInputIdentityChanged) {
		t.Fatalf("changed provenance: %v", err)
	}
	c.sets["all"] = sourceSet(unrelated)
	if _, err := r.RefreshLinks(context.Background(), frozen); !errors.Is(err, ErrPayloadUnavailable) {
		t.Fatalf("missing exact member: %v", err)
	}
}
