//go:build liveapi

package catalog

import (
	"context"
	"testing"
	"time"

	"uupbuilder/internal/model"
)

// TestLiveDiscoveryContract makes four real requests to the official API. It
// fails on unavailable/invalid service responses; no skip/offline path counts as
// integration evidence. noLinks metadata does not prove online payload availability.
func TestLiveDiscoveryContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := New(nil, "")
	c.MetadataOnly = true
	builds, err := c.Search(ctx, "22000.1 arm64")
	if err != nil {
		t.Fatalf("live catalog: %v", err)
	}
	var chosen Build
	for _, build := range builds {
		if build.UpdateID == "a1b78728-530f-443f-b672-d742e7c14bcb" {
			chosen = build
			break
		}
	}
	if chosen.UpdateID == "" {
		t.Fatal("live catalog no longer contains the expected research source; contract unverified")
	}
	langs, err := c.Languages(ctx, chosen.UpdateID)
	if err != nil {
		t.Fatalf("live languages: %v", err)
	}
	language := ""
	for _, lang := range langs {
		if lang.ID == "en-us" {
			language = lang.ID
		}
	}
	if language == "" {
		t.Fatal("live en-us language missing")
	}
	editions, err := c.Editions(ctx, chosen.UpdateID, language)
	if err != nil {
		t.Fatalf("live editions: %v", err)
	}
	edition := ""
	for _, candidate := range editions {
		if candidate.ID == "PROFESSIONAL" {
			edition = candidate.ID
		}
	}
	if edition == "" {
		t.Fatal("live PROFESSIONAL edition missing")
	}
	set, err := c.Files(ctx, chosen.UpdateID, language, edition)
	if err != nil {
		t.Fatalf("live file metadata: %v", err)
	}
	if set.Source.UpdateID != chosen.UpdateID || set.Source.Architecture != chosen.Architecture || len(set.Payloads) == 0 || len(set.Locators) != 0 {
		t.Fatal("live metadata identity/locator contract changed")
	}
	manifest, err := model.NewPayloadManifest(set.Source, set.Payloads)
	if err != nil {
		t.Fatalf("live manifest ingestion: %v", err)
	}
	t.Logf("UTC=%s origin=%s query=%q update_id=%s build=%s arch=%s language=%s edition=%s builds=%d languages=%d editions=%d metadata_payloads=%d manifest_sha256=%s noLinks=1; resolver filenames only; original composition provenance and online availability unverified",
		time.Now().UTC().Format(time.RFC3339), DefaultBaseURL, "22000.1 arm64", chosen.UpdateID, chosen.Build, chosen.Architecture, language, edition, len(builds), len(langs), len(editions), len(set.Payloads), manifest.Digest)
}
