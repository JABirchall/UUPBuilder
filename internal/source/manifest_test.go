package source

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
)

func sourceIdentity() model.SourceIdentity {
	return model.SourceIdentity{UpdateID: "12345678-1234-1234-1234-123456789abc_rev.7", BuildLabel: "10.0.1.2", Architecture: "arm64", Language: "en-us"}
}

func TestUnionPreservesNeutralAppQueryProvenance(t *testing.T) {
	base := sourceSet(sourcePayload("base.esd", "a"))
	apps := sourceSet(sourcePayload("app.msix", "b"))
	apps.Source.Language = "neutral"
	q := query("APP")
	q.Language = "neutral"
	q.Projection = apps.Payloads
	m, _, err := Union(sourceIdentity(), []catalog.FileSet{base, apps}, query("PROFESSIONAL"), q)
	if err != nil {
		t.Fatal(err)
	}
	if m.Source.Language != "en-us" || m.Queries[1].Language != "neutral" || m.Validate() != nil {
		t.Fatal("lost original source/query language")
	}
	apps.Source.BuildLabel = "other"
	if _, _, err = Union(sourceIdentity(), []catalog.FileSet{base, apps}, query("PROFESSIONAL"), q); err == nil {
		t.Fatal("cross-build app union accepted")
	}
	apps.Source = base.Source
	apps.Source.Language = "neutral"
	q.Edition = "PROFESSIONAL"
	if _, _, err = Union(sourceIdentity(), []catalog.FileSet{base, apps}, query("PROFESSIONAL"), q); err == nil {
		t.Fatal("neutral OS query accepted")
	}
}
func sourcePayload(name, digit string) model.Payload {
	return model.Payload{Identity: model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: strings.Repeat(digit, 64)}, Size: 16, Provenance: model.PackageProvenance{Source: "synthetic-original-package", Name: name}}, Destination: name}
}
func sourceSet(payloads ...model.Payload) catalog.FileSet {
	return catalog.FileSet{Source: sourceIdentity(), Payloads: payloads, Locators: make(model.Locators)}
}
func query(edition string) model.SourceQuery {
	s := sourceIdentity()
	return model.SourceQuery{UpdateID: s.UpdateID, Language: s.Language, Edition: edition}
}
func manifestFor(t *testing.T, payloads ...model.Payload) model.PayloadManifest {
	t.Helper()
	m, err := model.NewPayloadManifest(sourceIdentity(), payloads, query("CORE"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Losing a shared payload's second base query would make restart refresh unsafe.
func TestUnionDeduplicatesSharedBasePayload(t *testing.T) {
	shared, core, pro := sourcePayload("shared.esd", "a"), sourcePayload("core.esd", "b"), sourcePayload("pro.esd", "c")
	m, _, err := Union(sourceIdentity(), []catalog.FileSet{sourceSet(shared, core), sourceSet(pro, shared)}, query("PROFESSIONAL"), query("CORE"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Payloads) != 3 || len(m.Queries) != 2 || m.Queries[0].Edition != "CORE" || m.Queries[1].Edition != "PROFESSIONAL" {
		t.Fatalf("union lost identities or provenance: %+v", m)
	}
	other := shared
	other.Identity.Provenance.Name = "different-original-name"
	other.Destination = "alias.esd"
	m, _, err = Union(sourceIdentity(), []catalog.FileSet{sourceSet(shared, other)}, query("CORE"))
	if err != nil || len(m.Payloads) != 2 {
		t.Fatalf("different original package identities were aliased: %v", err)
	}
}

// Real catalog ingestion must work without a download UUID or runtime locator.
func TestNoLinksManifestIgnoresNullDownloadUUID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("noLinks") != "1" {
			t.Error("expected metadata-only request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response":{"build":"10.0.1.2","arch":"arm64","files":{"shared.esd":{"sha256":"` + strings.Repeat("a", 64) + `","sha1":null,"size":"16","url":null,"uuid":null,"expire":0}}}}`))
	}))
	defer srv.Close()
	c := catalog.New(srv.Client(), srv.URL)
	c.MetadataOnly = true
	set, err := c.Files(context.Background(), sourceIdentity().UpdateID, "en-us", "CORE")
	if err != nil {
		t.Fatal(err)
	}
	m, locs, err := Union(sourceIdentity(), []catalog.FileSet{set}, query("CORE"))
	if err != nil || len(m.Payloads) != 1 || len(locs) != 0 || m.Validate() != nil {
		t.Fatalf("no-links manifest: %v", err)
	}
}

// Runtime URL rotation cannot affect the canonical shared-model digest.
func TestManifestDigestExcludesURLAndExpiry(t *testing.T) {
	p := sourcePayload("a.esd", "a")
	set := sourceSet(p)
	set.Locators[p.Identity] = model.Locator{URL: "https://example.invalid/first?token=one", ExpiresAt: time.Unix(100, 0)}
	a, _, err := Union(sourceIdentity(), []catalog.FileSet{set}, query("CORE"))
	if err != nil {
		t.Fatal(err)
	}
	set.Locators[p.Identity] = model.Locator{URL: "https://example.invalid/second?token=two", ExpiresAt: time.Unix(200, 0)}
	b, _, err := Union(sourceIdentity(), []catalog.FileSet{set}, query("CORE"))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := DigestManifest(b)
	if err != nil || digest != a.Digest || digest != b.Digest {
		t.Fatalf("runtime locator changed manifest digest: %v", err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "token=") {
		t.Fatal("signed URL leaked")
	}
	b.Payloads[0].Identity.Size++
	if _, err := DigestManifest(b); err == nil {
		t.Fatal("accepted mutated frozen manifest")
	}
}

// Refresh must reject every identity-bearing change, including a query revision.
func TestRefreshRejectsChangedDigestSizePackageEncryptionOrRevision(t *testing.T) {
	p := sourcePayload("a.esd", "a")
	frozen := manifestFor(t, p)
	for _, field := range []string{"digest", "size", "package", "encryption", "revision", "destination", "query"} {
		t.Run(field, func(t *testing.T) {
			changed := p
			s := sourceIdentity()
			q := query("CORE")
			switch field {
			case "digest":
				changed.Identity.Digest.Value = strings.Repeat("b", 64)
			case "size":
				changed.Identity.Size++
			case "package":
				changed.Identity.Provenance.Name = "other"
			case "encryption":
				changed.Identity.Encryption = model.EncryptionIdentity{Method: "synthetic-aes", Fingerprint: strings.Repeat("c", 64)}
			case "revision":
				s.UpdateID = strings.Replace(s.UpdateID, ".7", ".8", 1)
				q.UpdateID = s.UpdateID
			case "destination":
				changed.Destination = "b.esd"
			case "query":
				q.Edition = "PROFESSIONAL"
			}
			fresh, err := model.NewPayloadManifest(s, []model.Payload{changed}, q)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Refresh(context.Background(), frozen, Resolution{Manifest: fresh, Locators: model.Locators{changed.Identity: {URL: "https://example.invalid/fresh"}}})
			if !errors.Is(err, ErrInputIdentityChanged) {
				t.Fatalf("accepted changed %s: %v", field, err)
			}
		})
	}
	loc := model.Locator{URL: "https://example.invalid/fresh"}
	fresh := Resolution{Manifest: frozen, Locators: model.Locators{p.Identity: loc}}
	got, err := Refresh(context.Background(), frozen, fresh)
	if err != nil {
		t.Fatal(err)
	}
	got[p.Identity] = model.Locator{}
	if !reflect.DeepEqual(fresh.Locators[p.Identity], loc) {
		t.Fatal("refresh aliases caller locator map")
	}
}

func TestRefreshMissingPayloadOrLocatorIsUnavailable(t *testing.T) {
	p, q := sourcePayload("a.esd", "a"), sourcePayload("b.esd", "b")
	frozen := manifestFor(t, p, q)
	for _, fresh := range []Resolution{{Manifest: manifestFor(t, p), Locators: model.Locators{p.Identity: {URL: "https://example.invalid/a"}}}, {Manifest: frozen, Locators: model.Locators{p.Identity: {URL: "https://example.invalid/a"}}}} {
		if _, err := Refresh(context.Background(), frozen, fresh); !errors.Is(err, ErrPayloadUnavailable) {
			t.Fatalf("missing payload accepted: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Refresh(ctx, frozen, Resolution{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestConflictingDestinationsRejected(t *testing.T) {
	a, b := sourcePayload("folder/a.esd", "a"), sourcePayload("folder/A.esd", "b")
	for _, payloads := range [][]model.Payload{{a, b}, {sourcePayload("folder", "b"), a}} {
		if _, _, err := Union(sourceIdentity(), []catalog.FileSet{sourceSet(payloads...)}, query("CORE")); !errors.Is(err, ErrConflictingDestinations) {
			t.Fatalf("conflict accepted: %v", err)
		}
	}
}
