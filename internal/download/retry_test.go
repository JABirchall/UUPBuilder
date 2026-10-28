//go:build windows

package download

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"uupbuilder/internal/model"
)

func TestExpiryRefreshIndependentOfRetryPolicy(t *testing.T) {
	var expiredCalls, refreshes atomic.Int32
	expired := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { expiredCalls.Add(1); w.WriteHeader(403) }))
	defer expired.Close()
	fresh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(fixture) }))
	defer fresh.Close()
	opts := testOptions(t)
	opts.Retries = 0
	p := payload(t, fixture, "p.bin")
	opts.Refresh = func(ctx context.Context, frozen model.PayloadManifest) (model.Locators, error) {
		refreshes.Add(1)
		return model.Locators{p.Identity: {URL: fresh.URL}}, nil
	}
	m := manager(t, opts)
	got, err := m.Fetch(context.Background(), manifest(t, p), model.Locators{p.Identity: {URL: expired.URL}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, got[p.Identity], p, fixture)
	if expiredCalls.Load() != 1 || refreshes.Load() != 1 {
		t.Fatalf("expiry requests=%d refreshes=%d", expiredCalls.Load(), refreshes.Load())
	}
}

func TestFetchOneNeverFabricatesRefreshSourceContext(t *testing.T) {
	for _, kind := range []string{"expires-at", "http-expiry"} {
		t.Run(kind, func(t *testing.T) {
			var refreshes, requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(403) }))
			defer srv.Close()
			opts := testOptions(t)
			opts.Refresh = func(context.Context, model.PayloadManifest) (model.Locators, error) {
				refreshes.Add(1)
				return nil, nil
			}
			loc := Locator{URL: srv.URL}
			if kind == "expires-at" {
				loc.ExpiresAt = time.Now().Add(-time.Hour)
			}
			m := manager(t, opts)
			_, err := m.FetchOne(context.Background(), payload(t, fixture, "p.bin"), loc, nil)
			if !errors.Is(err, ErrRefresh) || refreshes.Load() != 0 {
				t.Fatalf("FetchOne fabricated refresh context: %v calls=%d", err, refreshes.Load())
			}
			want := int32(1)
			if kind == "expires-at" {
				want = 0
			}
			if requests.Load() != want {
				t.Fatalf("expired request count=%d want=%d", requests.Load(), want)
			}
		})
	}
}

// A refresh consumer may mutate its borrowed DTO; subsequent refreshes must
// still receive the exact frozen source queries.
func TestRefreshCallbackCannotMutateFrozenQueries(t *testing.T) {
	p := payload(t, fixture, "p.bin")
	base := manifest(t, p)
	frozen, err := model.NewPayloadManifest(base.Source, base.Payloads, model.SourceQuery{UpdateID: base.Source.UpdateID, Language: base.Source.Language, Edition: "CORE"})
	if err != nil {
		t.Fatal(err)
	}
	set := locatorSet{frozen: frozen, locators: make(model.Locators)}
	set.refresh = func(_ context.Context, got model.PayloadManifest) (model.Locators, error) {
		if got.Validate() != nil || got.Queries[0].Edition != "CORE" {
			t.Fatal("callback mutated frozen queries")
		}
		got.Queries[0].Edition = "mutated"
		return model.Locators{p.Identity: {URL: "https://example.invalid/fresh"}}, nil
	}
	for range 2 {
		if _, err := set.get(context.Background(), p.Identity, time.Now(), true); err != nil {
			t.Fatal(err)
		}
	}
	if frozen.Validate() != nil {
		t.Fatal("callback mutated caller queries")
	}
}
