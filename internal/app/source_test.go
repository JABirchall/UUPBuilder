//go:build windows

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/download"
	"uupbuilder/internal/model"
	"uupbuilder/internal/platform/windows"
	"uupbuilder/internal/source"
)

// The assembly helper must wire real source refresh into the real downloader,
// so an expired URL is replaced and the verified immutable bytes reach cache.
func TestSourceManagerBindsSafeRefreshWithoutImportCycle(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc_rev.7"
	data := []byte("verified source bytes")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	identity := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: digest}, Size: int64(len(data)), Provenance: model.PackageProvenance{Source: "uupdump:get.php:" + id, Name: "payload.bin"}}
	p := model.Payload{Identity: identity, Destination: "payload.bin"}
	frozen, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: id, BuildLabel: "1.2.3.4", Architecture: "arm64", Language: "en-us"}, []model.Payload{p}, model.SourceQuery{UpdateID: id, Language: "en-us", Edition: "CORE"})
	if err != nil {
		t.Fatal(err)
	}
	var origin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/payload" {
			w.Write(data)
			return
		}
		if r.URL.Path != "/get.php" || r.URL.Query().Get("id") != id || r.URL.Query().Get("lang") != "en-us" || r.URL.Query().Get("edition") != "CORE" || r.URL.Query().Get("noLinks") != "0" {
			t.Error("assembly changed the frozen source query")
			http.Error(w, "bad query", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{"build": "1.2.3.4", "arch": "arm64", "files": map[string]any{"payload.bin": map[string]any{"sha256": digest, "size": len(data), "url": origin + "/payload", "expire": 0, "uuid": nil}}}})
	}))
	defer srv.Close()
	origin = srv.URL
	cache, err := windows.CreateWorkspace(t.TempDir(), "cache")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	job, err := windows.CreateWorkspace(t.TempDir(), "job")
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()
	r := &source.Resolver{Catalog: catalog.New(srv.Client(), srv.URL)}
	m, err := NewSourceManager(download.Options{Cache: cache, Job: job, Proxy: model.ProxySettings{Mode: model.ProxyDirect}, Refresh: func(context.Context, model.PayloadManifest) (model.Locators, error) {
		return nil, errors.New("unbound refresh callback")
	}}, r)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	got, err := m.Fetch(context.Background(), frozen, model.Locators{identity: {URL: srv.URL + "/expired", ExpiresAt: time.Now().Add(-time.Hour)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(got[identity].Path)
	if err != nil || string(bytes) != string(data) || got[identity].SHA256 != digest {
		t.Fatalf("assembly did not materialize verified bytes: %v", err)
	}
}

// A real composed manager must make semantic discovery available without a
// caller supplying test callbacks, and retain the exact metadata projection.
func TestSourceManagerBindsProductionDiscovery(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc_rev.7"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/listeditions.php" {
			w.Write([]byte(`{"response":{"editionList":["PROFESSIONAL"]}}`))
			return
		}
		w.Write([]byte(`{"response":{"build":"1.2.3.4","arch":"arm64","files":{"id.aggregatedmetadata.cab":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":16,"expire":0,"url":null},"other.esd":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":16,"expire":0,"url":null}}}}`))
	}))
	defer srv.Close()
	cache, err := windows.CreateWorkspace(t.TempDir(), "metadata-cache")
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	job, err := windows.CreateWorkspace(t.TempDir(), "metadata-download")
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()
	r := &source.Resolver{Catalog: catalog.New(srv.Client(), srv.URL)}
	m, err := NewSourceManager(download.Options{Cache: cache, Job: job, Proxy: model.ProxySettings{Mode: model.ProxyDirect}}, r)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if r.Discover == nil || r.DiscoverApps == nil {
		t.Fatal("production source discovery remains unbound")
	}
	plan, err := r.Discover(context.Background(), model.Selection{UpdateID: id, Architecture: "arm64", Language: "en-us", Editions: []string{"PROFESSIONAL"}})
	if err != nil || len(plan.Inputs) != 1 || len(plan.Sets) != 1 || len(plan.Sets[0].Query.Projection) != 1 {
		t.Fatalf("composed discovery: %+v %v", plan, err)
	}
}
