package app

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"uupbuilder/internal/config"
	"uupbuilder/internal/download"
	"uupbuilder/internal/jobs"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	"uupbuilder/internal/source"
	"uupbuilder/internal/tui"
)

const preflightSourceID = "8f550c54-da87-45d3-89e3-0c03a6f16ae8"

// These are real, bounded container bytes. No source/parser/materializer ports
// are replaced: removing default composition must lose the semantic result.
func preflightWIM(architecture string) []byte {
	xml := []byte(`<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>` + architecture + `</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`)
	b := make([]byte, 256+len(xml))
	copy(b, "MSWIM\x00\x00\x00")
	binary.LittleEndian.PutUint32(b[8:], 208)
	binary.LittleEndian.PutUint32(b[12:], 0xe00)
	binary.LittleEndian.PutUint16(b[40:], 1)
	binary.LittleEndian.PutUint16(b[42:], 1)
	binary.LittleEndian.PutUint64(b[72:], uint64(len(xml))|2<<56)
	binary.LittleEndian.PutUint64(b[80:], 256)
	binary.LittleEndian.PutUint64(b[88:], uint64(len(xml)))
	copy(b[256:], xml)
	return b
}

func preflightCAB(name string, body []byte) []byte {
	end := 61 + len(name)
	b := make([]byte, end+8+len(body))
	copy(b, "MSCF")
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[16:], 44)
	b[24], b[25] = 3, 1
	binary.LittleEndian.PutUint16(b[26:], 1)
	binary.LittleEndian.PutUint16(b[28:], 1)
	binary.LittleEndian.PutUint32(b[36:], uint32(end))
	binary.LittleEndian.PutUint16(b[40:], 1)
	binary.LittleEndian.PutUint32(b[44:], uint32(len(body)))
	copy(b[60:], name)
	binary.LittleEndian.PutUint16(b[end+4:], uint16(len(body)))
	binary.LittleEndian.PutUint16(b[end+6:], uint16(len(body)))
	copy(b[end+8:], body)
	return b
}

func preflightConfig(t *testing.T, endpoint string) config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Catalog.Endpoint = endpoint
	cfg.Image.UpdateID = preflightSourceID
	cfg.Image.Editions = []string{"Professional"}
	cfg.Storage.Workspace = t.TempDir()
	cfg.Storage.Cache = t.TempDir()
	cfg.Output.Directory = t.TempDir()
	cfg.Downloads.Proxy.Mode = model.ProxyDirect
	return cfg
}

func defaultBuild(t *testing.T, cfg config.Config) tui.BuildService {
	t.Helper()
	opts := Options{Config: cfg}
	closeBuild := composeInteractiveBuild(&opts)
	t.Cleanup(func() {
		if err := closeBuild(); err != nil {
			t.Errorf("close preflight: %v", err)
		}
	})
	return opts.Dependencies.Builder
}

func preflightResponse(w http.ResponseWriter, origin, name, digest, architecture string, size int, expired bool) {
	expiry := int64(0)
	if expired {
		expiry = 1
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{
		"build": "28000.3365", "arch": architecture,
		"files": map[string]any{
			name:                   map[string]any{"sha256": digest, "size": size, "expire": expiry, "url": origin + "/semantic"},
			"large-unselected.esd": map[string]any{"sha256": strings.Repeat("a", 64), "size": 5368709120, "expire": 0, "url": origin + "/forbidden"},
		},
	}})
}

func TestDefaultBuildInspectsVerifiedSemanticBytes(t *testing.T) {
	inner := preflightCAB("target.xml", []byte(`<CompDB xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate" SchemaVersion="1.2" BuildArch="amd64" Type="Build" BuildID="fixture"/>`))
	for _, tc := range []struct {
		name, payload, architecture      string
		body                             []byte
		corrupt, expired, changed, proxy bool
		failures                         int32
		want                             error
	}{
		{name: "WIM-and-configured-five-retries", payload: "professional_en-us.esd", architecture: "amd64", body: preflightWIM("9"), failures: 5, want: planner.ErrBlocked},
		{name: "nested-CAB-through-explicit-proxy", payload: "id.aggregatedmetadata.cab", architecture: "amd64", body: preflightCAB("DesktopTargetCompDB_professional_en-us.xml.cab", inner), proxy: true, want: planner.ErrBlocked},
		{name: "foreign-semantic-architecture", payload: "professional_en-us.esd", architecture: "amd64", body: preflightWIM("12"), want: metadata.ErrConflictingMetadata},
		{name: "publisher-digest-mismatch", payload: "professional_en-us.esd", architecture: "amd64", body: preflightWIM("9"), corrupt: true, want: download.ErrIntegrity},
		{name: "foreign-catalogue-target", payload: "professional_en-us.esd", architecture: "arm64", body: preflightWIM("9"), want: source.ErrInputIdentityChanged},
		{name: "expired-link-exact-projection", payload: "professional_en-us.esd", architecture: "amd64", body: preflightWIM("9"), expired: true, want: planner.ErrBlocked},
		{name: "refresh-identity-change", payload: "professional_en-us.esd", architecture: "amd64", body: preflightWIM("9"), expired: true, changed: true, want: download.ErrRefresh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sum := sha256.Sum256(tc.body)
			digest := hex.EncodeToString(sum[:])
			var gets, transfers atomic.Int32
			var origin string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/listeditions.php", "/api/listeditions.php":
					if r.URL.Query().Get("id") != preflightSourceID || r.URL.Query().Get("lang") != "en-us" {
						t.Error("default preflight changed exact selection")
					}
					_, _ = w.Write([]byte(`{"response":{"editionList":["Professional"]}}`))
				case "/get.php", "/api/get.php":
					n := gets.Add(1)
					if r.URL.Query().Get("id") != preflightSourceID || r.URL.Query().Get("lang") != "en-us" || r.URL.Query().Get("edition") != "Professional" || r.URL.Query().Get("noLinks") != "0" {
						t.Error("default preflight changed frozen source query")
					}
					hash := digest
					if tc.changed && n > 1 {
						hash = strings.Repeat("b", 64)
					}
					preflightResponse(w, origin, tc.payload, hash, tc.architecture, len(tc.body), tc.expired && n == 1)
				case "/semantic":
					if transfers.Add(1) <= tc.failures {
						http.Error(w, "retry", 503)
						return
					}
					body := append([]byte(nil), tc.body...)
					if tc.corrupt {
						body[len(body)-1] ^= 1
					}
					_, _ = w.Write(body)
				default:
					t.Errorf("unprojected body requested: %s", r.URL.Path)
					http.Error(w, "unexpected", 400)
				}
			}))
			defer srv.Close()
			origin = srv.URL
			cfg := preflightConfig(t, srv.URL)
			if tc.proxy {
				origin = "http://cdn.invalid"
				cfg.Catalog.Endpoint = "http://catalog.invalid/api"
				cfg.Downloads.Proxy = model.ProxySettings{Mode: model.ProxyExplicit, URL: srv.URL}
			}
			service := defaultBuild(t, cfg)
			plan, err := service.Prepare(context.Background(), tui.BuildDraft{Config: cfg, Revision: 7})
			if !errors.Is(err, tc.want) || plan.Validate() == nil {
				t.Fatalf("default semantic boundary: plan=%s err=%v; want %v", plan.Digest(), err, tc.want)
			}
			if tc.want == planner.ErrBlocked && !strings.Contains(err.Error(), "metadata-role-unresolved") && !strings.Contains(err.Error(), "media-layout-unresolved") {
				t.Fatalf("verified metadata did not reach independent missing-media-role gate: %v", err)
			}
			if gets.Load() == 0 {
				t.Fatal("default build never read exact source catalogue")
			}
			if tc.want == planner.ErrBlocked && transfers.Load() != tc.failures+1 {
				t.Fatalf("verified transfer/retry count = %d", transfers.Load())
			}
			if tc.changed && transfers.Load() != 0 {
				t.Fatal("identity-changing refresh reached CDN")
			}
			assertPreflightClean(t, cfg)
		})
	}
}

func assertPreflightClean(t *testing.T, cfg config.Config) {
	t.Helper()
	for _, parent := range []string{cfg.Storage.Cache, cfg.Storage.Workspace} {
		entries, err := os.ReadDir(parent)
		if err != nil || len(entries) != 0 {
			t.Errorf("preflight left owned resources at %s: %v %v", parent, entries, err)
		}
	}
}

func TestDefaultBuildCloseCancelsPreparationAndRejectsConcurrentCalls(t *testing.T) {
	entered, stopped := make(chan struct{}), make(chan struct{})
	var origin string
	body := preflightWIM("9")
	sum := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/listeditions.php":
			_, _ = w.Write([]byte(`{"response":{"editionList":["Professional"]}}`))
		case "/get.php":
			preflightResponse(w, origin, "professional_en-us.esd", hex.EncodeToString(sum[:]), "amd64", len(body), false)
		case "/semantic":
			close(entered)
			<-r.Context().Done()
			close(stopped)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	origin = srv.URL
	cfg := preflightConfig(t, srv.URL)
	service := defaultBuild(t, cfg)
	result := make(chan error, 1)
	go func() { _, err := service.Prepare(context.Background(), tui.BuildDraft{Config: cfg}); result <- err }()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("no real preflight transfer: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("transfer never began")
	}
	if _, err := service.Prepare(context.Background(), tui.BuildDraft{Config: cfg}); !errors.Is(err, jobs.ErrBusy) {
		t.Fatalf("concurrent preparation: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := service.(interface{ Close(context.Context) error }).Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("close returned before actual HTTP read stopped")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("prepare cancellation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("preparation did not return after close")
	}
	if _, err := service.Prepare(context.Background(), tui.BuildDraft{Config: cfg}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("preparation after close: %v", err)
	}
	assertPreflightClean(t, cfg)
}

func TestDefaultBuildCancellationReportsAndRetainsUnknownResource(t *testing.T) {
	entered := make(chan struct{})
	var origin string
	body := preflightWIM("9")
	sum := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/listeditions.php":
			_, _ = w.Write([]byte(`{"response":{"editionList":["Professional"]}}`))
		case "/get.php":
			preflightResponse(w, origin, "professional_en-us.esd", hex.EncodeToString(sum[:]), "amd64", len(body), false)
		case "/semantic":
			close(entered)
			<-r.Context().Done()
		}
	}))
	defer srv.Close()
	origin = srv.URL
	cfg := preflightConfig(t, srv.URL)
	opts := Options{Config: cfg}
	_ = composeInteractiveBuild(&opts)
	service := opts.Dependencies.Builder
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := service.Prepare(ctx, tui.BuildDraft{Config: cfg}); result <- err }()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("no transfer: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no transfer")
	}
	entries, err := os.ReadDir(cfg.Storage.Workspace)
	if err != nil || len(entries) != 1 {
		t.Fatalf("no private download owner: %v %v", entries, err)
	}
	retained := filepath.Join(cfg.Storage.Workspace, entries[0].Name(), "unexpected.txt")
	if err := os.WriteFile(retained, []byte("unexamined resource"), 0600); err != nil {
		t.Fatal(err)
	}
	cancel()
	var prepareErr error
	select {
	case prepareErr = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not quiesce")
	}
	if !errors.Is(prepareErr, context.Canceled) || !strings.Contains(prepareErr.Error(), filepath.Dir(retained)) || !strings.Contains(prepareErr.Error(), "preserved") {
		t.Fatalf("lost cancellation/custody: %v", prepareErr)
	}
	closeErr := service.(interface{ Close(context.Context) error }).Close(context.Background())
	if closeErr == nil || !strings.Contains(closeErr.Error(), filepath.Dir(retained)) {
		t.Fatalf("close lost earlier preservation: %v", closeErr)
	}
	again := service.(interface{ Close(context.Context) error }).Close(context.Background())
	if again == nil || again.Error() != closeErr.Error() {
		t.Fatalf("close error not latched: %v", again)
	}
	if body, err := os.ReadFile(retained); err != nil || string(body) != "unexamined resource" {
		t.Fatalf("unknown resource changed: %q %v", body, err)
	}
	if entries, err := os.ReadDir(cfg.Storage.Cache); err != nil || len(entries) != 0 {
		t.Fatalf("independent cache cleanup skipped: %v %v", entries, err)
	}
}

func TestDefaultBuildChecksMetadataStorageBeforeTransfer(t *testing.T) {
	var transfers atomic.Int32
	var origin string
	body := preflightWIM("9")
	sum := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/listeditions.php":
			_, _ = w.Write([]byte(`{"response":{"editionList":["Professional"]}}`))
		case "/get.php":
			preflightResponse(w, origin, "professional_en-us.esd", hex.EncodeToString(sum[:]), "amd64", len(body), false)
		case "/semantic":
			transfers.Add(1)
			_, _ = w.Write(body)
		}
	}))
	defer srv.Close()
	origin = srv.URL
	cfg := preflightConfig(t, srv.URL)
	service := defaultBuild(t, cfg).(*buildService)
	service.planner.InspectStorage = func(ctx context.Context, path string) (planner.Volume, error) {
		v, err := inspectBuildStorage(ctx, path)
		v.AvailableBytes = 0 // Exercise exhaustion without filling the host disk.
		return v, err
	}
	_, err := service.Prepare(context.Background(), tui.BuildDraft{Config: cfg})
	if !errors.Is(err, download.ErrStorage) || transfers.Load() != 0 {
		t.Fatalf("storage refusal reached CDN or lost boundary: %v transfers=%d", err, transfers.Load())
	}
	assertPreflightClean(t, cfg)
}

func TestDefaultBuildDefersLargeAppBodiesWhenMediaMetadataIsBlocked(t *testing.T) {
	var appBodies atomic.Int32
	var origin string
	body := preflightWIM("9")
	sum := sha256.Sum256(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/listeditions.php":
			_, _ = w.Write([]byte(`{"response":{"editionList":["Professional","APP"]}}`))
		case "/get.php":
			if r.URL.Query().Get("edition") == "APP" {
				_ = json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{"build": "28000.3365", "arch": "amd64", "files": map[string]any{"unexamined.appx": map[string]any{"sha256": strings.Repeat("a", 64), "size": 5368709120, "expire": 0, "url": origin + "/app"}}}})
			} else {
				preflightResponse(w, origin, "professional_en-us.esd", hex.EncodeToString(sum[:]), "amd64", len(body), false)
			}
		case "/semantic":
			_, _ = w.Write(body)
		case "/app":
			appBodies.Add(1)
			_, _ = w.Write([]byte("never a substitute for the advertised large app"))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	origin = srv.URL
	cfg := preflightConfig(t, srv.URL)
	cfg.Apps.Mode = model.AppsCustom
	cfg.Apps.Include = []string{"Requested.Family_123"}
	service := defaultBuild(t, cfg)
	_, err := service.Prepare(context.Background(), tui.BuildDraft{Config: cfg})
	if !errors.Is(err, planner.ErrBlocked) || !(strings.Contains(err.Error(), "metadata-role-unresolved") || strings.Contains(err.Error(), "media-layout-unresolved")) || appBodies.Load() != 0 {
		t.Fatalf("blocked media fetched apps or lost semantic evidence: %v app-bodies=%d", err, appBodies.Load())
	}
	if len(cfg.Apps.Include) != 1 || cfg.Apps.Include[0] != "Requested.Family_123" {
		t.Fatal("explicit app requests changed")
	}
	assertPreflightClean(t, cfg)
}
