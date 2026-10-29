//go:build windows

package source

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"uupbuilder/internal/catalog"
	"uupbuilder/internal/model"
)

const appTestID = "11111111-1111-1111-1111-111111111111_rev.2"
const appNS = `http://schemas.microsoft.com/embedded/2004/10/ImageUpdate`

type appTestRoundTripper func(*http.Request) (*http.Response, error)

func (f appTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAppCatalogDoesNotTruncateAttemptTimeout(t *testing.T) {
	loader := NewAppCatalog("https://example.invalid/")
	loader.metadata.RequestTimeout = 3 * time.Minute
	loader.http.Timeout = 0
	loader.http.Transport = appTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) < 165*time.Second {
			t.Fatalf("whole-load timeout truncated a bounded attempt: %v", time.Until(deadline))
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"response":{"editionList":["PROFESSIONAL"]}}`)), Header: make(http.Header)}, nil
	})
	if _, err := loader.Load(context.Background(), appSelection()); err != nil {
		t.Fatal(err)
	}
}

type appPacingClock struct {
	now     time.Time
	onSleep func()
}

func newAppPacingClock() *appPacingClock { return &appPacingClock{now: time.Unix(1700000000, 0)} }
func (c *appPacingClock) Now() time.Time { return c.now }
func (c *appPacingClock) Sleep(ctx context.Context, d time.Duration) error {
	if c.onSleep != nil {
		c.onSleep()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.now = c.now.Add(d)
	return nil
}
func setAppTestPacer(loader *SourceAppCatalog, clock *appPacingClock) {
	pacer := catalog.NewGetPacer(clock)
	loader.metadata.Clock, loader.online.Clock = clock, clock
	loader.metadata.Pacer, loader.online.Pacer = pacer, pacer
}

func appXML(features string) string {
	return `<CompDB xmlns="` + appNS + `" SchemaVersion="1.2" Type="Build" Product="Desktop" BuildID="build-id" BuildArch="amd64" OSVersion="10.0.1.1">` + features + `</CompDB>`
}
func editionXML(edition, refs string) string {
	return appXML(`<Tags Type="Edition"><Tag Name="Edition" Value="` + edition + `"/><Tag Name="Language" Value="en-gb"/></Tags><Features><Feature Type="DesktopMedia" FeatureID="` + edition + `_en-gb"><Dependencies>` + refs + `</Dependencies></Feature></Features>`)
}
func refXML(id, kind string) string {
	return `<Feature FeatureID="` + id + `" Type="` + kind + `" Group="PreinstalledApps"/>`
}
func sourceTestCAB(files map[string][]byte) []byte {
	// CAB file offsets are independently generated test input, not production tables.
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	slicesSort(names)
	table := 44
	block := table
	dataBytes := 0
	for _, n := range names {
		block += 17 + len(n)
		dataBytes += len(files[n])
	}
	b := make([]byte, block+8+dataBytes)
	copy(b, "MSCF")
	binary.LittleEndian.PutUint32(b[8:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[16:], uint32(table))
	b[24] = 3
	b[25] = 1
	binary.LittleEndian.PutUint16(b[26:], 1)
	binary.LittleEndian.PutUint16(b[28:], uint16(len(names)))
	binary.LittleEndian.PutUint32(b[36:], uint32(block))
	binary.LittleEndian.PutUint16(b[40:], 1)
	offset := 0
	for _, name := range names {
		data := files[name]
		binary.LittleEndian.PutUint32(b[table:], uint32(len(data)))
		binary.LittleEndian.PutUint32(b[table+4:], uint32(offset))
		copy(b[table+16:], name)
		copy(b[block+8+offset:], data)
		offset += len(data)
		table += 17 + len(name)
	}
	binary.LittleEndian.PutUint16(b[block+4:], uint16(dataBytes))
	binary.LittleEndian.PutUint16(b[block+6:], uint16(dataBytes))
	return b
}
func slicesSort(v []string) {
	for i := range v {
		for j := i + 1; j < len(v); j++ {
			if v[j] < v[i] {
				v[i], v[j] = v[j], v[i]
			}
		}
	}
}

type appHTTPFixture struct {
	body                                  []byte
	calls                                 []string
	bodyCalls                             int
	wrongSource, wrongOnline, corruptBody bool
	throttleBody                          bool
}

func newAppHTTPFixture() *appHTTPFixture {
	apps := appXML(`<Features><Feature FeatureID="Example.App_pub" Type="MSIXBundle"><Dependencies><Feature FeatureID="Example.Framework_pub" Type="Required"/></Dependencies><InitialIntents><InitialIntent Value="PREFERSTUB"/></InitialIntents></Feature><Feature FeatureID="Example.Other_pub" Type="MSIX"/><Feature FeatureID="Example.Framework_pub" Type="MSIXFramework"/></Features>`)
	return &appHTTPFixture{body: sourceTestCAB(map[string][]byte{
		"DesktopTargetCompDB_App_Neutral.xml.cab":        sourceTestCAB(map[string][]byte{"DesktopTargetCompDB_App_Neutral.xml": []byte(apps)}),
		"DesktopTargetCompDB_professional_en-gb.xml.cab": sourceTestCAB(map[string][]byte{"DesktopTargetCompDB_professional_en-gb.xml": []byte(editionXML("professional", refXML("Example.App_pub", "MediaCreationRequired")))}),
		"DesktopTargetCompDB_core_en-gb.xml.cab":         sourceTestCAB(map[string][]byte{"DesktopTargetCompDB_core_en-gb.xml": []byte(editionXML("core", refXML("Example.Other_pub", "Optional")))}),
	})}
}
func (f *appHTTPFixture) serve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.calls = append(f.calls, r.URL.Path+"?"+q.Encode())
	if r.URL.Path == "/cab" {
		f.bodyCalls++
		if f.throttleBody {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		body := f.body
		if f.corruptBody {
			body = append([]byte(nil), body...)
			body[len(body)-1] ^= 1
		}
		w.Write(body)
		return
	}
	if q.Get("id") != appTestID {
		http.Error(w, "wrong exact revision", 400)
		return
	}
	if r.URL.Path == "/listeditions.php" {
		fmt.Fprint(w, `{"response":{"editionList":["APP"]}}`)
		if q.Get("lang") != "neutral" {
			panic("must enumerate neutral selectors")
		}
		return
	}
	if r.URL.Path != "/get.php" {
		http.NotFound(w, r)
		return
	}
	language, edition := q.Get("lang"), q.Get("edition")
	if language == "neutral" && edition != "APP" || language != "neutral" && language != "en-gb" {
		http.Error(w, "wrong selector", 400)
		return
	}
	sum := sha256.Sum256(f.body)
	digest := hex.EncodeToString(sum[:])
	arch := "amd64"
	if f.wrongSource {
		arch = "arm64"
	}
	if f.wrongOnline && q.Get("noLinks") == "0" {
		digest = strings.Repeat("0", 64)
	}
	file := map[string]any{"sha256": digest, "size": len(f.body), "expire": 0}
	if q.Get("noLinks") == "0" {
		file["url"] = "http://" + r.Host + "/cab"
	}
	files := map[string]any{"AggregatedMetadata_test.cab": file, "large.appx": map[string]any{"sha256": strings.Repeat("1", 64), "size": 1000000000, "expire": 0}}
	_ = json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{"build": "1.20", "arch": arch, "files": files}})
}

func TestAppCatalogBodyRetryAfterPacesTheNextLoad(t *testing.T) {
	f := newAppHTTPFixture()
	f.throttleBody = true
	loader := fixtureAppLoader(t, f)
	if _, err := loader.Load(context.Background(), appSelection()); err == nil {
		t.Fatal("throttled body succeeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := loader.Load(ctx, appSelection()); !errors.Is(err, context.DeadlineExceeded) || f.bodyCalls != 1 {
		t.Fatalf("Retry-After bypassed: %v calls=%d", err, f.bodyCalls)
	}
}

func TestAppCatalogRedirectedCABRetainsTargetOriginCooldown(t *testing.T) {
	for _, route := range []string{"direct", "alternate redirect"} {
		t.Run(route, func(t *testing.T) {
			calls := 0
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(429)
			}))
			defer target.Close()
			redirect := func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL+"/cab", http.StatusFound) }
			first := httptest.NewServer(http.HandlerFunc(redirect))
			defer first.Close()
			alternate := httptest.NewServer(http.HandlerFunc(redirect))
			defer alternate.Close()
			loader := NewAppCatalog("https://example.invalid/")
			id := model.PayloadIdentity{}
			if _, err := loader.acquire(context.Background(), id, model.Locator{URL: first.URL + "/cab"}); err == nil || calls != 1 {
				t.Fatalf("initial throttle not observed: %v calls=%d", err, calls)
			}
			url := target.URL + "/cab"
			if route == "alternate redirect" {
				url = alternate.URL + "/cab"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			_, err := loader.acquire(ctx, id, model.Locator{URL: url})
			if err == nil || ctx.Err() != context.DeadlineExceeded || calls != 1 {
				t.Fatalf("redirect target cooldown bypassed: %v context=%v calls=%d", err, ctx.Err(), calls)
			}
		})
	}
}

func TestAppCatalogPacesActualRetryAndFollowingRequest(t *testing.T) {
	for _, header := range []string{"0", "", "1"} {
		t.Run("RetryAfter="+header, func(t *testing.T) {
			f := newAppHTTPFixture()
			clock := newAppPacingClock()
			var sends []time.Time
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/get.php" && r.URL.Query().Get("noLinks") == "0" {
					sends = append(sends, clock.Now())
					if len(sends) == 1 {
						if header != "" {
							w.Header().Set("Retry-After", header)
						}
						w.WriteHeader(429)
						fmt.Fprint(w, `{"response":{"error":"USER_RATE_LIMITED"}}`)
						return
					}
				}
				f.serve(w, r)
			}))
			defer server.Close()
			loader := NewAppCatalog(server.URL)
			setAppTestPacer(loader, clock)
			snapshot, err := loader.Load(context.Background(), appSelection())
			if err != nil || snapshot.State != AppCatalogAvailable {
				t.Fatalf("rate-limited app load failed: %v", err)
			}
			if len(sends) != 2 || sends[1].Sub(sends[0]) < 10250*time.Millisecond {
				t.Fatalf("actual linked requests not paced: %v", sends)
			}
		})
	}
}

func TestAppCatalogCancellationStopsPacedImmediateRetry(t *testing.T) {
	f := newAppHTTPFixture()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/get.php" && r.URL.Query().Get("noLinks") == "0" {
			calls++
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			fmt.Fprint(w, `{"response":{"error":"USER_RATE_LIMITED"}}`)
			return
		}
		f.serve(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := newAppPacingClock()
	clock.onSleep = func() {
		if calls > 0 {
			cancel()
		}
	}
	loader := NewAppCatalog(server.URL)
	setAppTestPacer(loader, clock)
	_, err := loader.Load(ctx, appSelection())
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancellation sent an immediate retry: %v calls=%d", err, calls)
	}
}

func TestAppCatalogLongRetryAfterSurvivesToNextLoad(t *testing.T) {
	for _, header := range []string{"121", "18446744073709551616"} {
		t.Run(header, func(t *testing.T) {
			f := newAppHTTPFixture()
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/get.php" && r.URL.Query().Get("noLinks") == "0" {
					calls++
					w.Header().Set("Retry-After", header)
					w.WriteHeader(429)
					fmt.Fprint(w, `{"response":{"error":"USER_RATE_LIMITED"}}`)
					return
				}
				f.serve(w, r)
			}))
			defer server.Close()
			loader := NewAppCatalog(server.URL)
			setAppTestPacer(loader, newAppPacingClock())
			for range 2 {
				_, err := loader.Load(context.Background(), appSelection())
				var later *catalog.RetryLaterError
				if !errors.As(err, &later) || calls != 1 {
					t.Fatalf("longer cooldown lost or not explained: %v calls=%d", err, calls)
				}
			}
		})
	}
}

func TestAppCatalogLiveCachedMetadata(t *testing.T) {
	root := os.Getenv("UUPBUILDER_APP_RESEARCH_DIR")
	if os.Getenv("UUPBUILDER_APP_LIVE") != "1" || root == "" {
		t.Skip("explicit opt-in live metadata-only walk")
	}
	raw, err := os.ReadFile(filepath.Join(root, "latest-en-gb-professional-nolinks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Response struct {
			Files map[string]struct {
				SHA256 string          `json:"sha256"`
				Size   json.RawMessage `json:"size"`
			} `json:"files"`
		} `json:"response"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		t.Fatal("invalid retained metadata")
	}
	body, err := os.ReadFile(filepath.Join(root, "latest-aggregated-metadata.cab"))
	if err != nil {
		t.Fatal(err)
	}
	selection := model.Selection{UpdateID: "8f550c54-da87-45d3-89e3-0c03a6f16ae8", Architecture: "amd64", Language: "en-gb", Editions: []string{"PROFESSIONAL"}}
	loader := NewAppCatalog("")
	for name, file := range envelope.Response.Files {
		if strings.Contains(strings.ToLower(name), "aggregatedmetadata") {
			// Size must match the retained actual body; the production verifier
			// rechecks this source SHA256 before any cached decoder use.
			loader.cachedID = model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: file.SHA256}, Size: int64(len(body)), Provenance: model.PackageProvenance{Source: "uupdump:get.php:" + selection.UpdateID, Name: name}}
			loader.cachedCAB = body
		}
	}
	if !verifiedCAB(loader.cachedID, body) {
		t.Fatal("retained CAB does not verify")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	snapshot, err := loader.Load(ctx, selection)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range snapshot.Entries {
		if len(e.Editions) > 0 && e.Type != "MSIXFramework" {
			count++
		}
	}
	if snapshot.State != AppCatalogAvailable || count != 50 {
		t.Fatalf("live source offers changed: state=%s choices=%d", snapshot.State, count)
	}
	t.Logf("paced live cached metadata source=%s build=%s arch=%s language=%s choices=%d CAB=%s documents=%+v", snapshot.SelectedSource.UpdateID, snapshot.SelectedSource.BuildLabel, snapshot.SelectedSource.Architecture, snapshot.SelectedSource.Language, count, snapshot.CAB.Digest.Value, snapshot.Documents)
}

func TestAppCatalogLiveFreshMetadata(t *testing.T) {
	if os.Getenv("UUPBUILDER_APP_LIVE") != "1" {
		t.Skip("explicit opt-in live fresh metadata/CAB walk")
	}
	selection := model.Selection{UpdateID: "8f550c54-da87-45d3-89e3-0c03a6f16ae8", Architecture: "amd64", Language: "en-gb", Editions: []string{"PROFESSIONAL"}}
	loader := NewAppCatalog("")
	metadataRequests, linkedRequests, bodyRequests := 0, 0, 0
	var previousGet time.Time
	baseTransport := loader.http.Transport
	loader.http.Transport = appTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		now := time.Now()
		if strings.HasSuffix(r.URL.Path, "/get.php") {
			if r.URL.Query().Get("noLinks") == "1" {
				metadataRequests++
			} else {
				linkedRequests++
				if !previousGet.IsZero() && now.Sub(previousGet) < 10250*time.Millisecond {
					t.Error("live linked request bypassed cooldown")
				}
			}
			previousGet = now
		} else if !strings.HasSuffix(r.URL.Path, "/listeditions.php") {
			bodyRequests++
		}
		return baseTransport.RoundTrip(r)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	snapshot, err := loader.Load(ctx, selection)
	if err != nil {
		t.Fatal(err)
	}
	choices := 0
	for _, entry := range snapshot.Entries {
		if len(entry.Editions) > 0 && entry.Type != "MSIXFramework" {
			choices++
		}
	}
	if snapshot.State != AppCatalogAvailable || choices != 50 || metadataRequests < 2 || metadataRequests > 6 || linkedRequests < 1 || linkedRequests > 3 || bodyRequests != 1 {
		t.Fatalf("fresh source changed: state=%s choices=%d metadata=%d links=%d bodies=%d", snapshot.State, choices, metadataRequests, linkedRequests, bodyRequests)
	}
	t.Logf("fresh live source=%s choices=%d metadata=%d linked=%d CAB requests=%d SHA256=%s", selection.UpdateID, choices, metadataRequests, linkedRequests, bodyRequests, snapshot.CAB.Digest.Value)
}
func fixtureAppLoader(t *testing.T, f *appHTTPFixture) *SourceAppCatalog {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(s.Close)
	loader := NewAppCatalog(s.URL)
	setAppTestPacer(loader, newAppPacingClock())
	return loader
}
func appSelection() model.Selection {
	return model.Selection{UpdateID: appTestID, Architecture: "amd64", Language: "en-gb", Editions: []string{"PROFESSIONAL"}}
}

func TestAppCatalogHTTPWalkBindsNeutralToSelectedEdition(t *testing.T) {
	f := newAppHTTPFixture()
	loader := fixtureAppLoader(t, f)
	selection := appSelection()
	snapshot, err := loader.Load(context.Background(), selection)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != AppCatalogAvailable || !reflect.DeepEqual(snapshot.Selection, selection) || snapshot.AppSource.Language != "neutral" || snapshot.SelectedSource.Language != "en-gb" || snapshot.SelectedSource.BuildLabel != "1.20" || snapshot.Binding.BaselineOSVersion != "10.0.1.1" || len(snapshot.Entries) != 2 {
		t.Fatalf("bad catalogue binding: %+v", snapshot)
	}
	if snapshot.Entries[0].FeatureID != "Example.App_pub" || len(snapshot.Entries[0].Editions) != 1 || snapshot.Entries[0].Editions[0].Type != "MediaCreationRequired" || snapshot.Entries[0].Dependencies[0].FeatureID != "Example.Framework_pub" {
		t.Fatalf("wrong edition requests: %+v", snapshot.Entries)
	}
	if snapshot.AppManifest.Validate() != nil || snapshot.SelectedManifests[0].Validate() != nil || snapshot.AppManifest.Source.Language != "neutral" || f.bodyCalls != 1 {
		t.Fatal("mixed manifests or wrong acquisition")
	}
	if len(snapshot.Documents) != 2 || len(snapshot.Containers) != 3 || len(snapshot.Gaps) == 0 {
		t.Fatal("missing exact evidence or pending validation")
	}
	snapshot.Entries[0].FeatureID = "caller mutation"
	snapshot.Selection.Editions[0] = "changed"
	again, err := loader.Load(context.Background(), appSelection())
	if err != nil || again.Entries[0].FeatureID != "Example.App_pub" || again.Selection.Editions[0] != "PROFESSIONAL" || f.bodyCalls != 1 {
		t.Fatalf("cache/isolation failed: %v %+v", err, again)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "large.appx") {
			t.Fatal("downloaded app body")
		}
	}
}

func TestAppCatalogMultiEditionPreservesMembership(t *testing.T) {
	f := newAppHTTPFixture()
	loader := fixtureAppLoader(t, f)
	selection := appSelection()
	selection.Editions = append(selection.Editions, "CORE")
	snapshot, err := loader.Load(context.Background(), selection)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 3 || len(snapshot.Documents) != 3 {
		t.Fatalf("wrong projection: %+v", snapshot)
	}
	for _, entry := range snapshot.Entries {
		if entry.FeatureID == "Example.Other_pub" && (len(entry.Editions) != 1 || entry.Editions[0].Edition != "CORE") {
			t.Fatalf("union pretended all edition applicability: %+v", entry)
		}
	}
}

func TestAppCatalogRejectsChangedSourceOnlineIdentityAndBody(t *testing.T) {
	for _, kind := range []string{"source", "online", "digest", "buildID"} {
		t.Run(kind, func(t *testing.T) {
			f := newAppHTTPFixture()
			switch kind {
			case "source":
				f.wrongSource = true
			case "online":
				f.wrongOnline = true
			case "digest":
				f.corruptBody = true
			case "buildID":
				f.body = sourceTestCAB(map[string][]byte{"DesktopTargetCompDB_App_Neutral.xml.cab": sourceTestCAB(map[string][]byte{"DesktopTargetCompDB_App_Neutral.xml": []byte(appXML(`<Features/>`))}), "DesktopTargetCompDB_professional_en-gb.xml.cab": sourceTestCAB(map[string][]byte{"DesktopTargetCompDB_professional_en-gb.xml": []byte(strings.Replace(editionXML("professional", refXML("Example.App_pub", "Optional")), "build-id", "other-build", 1))})})
			}
			_, err := fixtureAppLoader(t, f).Load(context.Background(), appSelection())
			if err == nil {
				t.Fatal("changed metadata accepted")
			}
		})
	}
}

func TestAppCatalogNoSelectorIsDeferredAndCancellationStopsWait(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"response":{"editionList":["PROFESSIONAL"]}}`)
	}))
	defer s.Close()
	loader := NewAppCatalog(s.URL)
	snapshot, err := loader.Load(context.Background(), appSelection())
	if err != nil || snapshot.State != AppCatalogDeferred || len(snapshot.Entries) != 0 || len(snapshot.Gaps) == 0 {
		t.Fatalf("missing selector claimed empty available: %+v %v", snapshot, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = loader.Load(ctx, appSelection()); !errors.Is(err, context.Canceled) {
		t.Fatalf("ignored cancellation: %v", err)
	}
}

// Opt-in authentic retained evidence is never a product resource or a copied
// test fixture. This exercises the real CAB/XML path without app bodies.
func TestAppCatalogRetainedEvidence(t *testing.T) {
	root := os.Getenv("UUPBUILDER_APP_RESEARCH_DIR")
	if root == "" {
		t.Skip("set a retained research evidence directory")
	}
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	body := read("latest-aggregated-metadata.cab")
	app := read("latest-neutral-app-nolinks.json")
	selected := read("latest-en-gb-professional-nolinks.json")
	editions := read("latest-neutral-listeditions.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cab" {
			w.Write(body)
			return
		}
		if r.URL.Path == "/listeditions.php" {
			w.Write(editions)
			return
		}
		if r.URL.Query().Get("lang") == "neutral" {
			w.Write(app)
			return
		}
		if r.URL.Query().Get("noLinks") == "1" {
			w.Write(selected)
			return
		}
		var envelope map[string]any
		if json.Unmarshal(selected, &envelope) != nil {
			t.Fatal("bad evidence JSON")
		}
		files := envelope["response"].(map[string]any)["files"].(map[string]any)
		for name, value := range files {
			if strings.Contains(strings.ToLower(name), "aggregatedmetadata") {
				value.(map[string]any)["url"] = "http://" + r.Host + "/cab"
				value.(map[string]any)["expire"] = 0
			}
		}
		json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()
	loader := NewAppCatalog(server.URL)
	setAppTestPacer(loader, newAppPacingClock())
	selection := model.Selection{UpdateID: "8f550c54-da87-45d3-89e3-0c03a6f16ae8", Architecture: "amd64", Language: "en-gb", Editions: []string{"PROFESSIONAL"}}
	snapshot, err := loader.Load(context.Background(), selection)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	teams, hevc := false, false
	for _, entry := range snapshot.Entries {
		if len(entry.Editions) > 0 && entry.Type != "MSIXFramework" {
			count++
		}
		if entry.FeatureID == "MSTeams_8wekyb3d8bbwe" {
			teams = len(entry.Licenses) == 1 && !entry.Licenses[0].FamilyMatchesIgnoringCase && entry.Licenses[0].PFM == "microsoft.microsoftteamsapp_8wekyb3d8bbwe"
		}
		if entry.FeatureID == "Microsoft.HEVCVideoExtension_8wekyb3d8bbwe" {
			hevc = len(entry.Editions) == 1 && entry.Editions[0].Type == "MediaCreationRequired"
		}
	}
	if count != 50 || !teams || !hevc || snapshot.Binding.BuildID != "45571fb0-281e-82c9-ee74-5b4894fc7666" || snapshot.SelectedSource.BuildLabel != "28000.3365" {
		t.Fatalf("authentic observations changed: choices=%d Teams=%v HEVC=%v binding=%+v", count, teams, hevc, snapshot.Binding)
	}
	t.Logf("source choices=%d entries=%d CAB=%s documents=%+v containers=%d", count, len(snapshot.Entries), snapshot.CAB.Digest.Value, snapshot.Documents, len(snapshot.Containers))
}
