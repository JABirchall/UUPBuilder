package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"uupbuilder/internal/model"
)

func TestNoLinksNullDownloadUUIDRetainsPayloadIdentity(t *testing.T) {
	s := serveJSON(t, fixture(t, "files-nolinks.json"))
	c := New(s.Client(), s.URL)
	c.MetadataOnly = true
	set, err := c.Files(context.Background(), sourceID, "en-us", "updateonly")
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Payloads) != 6 || len(set.Locators) != 0 {
		t.Fatalf("null locators lost metadata or invented URLs: %+v", set)
	}
	for _, p := range set.Payloads {
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		if p.Destination != "windows10.0-kb5005189-arm64.psf" {
			continue
		}
		if p.Identity.Digest != (model.Digest{Algorithm: model.DigestSHA1, Value: "397003ef4479d3964991d4deafe0e46b1bd3ffb6"}) || p.Identity.Size != 157251389 ||
			p.Identity.Provenance.Name != p.Destination || p.Identity.Provenance.Source != "uupdump:get.php:"+sourceID {
			t.Fatalf("lost trusted identity or resolver provenance: %+v", p)
		}
		manifest, err := model.NewPayloadManifest(set.Source, set.Payloads)
		if err != nil || manifest.Digest == "" {
			t.Fatalf("fixture failed production manifest ingestion: %v", err)
		}
		return
	}
	t.Fatal("PSF payload disappeared")
}

func TestFilesPreferDeclaredSHA256AndDoNotInventIt(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	data := strings.Replace(string(fixture(t, "files-nolinks.json")), `"sha256":null`, `"sha256":"`+digest+`"`, 1)
	s := serveJSON(t, []byte(data))
	c := New(s.Client(), s.URL)
	c.MetadataOnly = true
	set, err := c.Files(context.Background(), sourceID, "en-us", "updateonly")
	if err != nil {
		t.Fatal(err)
	}
	if set.Payloads[0].Identity.Digest.Algorithm != model.DigestSHA256 || set.Payloads[0].Identity.Digest.Value != digest {
		t.Fatal("declared SHA-256 was lost")
	}
	if set.Payloads[1].Identity.Digest.Algorithm != model.DigestSHA1 {
		t.Fatal("invented SHA-256 for null upstream hash")
	}
}

func TestFilesLocatorsRemainRuntimeOnlyAndKeepDeclaredScheme(t *testing.T) {
	data := strings.Replace(string(fixture(t, "files-nolinks.json")), `"url":null`, `"url":"http://payload.invalid/metadata.cab?token=synthetic"`, 1)
	data = strings.Replace(data, `"expire":0`, `"expire":"1900000000"`, 1)
	var requests atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Get("noLinks") != "0" {
			t.Error("normal Files must resolve locators")
		}
		_, _ = w.Write([]byte(data))
	}))
	defer s.Close()
	c := New(s.Client(), s.URL)
	first, err := c.Files(context.Background(), sourceID, "en-us", "updateonly")
	if err != nil {
		t.Fatal(err)
	}
	for _, locator := range first.Locators {
		if locator.URL != "http://payload.invalid/metadata.cab?token=synthetic" || locator.ExpiresAt.Unix() != 1900000000 {
			t.Fatal("declared scheme/expiry changed")
		}
	}
	if len(first.Locators) != 1 {
		t.Fatal("missing locator")
	}
	encoded, err := json.Marshal(first)
	if err != nil || strings.Contains(string(encoded), "synthetic") {
		t.Fatalf("serialized runtime locator: %s, %v", encoded, err)
	}
	if _, err := c.Files(context.Background(), sourceID, "en-us", "updateonly"); err != nil || requests.Load() != 2 {
		t.Fatalf("get.php response was cached: requests=%d error=%v", requests.Load(), err)
	}
}

func TestFilesRejectUnsafeOrIncompleteMetadata(t *testing.T) {
	data := string(fixture(t, "files-nolinks.json"))
	for _, tt := range []struct{ name, from, to string }{
		{"path-traversal", `desktopdeployment.cab`, `../desktopdeployment.cab`},
		{"device", `desktopdeployment.cab`, `CON.cab`},
		{"collision", `desktopdeployment.cab`, `SSU-22000.132-ARM64.CAB`},
		{"size", `"944706"`, `"-1"`},
		{"size-overflow", `"944706"`, `"9223372036854775808"`},
		{"digest", `54b4e3b8064b3823fea49c5cf609749dbb70ad06`, `wrong`},
		{"expiry", `"expire":0`, `"expire":null`},
		{"url-scheme", `"url":null`, `"url":"file:///tmp/private"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := serveJSON(t, []byte(strings.Replace(data, tt.from, tt.to, 1)))
			if _, err := New(s.Client(), s.URL).Files(context.Background(), sourceID, "en-us", "updateonly"); err == nil {
				t.Fatal("unsafe/incomplete metadata accepted")
			}
		})
	}
}
