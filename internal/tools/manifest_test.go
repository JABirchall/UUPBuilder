package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"uupbuilder/internal/model"
)

// All fixtures are invented text. They are not vendor files or runtime evidence.
func testSHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func fixtureDocument() manifestDocument {
	return manifestDocument{SchemaVersion: 1, Providers: []provider{{
		ID: "synthetic", Version: "1.0", NativeArchitecture: "arm64", Route: "vendor-zip",
		Publisher: "Synthetic fixture author", Provenance: "test-only invented text bytes",
		IntentOperations: []Operation{Extract}, Notices: []string{"COPYING.txt"},
		Pending:  []Blocker{{Code: "runtime-unverified", Detail: "Synthetic data cannot prove operations"}},
		Packages: []packagePin{{Name: "fixture.zip", URL: "https://example.test/fixture-1.0.zip", Size: 1, SHA256: testSHA([]byte("z")), SHA256Origin: "local-measurement", Provenance: "test fixture", SignatureObservation: "not-inspected"}},
		Files: []filePin{
			{Path: "tool.exe", Role: "executable", Version: "1.0", Size: 4, SHA256: testSHA([]byte("tool")), NativeArchitecture: "arm64", Dependencies: []string{"companion.dll"}},
			{Path: "companion.dll", Role: "dll", Version: "1.0", Size: 3, SHA256: testSHA([]byte("dll")), NativeArchitecture: "arm64"},
			{Path: "COPYING.txt", Role: "notice", Size: 7, SHA256: testSHA([]byte("notice\n"))},
		},
	}}}
}

func trustedFixture(t *testing.T, doc manifestDocument) TrustedManifest {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	m, err := LoadTrustedManifest(b, testSHA(b))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTrustedManifestRequiresExactTrustedContent(t *testing.T) {
	doc := fixtureDocument()
	b, _ := json.Marshal(doc)
	if _, err := LoadTrustedManifest(b, strings.Repeat("0", 64)); !errors.Is(err, ErrManifestDigest) {
		t.Fatalf("changed manifest was accepted: %v", err)
	}
	for _, mutation := range []struct {
		name  string
		apply func(*manifestDocument)
	}{
		{"missing-blockers", func(d *manifestDocument) { d.Providers[0].Pending = nil }},
		{"insecure-origin", func(d *manifestDocument) { d.Providers[0].Packages[0].URL = "http://example.test/tool.zip" }},
		{"moving-origin", func(d *manifestDocument) { d.Providers[0].Packages[0].URL = "https://example.test/latest/tool.zip" }},
		{"missing-pin", func(d *manifestDocument) { d.Providers[0].Files[1].SHA256 = "" }},
		{"case-collision", func(d *manifestDocument) { d.Providers[0].Files[1].Path = "TOOL.exe" }},
		{"unsafe-native-component", func(d *manifestDocument) {
			d.Providers[0].NativeArchitecture = "../arm64"
			for i := range d.Providers[0].Files {
				if d.Providers[0].Files[i].NativeArchitecture != "" {
					d.Providers[0].Files[i].NativeArchitecture = "../arm64"
				}
			}
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			d := fixtureDocument()
			mutation.apply(&d)
			raw, _ := json.Marshal(d)
			if _, err := LoadTrustedManifest(raw, testSHA(raw)); !errors.Is(err, ErrManifest) {
				t.Fatalf("invalid candidate accepted: %v", err)
			}
		})
	}
}

func TestTrustedManifestRejectsAmbiguousJSON(t *testing.T) {
	b, _ := json.Marshal(fixtureDocument())
	for _, raw := range [][]byte{
		[]byte(strings.Replace(string(b), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)),
		[]byte(strings.Replace(string(b), `"schema_version":1`, `"schema_version":1,"SCHEMA_VERSION":1`, 1)),
		[]byte(strings.Replace(string(b), `"schema_version":1`, `"schema_version":1,"ready":true`, 1)),
		append(append([]byte(nil), b...), []byte(` {}`)...),
		[]byte(strings.Repeat(" ", (4<<20)+1)),
	} {
		if _, err := LoadTrustedManifest(raw, testSHA(raw)); !errors.Is(err, ErrManifest) {
			t.Fatalf("ambiguous/unbounded JSON accepted: %v", err)
		}
	}
}

func TestEmbeddedManifestPinSurvivesCheckoutLineEndings(t *testing.T) {
	original := defaultManifest
	t.Cleanup(func() { defaultManifest = original })
	lf := strings.ReplaceAll(string(original), "\r\n", "\n")
	for _, data := range []string{lf, strings.ReplaceAll(lf, "\n", "\r\n")} {
		defaultManifest = []byte(data)
		if _, err := DefaultManifest(); err != nil {
			t.Fatalf("checkout newline conversion invalidated embedded content pin: %v", err)
		}
	}
}

func testRequirement(digest string) Requirement {
	return Requirement{Host: model.Host{WindowsBuild: 19045, ProcessArchitecture: "amd64", NativeArchitecture: "arm64"}, Target: "x86", Operations: []Operation{Extract}, ManifestDigest: digest}
}

func TestSelectionUsesNativeHostAndTargetCapabilities(t *testing.T) {
	doc := fixtureDocument()
	x64 := doc.Providers[0]
	x64.ID = "wrong-emulated-provider"
	x64.NativeArchitecture = "amd64"
	x64.Files = append([]filePin(nil), x64.Files...)
	for i := range x64.Files {
		if x64.Files[i].NativeArchitecture != "" {
			x64.Files[i].NativeArchitecture = "amd64"
		}
	}
	doc.Providers = append(doc.Providers, x64)
	m := trustedFixture(t, doc)
	req := testRequirement(m.Digest())
	req.Operations = []Operation{Service}
	selection, err := m.Select(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.Candidates) != 1 || selection.Candidates[0].ID != "synthetic" {
		t.Fatalf("selected process architecture instead of native host: %+v", selection)
	}
	if selection.Requirement.Target != "x86" || !hasBlocker(selection.Blockers, "capability-unverified") || !hasBlocker(selection.Candidates[0].Blockers, "operation-unavailable") {
		t.Fatalf("missing exact target/operation blocker: %+v", selection)
	}
}

func TestUnknownTargetIsNotHidden(t *testing.T) {
	m := trustedFixture(t, fixtureDocument())
	req := testRequirement(m.Digest())
	req.Target = "future-cpu"
	selection, err := m.Select(req)
	if err != nil {
		t.Fatalf("upstream target was rejected: %v", err)
	}
	if selection.Requirement.Target != "future-cpu" || len(selection.Candidates) != 1 || !hasBlocker(selection.Blockers, "capability-unverified") {
		t.Fatalf("target silently removed: %+v", selection)
	}
	req.Operations[0] = Service
	if selection.Requirement.Operations[0] != Extract {
		t.Fatal("selection aliased mutable caller operations")
	}
}

func hasBlocker(bs []Blocker, code string) bool {
	for _, b := range bs {
		if b.Code == code {
			return true
		}
	}
	return false
}
