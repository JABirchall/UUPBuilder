package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSourceIdentityPreservesRevision(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc_rev.7"
	source, err := NewSourceIdentity(id, "Windows build 12345.67", Architecture("amd64"), "en-us")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var restored SourceIdentity
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.UpdateID != id {
		t.Fatalf("revision-qualified identity lost: %q", restored.UpdateID)
	}
	if err := restored.Validate(); err != nil {
		t.Fatal(err)
	}
	other := restored
	other.UpdateID = "12345678-1234-1234-1234-123456789abc_rev.8"
	a, err := NewPayloadManifest(restored, []Payload{testPayload(t, "sources/install.esd")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPayloadManifest(other, a.Payloads)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest == b.Digest {
		t.Fatal("different source revisions share a manifest digest")
	}
}

func TestUnknownArchitectureIsRetained(t *testing.T) {
	for _, value := range []string{"x86", "amd64", "arm64", "arm", "future128-v2"} {
		arch, err := NewArchitecture(value)
		if err != nil {
			t.Fatalf("%s: %v", value, err)
		}
		if string(arch) != value {
			t.Fatalf("architecture %q changed to %q", value, arch)
		}
	}
	if got := ArchitectureFromGo("386"); got != "x86" {
		t.Fatalf("Go 386 maps to %q", got)
	}
	if got := ArchitectureFromGo("future128"); got != "future128" {
		t.Fatalf("unknown Go architecture lost: %q", got)
	}
	for _, value := range []string{"", " amd64", "a\nb"} {
		if _, err := NewArchitecture(value); err == nil {
			t.Fatalf("accepted malformed architecture %q", value)
		}
	}
}

func TestPayloadIdentityIgnoresDownloadUUID(t *testing.T) {
	// A resolver must retain trusted package metadata even when a link has no UUID.
	var link struct {
		UUID *string `json:"uuid"`
	}
	if err := json.Unmarshal([]byte(`{"uuid":null}`), &link); err != nil {
		t.Fatal(err)
	}
	payload := testPayload(t, "sources/install.esd")
	key := payload.Identity.Key()
	locators := Locators{payload.Identity: {URL: "https://example.invalid/file?signature=secret", ExpiresAt: time.Unix(100, 0)}}
	locators[payload.Identity] = Locator{URL: "https://example.invalid/refreshed?signature=replaced"}
	if link.UUID != nil || payload.Identity.Key() != key {
		t.Fatal("download link changed payload identity")
	}
	source, err := NewSourceIdentity("update_rev.3", "build", "arm", "en-us")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewPayloadManifest(source, []Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "signature") || strings.Contains(string(data), "https:") {
		t.Fatalf("locator leaked into manifest: %s", data)
	}
	if _, err := json.Marshal(locators); err == nil {
		t.Fatal("runtime locators must refuse public serialization")
	}
	if _, err := json.Marshal(locators[payload.Identity]); err == nil {
		t.Fatal("a runtime locator must refuse public serialization")
	}
	changed := payload.Identity
	changed.Encryption.Fingerprint = strings.Repeat("b", 64)
	if changed.Key() == key {
		t.Fatal("encryption identity omitted from payload key")
	}
	changed = payload.Identity
	changed.Provenance.Name = "another-package.esd"
	if changed.Key() == key {
		t.Fatal("original package provenance omitted from payload key")
	}
}

func TestPayloadIdentityValidatesLegacyDigests(t *testing.T) {
	for _, tc := range []struct {
		algorithm DigestAlgorithm
		size      int
	}{{DigestMD5, 32}, {DigestSHA1, 40}, {DigestSHA256, 64}, {DigestSHA384, 96}, {DigestSHA512, 128}} {
		digest, err := NewDigest(tc.algorithm, strings.Repeat("A", tc.size))
		if err != nil {
			t.Fatal(err)
		}
		if digest.Value != strings.Repeat("a", tc.size) {
			t.Fatal("digest not canonicalized")
		}
	}
	for _, digest := range []Digest{{Algorithm: DigestSHA1, Value: "short"}, {Algorithm: DigestSHA256, Value: strings.Repeat("z", 64)}, {Algorithm: "unknown", Value: strings.Repeat("a", 64)}} {
		if err := digest.Validate(); err == nil {
			t.Fatalf("accepted invalid digest %+v", digest)
		}
	}
	identity := testPayload(t, "a.esd").Identity
	identity.Size = -1
	if err := identity.Validate(); err == nil {
		t.Fatal("accepted negative payload size")
	}
	identity = testPayload(t, "a.esd").Identity
	identity.Encryption.Fingerprint = "secret-key"
	if err := identity.Validate(); err == nil {
		t.Fatal("accepted non-SHA256 encryption fingerprint")
	}
}

func TestPayloadManifestDeterministicAndDetectsMutation(t *testing.T) {
	source, err := NewSourceIdentity("update_rev.1", "build", "amd64", "en-us")
	if err != nil {
		t.Fatal(err)
	}
	first, second := testPayload(t, "b.esd"), testPayload(t, "a.esd")
	a, err := NewPayloadManifest(source, []Payload{first, second})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPayloadManifest(source, []Payload{second, first})
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest {
		t.Fatal("input ordering changes manifest identity")
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	a.Payloads[0].Destination = "changed.esd"
	if err := a.Validate(); err == nil {
		t.Fatal("mutated frozen manifest still validates")
	}
	if _, err := NewPayloadManifest(source, []Payload{testPayload(t, "SOURCES/a.esd"), testPayload(t, "sources/A.esd")}); err == nil {
		t.Fatal("accepted colliding Windows destinations")
	}
}

func TestPayloadManifestRejectsFileDirectoryConflicts(t *testing.T) {
	source, err := NewSourceIdentity("update_rev.1", "build", "amd64", "en-us")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		destinations []string
	}{
		{"parent-first", []string{"sources/a.esd", "sources/a.esd/child.esd"}},
		{"child-first", []string{"sources/a.esd/child.esd", "sources/a.esd"}},
		{"mixed-case-parent-first", []string{"Sources/A.ESD", "sources/a.esd/child.esd"}},
		{"mixed-case-child-first", []string{"sources/A.ESD/child.esd", "SOURCES/a.esd"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payloads := []Payload{testPayload(t, tc.destinations[0]), testPayload(t, tc.destinations[1])}
			if _, err := NewPayloadManifest(source, payloads); err == nil || !strings.Contains(err.Error(), "manifest.payloads") {
				t.Errorf("constructor must reject conflicting file/directory destinations, got %v", err)
			}
			// Validate must identify the structural conflict before checking the
			// digest, including when a manifest is restored rather than constructed.
			manifest := PayloadManifest{Source: source, Payloads: payloads}
			if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "manifest.payloads") {
				t.Errorf("validation must reject conflicting file/directory destinations, got %v", err)
			}
		})
	}
}

func TestPayloadManifestAllowsSharedDirectoriesAndDistinctPrefixes(t *testing.T) {
	source, err := NewSourceIdentity("update_rev.1", "build", "amd64", "en-us")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewPayloadManifest(source, []Payload{
		testPayload(t, "sources/a.esd"),
		testPayload(t, "SOURCES/b.esd"),
		testPayload(t, "sources/a.esd.other/child.esd"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
}

func testPayload(t *testing.T, destination string) Payload {
	t.Helper()
	digest, err := NewDigest(DigestSHA1, strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	identity := PayloadIdentity{Digest: digest, Size: 123, Provenance: PackageProvenance{Source: "update_rev.3", Name: "original-package.esd"}, Encryption: EncryptionIdentity{Method: "esd", Fingerprint: strings.Repeat("c", 64)}}
	payload, err := NewPayload(identity, destination)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
