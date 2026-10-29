package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Architecture is an open-ended upstream target, independent of the host CPU.
type Architecture string

const (
	ArchitectureX86   Architecture = "x86"
	ArchitectureAMD64 Architecture = "amd64"
	ArchitectureARM64 Architecture = "arm64"
)

func NewArchitecture(value string) (Architecture, error) {
	arch := Architecture(value)
	return arch, arch.Validate()
}

func (a Architecture) Validate() error {
	if err := identifier("architecture", string(a)); err != nil {
		return err
	}
	if strings.ContainsFunc(string(a), unicode.IsSpace) {
		return errors.New("architecture must not contain whitespace")
	}
	return nil
}

// ArchitectureFromGo maps the differently named x86 host family explicitly.
// Unknown values survive and must not be used to filter upstream targets.
func ArchitectureFromGo(goarch string) Architecture {
	if goarch == "386" {
		return ArchitectureX86
	}
	return Architecture(goarch)
}

// UpdateID is opaque: the complete upstream UUID/revision string is retained.
// BuildLabel is descriptive, not a substitute for UpdateID.
type SourceIdentity struct {
	UpdateID     string       `json:"update_id" toml:"update_id"`
	BuildLabel   string       `json:"build_label" toml:"build_label"`
	Architecture Architecture `json:"architecture" toml:"architecture"`
	Language     string       `json:"language" toml:"language"`
}

func NewSourceIdentity(updateID, buildLabel string, architecture Architecture, language string) (SourceIdentity, error) {
	source := SourceIdentity{UpdateID: updateID, BuildLabel: buildLabel, Architecture: architecture, Language: language}
	return source, source.Validate()
}

func (s SourceIdentity) Validate() error {
	if err := identifier("source.update_id", s.UpdateID); err != nil {
		return err
	}
	if err := identifier("source.build_label", s.BuildLabel); err != nil {
		return err
	}
	if err := s.Architecture.Validate(); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	return identifier("source.language", s.Language)
}

type DigestAlgorithm string

const (
	DigestMD5    DigestAlgorithm = "md5"
	DigestSHA1   DigestAlgorithm = "sha1"
	DigestSHA256 DigestAlgorithm = "sha256"
	DigestSHA384 DigestAlgorithm = "sha384"
	DigestSHA512 DigestAlgorithm = "sha512"
)

// Legacy source digests are supported; cache ingestion still computes SHA-256.
// A well-formed digest does not by itself establish the metadata's trust.
type Digest struct {
	Algorithm DigestAlgorithm `json:"algorithm" toml:"algorithm"`
	Value     string          `json:"value" toml:"value"`
}

func NewDigest(algorithm DigestAlgorithm, value string) (Digest, error) {
	digest := Digest{Algorithm: DigestAlgorithm(strings.ToLower(string(algorithm))), Value: strings.ToLower(value)}
	return digest, digest.Validate()
}

func (d Digest) Validate() error {
	sizes := map[DigestAlgorithm]int{DigestMD5: 32, DigestSHA1: 40, DigestSHA256: 64, DigestSHA384: 96, DigestSHA512: 128}
	size, ok := sizes[d.Algorithm]
	if !ok {
		return fmt.Errorf("digest.algorithm: unsupported algorithm %q", d.Algorithm)
	}
	if len(d.Value) != size || strings.ToLower(d.Value) != d.Value {
		return fmt.Errorf("digest.value: expected %d lowercase hexadecimal characters", size)
	}
	if _, err := hex.DecodeString(d.Value); err != nil {
		return fmt.Errorf("digest.value: invalid hexadecimal digest")
	}
	return nil
}

type PackageProvenance struct {
	Source string `json:"source" toml:"source"`
	Name   string `json:"name" toml:"name"`
}

// EncryptionIdentity contains an algorithm/method identity and a SHA-256
// fingerprint of required decryption information, never the decryption secret.
// Both fields are empty for unencrypted payloads.
type EncryptionIdentity struct {
	Method      string `json:"method,omitempty" toml:"method,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty" toml:"fingerprint,omitempty"`
}

// PayloadIdentity is comparable and is safe to use as a runtime map key.
// A nullable download UUID and expiring URLs are deliberately absent.
type PayloadIdentity struct {
	Digest     Digest             `json:"digest" toml:"digest"`
	Size       int64              `json:"size" toml:"size"`
	Provenance PackageProvenance  `json:"provenance" toml:"provenance"`
	Encryption EncryptionIdentity `json:"encryption" toml:"encryption"`
}

func (p PayloadIdentity) Validate() error {
	if err := p.Digest.Validate(); err != nil {
		return err
	}
	if p.Size < 0 {
		return errors.New("payload.size: must not be negative")
	}
	if err := identifier("payload.provenance.source", p.Provenance.Source); err != nil {
		return err
	}
	if err := identifier("payload.provenance.name", p.Provenance.Name); err != nil {
		return err
	}
	if p.Encryption.Method != "" || p.Encryption.Fingerprint != "" {
		if err := identifier("payload.encryption.method", p.Encryption.Method); err != nil {
			return err
		}
		if err := (Digest{Algorithm: DigestSHA256, Value: p.Encryption.Fingerprint}).Validate(); err != nil {
			return fmt.Errorf("payload.encryption.fingerprint: %w", err)
		}
	}
	return nil
}

// Key is a deterministic SHA-256 of every identity field. Validate before use.
func (p PayloadIdentity) Key() string { return contentDigest(p) }

type Payload struct {
	Identity    PayloadIdentity `json:"identity" toml:"identity"`
	Destination string          `json:"destination" toml:"destination"`
}

func NewPayload(identity PayloadIdentity, destination string) (Payload, error) {
	if err := identity.Validate(); err != nil {
		return Payload{}, err
	}
	path, err := ValidateRelativePath(destination)
	if err != nil {
		return Payload{}, fmt.Errorf("payload.destination: %w", err)
	}
	return Payload{Identity: identity, Destination: path}, nil
}

func (p Payload) Validate() error {
	if err := p.Identity.Validate(); err != nil {
		return err
	}
	path, err := ValidateRelativePath(p.Destination)
	if err != nil {
		return fmt.Errorf("payload.destination: %w", err)
	}
	if path != p.Destination {
		return errors.New("payload.destination: must use canonical slash separators")
	}
	return nil
}

// A manifest is frozen after construction. Validate detects accidental mutation.
// Runtime locators and secrets are never part of this public representation.
type PayloadManifest struct {
	Source   SourceIdentity `json:"source" toml:"source"`
	Payloads []Payload      `json:"payloads" toml:"payloads"`
	Queries  []SourceQuery  `json:"queries,omitempty" toml:"queries,omitempty"`
	Digest   string         `json:"digest" toml:"digest"`
}

// SourceQuery is public, frozen catalog provenance for replay after restart.
// Projection, when present, freezes an exact subset of a complete response.
// Omission preserves the original whole-response contract. No runtime links.
type SourceQuery struct {
	UpdateID   string    `json:"update_id" toml:"update_id"`
	Language   string    `json:"language" toml:"language"`
	Edition    string    `json:"edition" toml:"edition"`
	Projection []Payload `json:"projection,omitempty" toml:"projection,omitempty"`
}

func (q SourceQuery) Validate() error {
	for _, value := range []string{q.UpdateID, q.Language, q.Edition} {
		if value == "" || len(value) > 128 {
			return errors.New("manifest.query: selectors must contain 1 to 128 ASCII identifier characters")
		}
		first := value[0]
		if !(first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z' || first >= '0' && first <= '9') {
			return errors.New("manifest.query: selectors must start with an ASCII letter or digit")
		}
		for _, r := range value {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
				return errors.New("manifest.query: selectors must contain only ASCII identifier characters")
			}
		}
	}
	seen := map[string]bool{}
	for _, p := range q.Projection {
		if p.Validate() != nil || seen[strings.ToLower(p.Destination)] {
			return errors.New("manifest.query: invalid or duplicate projected payload")
		}
		seen[strings.ToLower(p.Destination)] = true
	}
	return nil
}

// CloneSourceQueries also copies nested projection slices at freeze boundaries.
func CloneSourceQueries(queries []SourceQuery) []SourceQuery {
	copy := slices.Clone(queries)
	for i := range copy {
		copy[i].Projection = append([]Payload(nil), copy[i].Projection...)
	}
	return copy
}

func compareQueries(a, b SourceQuery) int {
	if c := strings.Compare(a.UpdateID, b.UpdateID); c != 0 {
		return c
	}
	if c := strings.Compare(a.Language, b.Language); c != 0 {
		return c
	}
	if c := strings.Compare(a.Edition, b.Edition); c != 0 {
		return c
	}
	return strings.Compare(contentDigest(a.Projection), contentDigest(b.Projection))
}

func NewPayloadManifest(source SourceIdentity, payloads []Payload, queries ...SourceQuery) (PayloadManifest, error) {
	manifest := PayloadManifest{Source: source, Payloads: slices.Clone(payloads), Queries: CloneSourceQueries(queries)}
	for i := range manifest.Queries {
		slices.SortFunc(manifest.Queries[i].Projection, func(a, b Payload) int { return strings.Compare(a.Destination, b.Destination) })
	}
	if err := manifest.validateInputs(); err != nil {
		return PayloadManifest{}, err
	}
	slices.SortFunc(manifest.Payloads, func(a, b Payload) int {
		if order := strings.Compare(a.Destination, b.Destination); order != 0 {
			return order
		}
		return strings.Compare(a.Identity.Key(), b.Identity.Key())
	})
	slices.SortFunc(manifest.Queries, compareQueries)
	manifest.Queries = slices.CompactFunc(manifest.Queries, func(a, b SourceQuery) bool { return compareQueries(a, b) == 0 })
	manifest.Digest = manifest.contentDigest()
	return manifest, nil
}

func (m PayloadManifest) Validate() error {
	if err := m.validateInputs(); err != nil {
		return err
	}
	canonical, err := NewPayloadManifest(m.Source, m.Payloads, m.Queries...)
	if err != nil {
		return err
	}
	if m.Digest != canonical.Digest {
		return errors.New("manifest.digest: frozen manifest identity does not match its content")
	}
	return nil
}

func (m PayloadManifest) validateInputs() error {
	if err := m.Source.Validate(); err != nil {
		return err
	}
	if len(m.Payloads) == 0 {
		return errors.New("manifest.payloads: at least one payload is required")
	}
	for _, query := range m.Queries {
		if err := query.Validate(); err != nil {
			return err
		}
		if query.UpdateID != m.Source.UpdateID || query.Language != m.Source.Language {
			return errors.New("manifest.query: source revision and language must match the manifest")
		}
		for _, projected := range query.Projection {
			if !slices.Contains(m.Payloads, projected) {
				return errors.New("manifest.query: projected payload is outside frozen closure")
			}
		}
	}
	seen := make(map[string]bool)
	directories := make(map[string]bool)
	for _, payload := range m.Payloads {
		if err := payload.Validate(); err != nil {
			return err
		}
		key := strings.ToLower(payload.Destination)
		if seen[key] {
			return fmt.Errorf("manifest.payloads: duplicate Windows destination %q", payload.Destination)
		}
		if directories[key] {
			return fmt.Errorf("manifest.payloads: file/directory destination conflict at %q", payload.Destination)
		}
		for parent := key; ; {
			slash := strings.LastIndexByte(parent, '/')
			if slash < 0 {
				break
			}
			parent = parent[:slash]
			if seen[parent] {
				return fmt.Errorf("manifest.payloads: destination %q requires file path %q to be a directory", payload.Destination, parent)
			}
			directories[parent] = true
		}
		seen[key] = true
	}
	return nil
}

func (m PayloadManifest) contentDigest() string {
	return contentDigest(struct {
		Version  int            `json:"version"`
		Source   SourceIdentity `json:"source"`
		Payloads []Payload      `json:"payloads"`
		Queries  []SourceQuery  `json:"queries,omitempty"`
	}{Version: 1, Source: m.Source, Payloads: m.Payloads, Queries: m.Queries})
}

// Locator is a runtime-only signed URL. Serialization fails even when a caller
// accidentally tries to marshal a locator directly.
type Locator struct {
	URL       string    `json:"-" toml:"-"`
	ExpiresAt time.Time `json:"-" toml:"-"`
}

type Locators map[PayloadIdentity]Locator

func (Locator) MarshalJSON() ([]byte, error) {
	return nil, errors.New("runtime payload locator cannot be serialized")
}
func (Locators) MarshalJSON() ([]byte, error) {
	return nil, errors.New("runtime payload locators cannot be serialized")
}

func contentDigest(value any) string {
	// Only fixed model structs with string/integer/slice fields are passed here.
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func identifier(key, value string) error {
	if value == "" || !utf8.ValidString(value) || value != strings.TrimSpace(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return fmt.Errorf("%s: must be nonempty UTF-8 without surrounding whitespace or controls", key)
	}
	return nil
}
