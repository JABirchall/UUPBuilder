// Package tools records pinned native provider candidates and their explicit
// blockers. Static identities do not establish operational toolchain readiness.
package tools

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode"

	"uupbuilder/internal/model"
)

var (
	ErrManifest       = errors.New("invalid tool manifest")
	ErrManifestDigest = errors.New("tool manifest digest mismatch")
	ErrUnverified     = errors.New("toolchain capability unverified")
	ErrIntegrity      = errors.New("tool materialization integrity failure")
	ErrArchive        = errors.New("unsafe tool archive")
	ErrInUse          = errors.New("tool workspace already leased")
	ErrClosed         = errors.New("tool manager closed")
	ErrStorage        = errors.New("tool owned storage operation failed")
	ErrInvalidInput   = errors.New("invalid tool requirement or options")
	ErrAcquisition    = errors.New("tool package acquisition failed")
)

type Blocker struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}
type manifestDocument struct {
	SchemaVersion int        `json:"schema_version"`
	Providers     []provider `json:"providers"`
}
type provider struct {
	ID                 string             `json:"id"`
	Version            string             `json:"version"`
	NativeArchitecture model.Architecture `json:"native_architecture"`
	Route              string             `json:"route"`
	Publisher          string             `json:"publisher"`
	Provenance         string             `json:"provenance"`
	IntentOperations   []Operation        `json:"intent_operations"`
	Packages           []packagePin       `json:"packages"`
	Files              []filePin          `json:"files"`
	Notices            []string           `json:"notices"`
	Pending            []Blocker          `json:"pending"`
}
type packagePin struct {
	Name                 string        `json:"name"`
	URL                  string        `json:"url"`
	Size                 int64         `json:"size"`
	SHA256               string        `json:"sha256"`
	SHA256Origin         string        `json:"sha256_origin"`
	Provenance           string        `json:"provenance"`
	PublisherDigest      *model.Digest `json:"publisher_digest,omitempty"`
	SignatureObservation string        `json:"signature_observation"`
	Signer               string        `json:"signer,omitempty"`
	SignerThumbprint     string        `json:"signer_thumbprint,omitempty"`
	ObservedAt           string        `json:"observed_at,omitempty"`
}
type filePin struct {
	Path                 string             `json:"path"`
	Role                 string             `json:"role"`
	Size                 int64              `json:"size"`
	SHA256               string             `json:"sha256"`
	Version              string             `json:"version,omitempty"`
	NativeArchitecture   model.Architecture `json:"native_architecture,omitempty"`
	Dependencies         []string           `json:"dependencies,omitempty"`
	Provenance           string             `json:"provenance,omitempty"`
	SignatureObservation string             `json:"signature_observation,omitempty"`
}
type TrustedManifest struct {
	digest    string
	providers []provider
}

func (m TrustedManifest) Digest() string { return m.digest }

// LoadTrustedManifest checks a digest supplied by trusted application code, not
// by a downloaded document. It authenticates configured content only: locally
// measured pins and historical signature observations are not publisher hashes,
// current signature checks, legal permission, or operational attestation.
// Schema 1 is deliberately candidate-only; no document can declare readiness.
func LoadTrustedManifest(data []byte, expectedSHA256 string) (TrustedManifest, error) {
	if len(data) > 4<<20 {
		return TrustedManifest{}, ErrManifest
	}
	if !validSHA(expectedSHA256) || digestBytes(data) != expectedSHA256 {
		return TrustedManifest{}, ErrManifestDigest
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return TrustedManifest{}, fmt.Errorf("%w: JSON structure", ErrManifest)
	}
	var doc manifestDocument
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&doc); err != nil {
		return TrustedManifest{}, fmt.Errorf("%w: JSON fields: %v", ErrManifest, err)
	}
	if d.Decode(new(any)) != io.EOF || doc.SchemaVersion != 1 || len(doc.Providers) == 0 {
		return TrustedManifest{}, ErrManifest
	}
	seen := map[string]bool{}
	for _, p := range doc.Providers {
		if err := validateProvider(p); err != nil {
			return TrustedManifest{}, fmt.Errorf("%w: %s: %v", ErrManifest, p.ID, err)
		}
		key := strings.ToLower(p.ID + "/" + p.Version + "/" + string(p.NativeArchitecture))
		if seen[key] {
			return TrustedManifest{}, fmt.Errorf("%w: duplicate provider", ErrManifest)
		}
		seen[key] = true
	}
	return TrustedManifest{digest: expectedSHA256, providers: doc.Providers}, nil
}

//go:embed manifests/v1.json
var defaultManifest []byte

// This content pin uses LF line endings so Git's Windows checkout conversion
// cannot change it. It is reviewed with the embedded candidate facts; it is not
// a vendor signature or operational approval. External manifests remain exact.
const defaultManifestSHA256 = "f604bfe3c81327cbbe3e2e1491af569af542f22369bdc3c94022d61ed33aa193"

func DefaultManifest() (TrustedManifest, error) {
	return LoadTrustedManifest(bytes.ReplaceAll(defaultManifest, []byte("\r\n"), []byte("\n")), defaultManifestSHA256)
}

func digestBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func validSHA(s string) bool {
	return (model.Digest{Algorithm: model.DigestSHA256, Value: s}).Validate() == nil
}
func safeText(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}
func pathValid(s string) bool    { n, err := model.ValidateRelativePath(s); return err == nil && n == s }
func segmentValid(s string) bool { return pathValid(s) && !strings.Contains(s, "/") }
func operationValid(op Operation) bool {
	switch op {
	case Extract, Inspect, Service, Reconstruct, MasterISO:
		return true
	}
	return false
}

func validateProvider(p provider) error {
	if !segmentValid(p.ID) || !segmentValid(p.Version) || !segmentValid(string(p.NativeArchitecture)) || p.NativeArchitecture.Validate() != nil || !safeText(p.Publisher) || !safeText(p.Provenance) {
		return errors.New("missing provider identity/provenance")
	}
	if p.Route != "vendor-zip" && p.Route != "vendor-managed-adk" {
		return errors.New("unknown acquisition route")
	}
	if len(p.Pending) == 0 || len(p.IntentOperations) == 0 || len(p.Packages) == 0 || len(p.Files) == 0 || len(p.Notices) == 0 {
		return errors.New("candidate pins, intent, notices and explicit blockers required")
	}
	for _, b := range p.Pending {
		if !safeText(b.Code) || !safeText(b.Detail) {
			return errors.New("invalid candidate blocker")
		}
	}
	ops := map[Operation]bool{}
	for _, op := range p.IntentOperations {
		if !operationValid(op) || ops[op] {
			return errors.New("invalid intent operations")
		}
		ops[op] = true
	}
	names := map[string]bool{}
	for _, pin := range p.Packages {
		if !segmentValid(pin.Name) || names[strings.ToLower(pin.Name)] || pin.Size <= 0 || !validSHA(pin.SHA256) || !safeText(pin.Provenance) {
			return errors.New("invalid package pin")
		}
		names[strings.ToLower(pin.Name)] = true
		if pin.SHA256Origin != "local-measurement" && pin.SHA256Origin != "publisher-published" {
			return errors.New("digest origin required")
		}
		u, err := url.Parse(pin.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.Contains(strings.ToLower(u.Path), "/latest") || strings.Contains(strings.ToLower(u.Path), "fwlink") {
			return errors.New("exact HTTPS package origin required")
		}
		if pin.PublisherDigest != nil && pin.PublisherDigest.Validate() != nil {
			return errors.New("invalid separately attributed publisher digest")
		}
		switch pin.SignatureObservation {
		case "valid-observed":
			if !safeText(pin.Signer) {
				return errors.New("signature observation missing signer")
			}
		case "unsigned-observed", "not-inspected":
		default:
			return errors.New("unknown signature observation")
		}
	}
	files := map[string]bool{}
	for _, f := range p.Files {
		if !pathValid(f.Path) || files[strings.ToLower(f.Path)] || f.Size < 0 || !validSHA(f.SHA256) {
			return errors.New("invalid file pin")
		}
		files[strings.ToLower(f.Path)] = true
		switch f.Role {
		case "executable", "dll", "driver":
			if f.NativeArchitecture != p.NativeArchitecture || !safeText(f.Version) {
				return errors.New("native file identity missing")
			}
		case "notice", "resource":
		default:
			return errors.New("invalid file role")
		}
		for _, dep := range f.Dependencies {
			if !pathValid(dep) {
				return errors.New("invalid dependency path")
			}
		}
	}
	for path := range files {
		for parent := path; strings.Contains(parent, "/"); {
			parent = parent[:strings.LastIndexByte(parent, '/')]
			if files[parent] {
				return errors.New("file/directory collision")
			}
		}
	}
	notices := map[string]bool{}
	for _, n := range p.Notices {
		if !pathValid(n) || notices[strings.ToLower(n)] {
			return errors.New("invalid notice inventory")
		}
		notices[strings.ToLower(n)] = true
	}
	return nil
}

// encoding/json accepts duplicate object keys. A second token pass rejects
// them at every depth so a reviewed pin has one unambiguous interpretation.
func rejectDuplicateKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return ErrManifest
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			keys := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				// Match encoding/json's Unicode simple-fold equivalence, which
				// includes long-s/S and Kelvin-sign/K beyond lowercase mapping.
				key = strings.Map(func(r rune) rune {
					canonical := r
					for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
						if folded < canonical {
							canonical = folded
						}
					}
					return canonical
				}, key)
				if !ok || keys[key] {
					return ErrManifest
				}
				keys[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return ErrManifest
			}
		case json.Delim('['):
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return ErrManifest
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrManifest
	}
	return nil
}
