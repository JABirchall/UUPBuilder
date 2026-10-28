package probes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"uupbuilder/internal/model"
)

const runtimeBindingsLimit = 1 << 20

// Roots deliberately live outside RuntimeConfig's public JSON form. This
// private envelope grants neither readiness nor permission to run a command.
type privateRuntimeBinding struct {
	CaseID          string        `json:"case_id"`
	FixtureRoot     string        `json:"fixture_root"`
	WorkspaceParent string        `json:"workspace_parent"`
	Runtime         RuntimeConfig `json:"runtime"`
}

// LoadRuntimeBindings reads the strict private v1 envelope. Case membership and
// the complete recipe/case contract are checked by bindProviderRuntimes before
// the tagged gate launches anything. No filesystem or provider is opened here.
func LoadRuntimeBindings(r io.Reader) (map[string]RuntimeConfig, error) {
	if r == nil {
		return nil, errors.New("runtime bindings: reader required")
	}
	encoded, err := io.ReadAll(io.LimitReader(r, runtimeBindingsLimit+1))
	if err != nil {
		return nil, err
	}
	if len(encoded) > runtimeBindingsLimit || !utf8.Valid(encoded) {
		return nil, errors.New("runtime bindings: requires UTF-8 within 1 MiB")
	}
	// encoding/json otherwise silently accepts duplicate keys and case-insensitive
	// field aliases. Reject both before typed decoding, including nested objects.
	keys := json.NewDecoder(bytes.NewReader(encoded))
	if err := checkBindingJSON(keys, 0); err != nil {
		return nil, err
	}
	if _, err := keys.Token(); err != io.EOF {
		return nil, errors.New("runtime bindings: trailing JSON")
	}
	var document struct {
		SchemaVersion int                     `json:"schema_version"`
		Bindings      []privateRuntimeBinding `json:"bindings"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if document.SchemaVersion != 1 || len(document.Bindings) == 0 || len(document.Bindings) > 128 {
		return nil, errors.New("runtime bindings: schema 1 and 1..128 bindings required")
	}
	result := make(map[string]RuntimeConfig)
	seen := map[string]bool{}
	for _, entry := range document.Bindings {
		if !bindingIdentity(entry.CaseID) || seen[strings.ToLower(entry.CaseID)] {
			return nil, errors.New("runtime bindings: malformed or ambiguous case ID")
		}
		seen[strings.ToLower(entry.CaseID)] = true
		config := entry.Runtime
		config.FixtureRoot, config.WorkspaceParent = entry.FixtureRoot, entry.WorkspaceParent
		if err := validatePrivateRuntime(config); err != nil {
			return nil, fmt.Errorf("runtime binding %q: %w", entry.CaseID, err)
		}
		result[entry.CaseID] = config
	}
	return result, nil
}

func checkBindingJSON(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("runtime bindings: excessive JSON nesting")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("runtime bindings: null values forbidden")
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errors.New("runtime bindings: unexpected delimiter")
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || name == "" || strings.ContainsFunc(name, func(r rune) bool { return r != '_' && (r < 'a' || r > 'z') }) || seen[name] {
				return errors.New("runtime bindings: duplicate or noncanonical JSON key")
			}
			seen[name] = true
		}
		if err := checkBindingJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func bindingIdentity(value string) bool {
	return len(value) > 0 && len(value) <= 128 && !strings.ContainsFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.')
	}) && value != "." && value != ".."
}

func validatePrivateRuntime(config RuntimeConfig) error {
	if err := (model.Digest{Algorithm: model.DigestSHA256, Value: config.CaseDigest}).Validate(); err != nil || config.CaseDigest != strings.ToLower(config.CaseDigest) {
		return errors.New("canonical frozen case SHA-256 required")
	}
	for _, root := range []string{config.FixtureRoot, config.WorkspaceParent} {
		if !filepath.IsAbs(root) || textRequired("private root", root) != nil {
			return errors.New("explicit absolute fixture/workspace roots required")
		}
	}
	seen := map[string]bool{}
	for _, group := range [][]FileBinding{config.Inputs, config.Components} {
		if len(group) == 0 || len(group) > 128 {
			return errors.New("bounded nonempty artifact bindings required")
		}
		paths := map[string]bool{}
		for _, binding := range group {
			path, err := model.ValidateRelativePath(binding.Path)
			id := strings.ToLower(binding.ID)
			if err != nil || !bindingIdentity(binding.ID) || seen[id] || paths[strings.ToLower(path)] {
				return errors.New("unsafe or ambiguous artifact binding")
			}
			seen[id], paths[strings.ToLower(path)] = true, true
		}
	}
	for _, binding := range config.Components {
		if !oneOf(binding.Path, "expand.exe", "certutil.exe", "cabinet.dll") {
			return errors.New("only closed native component names allowed")
		}
	}
	var ids, identity []string
	var member string
	switch config.Recipe {
	case ExpandCompDBCABV1:
		x := config.Extraction
		if config.WIM != (WIMExtraction{}) || x.Identity.Architecture.Validate() != nil {
			return errors.New("misbound CompDB recipe")
		}
		ids = []string{x.InputID, x.ExpectationID, x.ExpandID, x.CertutilID}
		identity = []string{x.Identity.Type, x.Identity.BuildID, x.Identity.OSVersion}
		member = x.Member
		if !strings.EqualFold(filepath.Ext(member), ".xml") {
			return errors.New("one XML member required")
		}
	case ObserveWIMLZMSV1:
		x := config.WIM
		if config.Extraction != (CompDBExtraction{}) || x.Identity.Architecture.Validate() != nil || x.Member != "update.mum" {
			return errors.New("misbound bounded WIM recipe")
		}
		ids = []string{x.InputID, x.ExpectationID, x.CabinetID, x.CertutilID}
		identity = []string{x.Identity.Name, x.Identity.Version, x.Identity.PublicKeyToken, x.Identity.Language}
		member = x.Member
	default:
		return errors.New("unsupported closed probe recipe")
	}
	for _, id := range ids {
		if !bindingIdentity(id) {
			return errors.New("malformed recipe identity")
		}
	}
	for _, value := range identity {
		if textRequired("recipe identity", value) != nil {
			return errors.New("incomplete recipe identity")
		}
	}
	if _, err := model.ValidateRelativePath(member); err != nil || strings.ContainsAny(member, "/\\") {
		return errors.New("one explicit closed recipe member required")
	}
	return nil
}

// Validate the whole request before the first RunCase. A stale binding for even
// an unselected case is rejected rather than silently ignored. Component cases
// can bind, but their original pending blockers and observation limits remain.
func bindProviderRuntimes(cases, selected []Case, bindings map[string]RuntimeConfig) (map[string]RuntimeConfig, error) {
	frozen := map[string]Case{}
	seen := map[string]bool{}
	for _, c := range cases {
		if !bindingIdentity(c.ID) || seen[strings.ToLower(c.ID)] {
			return nil, errors.New("ambiguous frozen case identity")
		}
		if err := c.Validate(); err != nil {
			return nil, err
		}
		seen[strings.ToLower(c.ID)], frozen[c.ID] = true, c
	}
	for id, config := range bindings {
		c, exists := frozen[id]
		if !exists {
			return nil, fmt.Errorf("unknown frozen case binding %q", id)
		}
		if err := validatePrivateRuntime(config); err != nil {
			return nil, err
		}
		if _, err := validateRuntime(c, config); err != nil {
			return nil, fmt.Errorf("case %q: %w", id, err)
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("selected frozen cases required")
	}
	result := map[string]RuntimeConfig{}
	for _, c := range selected {
		original, exists := frozen[c.ID]
		if !exists || original.Digest() != c.Digest() {
			return nil, errors.New("selected case differs from frozen ledger")
		}
		config, exists := bindings[c.ID]
		if !exists {
			return nil, fmt.Errorf("missing runtime binding for frozen case %q", c.ID)
		}
		if _, duplicate := result[c.ID]; duplicate {
			return nil, errors.New("duplicate selected case")
		}
		config.Inputs = append([]FileBinding(nil), config.Inputs...)
		config.Components = append([]FileBinding(nil), config.Components...)
		result[c.ID] = config
	}
	return result, nil
}
