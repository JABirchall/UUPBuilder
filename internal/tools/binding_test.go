package tools

import (
	"errors"
	"strings"
	"testing"
	"uupbuilder/internal/model"
)

func TestCapabilityRequestBindsExactSourceAndRuleBeforeSelection(t *testing.T) {
	m, err := DefaultManifest()
	if err != nil {
		t.Fatal(err)
	}
	r := testRequirement(m.Digest())
	r.Source = model.SourceIdentity{UpdateID: "source-rev.2", BuildLabel: "19041.1", Architecture: r.Target, Language: "en-us"}
	r.SourceManifestDigest = strings.Repeat("a", 64)
	r.RuleDigest = strings.Repeat("b", 64)
	selected, err := m.Select(r)
	if err != nil || selected.Requirement.Source != r.Source || selected.Requirement.SourceManifestDigest != r.SourceManifestDigest || selected.Requirement.RuleDigest != r.RuleDigest || len(selected.Blockers) == 0 {
		t.Fatalf("binding lost or promoted to readiness: %+v %v", selected, err)
	}
	r.Source.Architecture = "amd64"
	if _, err := m.Select(r); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("mismatched source target accepted: %v", err)
	}
	r.Source.Architecture = r.Target
	r.RuleDigest = ""
	if _, err := m.Select(r); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("partial capability binding accepted: %v", err)
	}
}
