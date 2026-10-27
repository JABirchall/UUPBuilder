package config

import (
	"errors"
	"testing"
)

func TestStrictDiagnosticsRetainAllUnknownKeys(t *testing.T) {
	_, err := Decode([]byte("schema_version=1\n[output]\nfirst=1\nsecond=2\n"), "unknown.toml")
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("expected joined diagnostics, got %T: %v", err, err)
	}
	diagnostics := joined.Unwrap()
	if len(diagnostics) != 2 {
		t.Fatalf("got %d diagnostics", len(diagnostics))
	}
	assertDiagnostic(t, diagnostics[0], "unknown.toml", "output.first", 3, 1)
	assertDiagnostic(t, diagnostics[1], "unknown.toml", "output.second", 4, 1)
}

func TestErrorUnwrapsCause(t *testing.T) {
	cause := errors.New("cause")
	err := &Error{Key: "output.kind", Err: cause}
	if !errors.Is(err, cause) || err.Error() != "config: output.kind: cause" {
		t.Fatalf("error lost context: %v", err)
	}
}
