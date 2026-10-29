package cabindex

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/cabformat"
	"uupbuilder/internal/model"
)

func TestExhaustedResultRemainderRefusesBeforeCABFraming(t *testing.T) {
	// This fixture has 286 manifest string bytes, one reference, two payloads,
	// no queries/projections: 286*8 + 1*256 + 2*16384 + 4096 = 39408 bytes.
	// Use that exact boundary, rather than a smaller budget refused on entry.
	const initialCharge = 39408
	for _, tc := range []struct {
		name      string
		malformed bool
		metadata  uint64
	}{
		{name: "valid-source-parser-budget-sentinel", metadata: 1},
		{name: "malformed-source-signature-sentinel", malformed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
			if tc.malformed {
				copy(body[:4], "BAD!")
			}
			m, files, oracle := input(t, [][]byte{body}, [][]byte{[]byte("xx")})
			if len(m.Payloads) != 2 || len(m.Queries) != 0 || oracle.Claim().References != 1 {
				t.Fatal("fixture no longer represents the hand-derived exact boundary")
			}
			result, err := Build(context.Background(), m, files, oracle, Limits{MaxResultBytes: initialCharge, MaxMetadataBytes: tc.metadata})
			if result != nil {
				result.Close()
				t.Fatal("exhausted result allowance published a result")
			}
			// The old path returns the framing budget/signature error here. The Build
			// limit must win before Inspect can observe either independent sentinel.
			if !errors.Is(err, ErrLimit) || errors.Is(err, cabformat.ErrLimit) || errors.Is(err, cabformat.ErrLayout) {
				t.Fatalf("framing began after exact result exhaustion: %v", err)
			}
		})
	}
}

func TestUnboundSuppliedIdentityNameIsBoundBeforeNormalization(t *testing.T) {
	body := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, files, oracle := input(t, [][]byte{body}, [][]byte{[]byte("xx")})
	// Construct caller-owned input before measuring Build. ASCII uppercase forces
	// ToLower to allocate a full new string if this unbound name reaches it.
	name := strings.Repeat("A", 8<<20) + ".CAB"
	files[0].Identity.Provenance.Name = name
	for _, tc := range []struct {
		name     string
		variable int
	}{{name: "default-variable-cap"}, {name: "lowered-variable-cap", variable: 256}} {
		t.Run(tc.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			result, err := Build(context.Background(), m, files, oracle, Limits{MaxResultBytes: 40 << 10, MaxVariableBytes: tc.variable})
			runtime.ReadMemStats(&after)
			allocated := after.TotalAlloc - before.TotalAlloc
			t.Logf("Build allocated %d bytes for an unbound %d-byte uppercase name", allocated, len(name))
			if result != nil {
				result.Close()
				t.Error("unbound identity published a result")
			}
			if !errors.Is(err, ErrLimit) {
				t.Errorf("supplied name did not hit its early variable bound: %v", err)
			}
			// Generous headroom for bounded manifest/reference bookkeeping and runtime
			// noise, but far below one lowercase copy of the caller's eight-MiB name.
			if allocated >= 1<<20 {
				t.Errorf("unbound name reached allocating normalization: %d bytes", allocated)
			}
		})
	}
}

func TestSuppliedIdentityFieldsAreBoundBeforeValidation(t *testing.T) {
	body := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, files, oracle := input(t, [][]byte{body}, [][]byte{[]byte("xx")})
	oversized := strings.Repeat("A", 4097)
	for _, tc := range []struct {
		name   string
		change func(*model.PayloadIdentity)
	}{
		{"digest-algorithm", func(i *model.PayloadIdentity) { i.Digest.Algorithm = model.DigestAlgorithm(oversized) }},
		{"digest-value", func(i *model.PayloadIdentity) { i.Digest.Value = oversized }},
		{"provenance-source", func(i *model.PayloadIdentity) { i.Provenance.Source = oversized }},
		{"provenance-name", func(i *model.PayloadIdentity) { i.Provenance.Name = oversized }},
		{"encryption-method", func(i *model.PayloadIdentity) { i.Encryption.Method = oversized }},
		{"encryption-fingerprint", func(i *model.PayloadIdentity) { i.Encryption.Fingerprint = oversized }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			supplied := append([]metadata.LocalResource(nil), files...)
			tc.change(&supplied[0].Identity)
			result, err := Build(context.Background(), m, supplied, oracle, Limits{})
			if result != nil {
				result.Close()
				t.Fatal("oversized unbound identity published a result")
			}
			if !errors.Is(err, ErrLimit) {
				t.Fatalf("supplied identity reached validation before its variable bound: %v", err)
			}
		})
	}
}
