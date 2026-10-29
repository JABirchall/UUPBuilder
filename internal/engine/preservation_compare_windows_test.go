package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"uupbuilder/internal/engine/source"
	platform "uupbuilder/internal/platform/windows"
)

// This private deterministic port supplies synthetic complete native fields.
// Its paths, stream bytes, times and descriptor are hand-authored independently
// of SourceExpectations. It is unavailable through the public comparison API.
type syntheticPreservationPort struct {
	id      platform.TreeIdentity
	mutate  func(string, *platform.MetadataObservation)
	paths   func([]platform.InventoryEntry) []platform.InventoryEntry
	content func(string, string, []byte) []byte
	closed  bool
	calls   map[string]int
}

func TestPreservationComparisonReusesScratchBeyondOldReservationCeiling(t *testing.T) {
	ctx := context.Background()
	in, _, _ := preservationFixtureExtraFiles(t, false, 7, "", 500, true)
	r, e := source.BindCanonical(ctx, in, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	a, e := Reconstruct(ctx, r, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	p, e := BindPreservationProof(ctx, r, a, PreservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	native := &syntheticPreservationPort{id: platform.TreeIdentity{SourceDigest: p.state.Digest, OperationID: "synthetic-scale", Root: platform.FileIdentity{VolumeSerial: 1, FileIndex: 1}}}
	native.paths = func(v []platform.InventoryEntry) []platform.InventoryEntry {
		for j := 0; j < 500; j++ {
			v = append(v, platform.InventoryEntry{Path: fmt.Sprintf("Windows/System32/extra-%04d", j), Status: "known", Identity: platform.FileIdentity{VolumeSerial: 1, FileIndex: uint64(100 + j)}, Attributes: 32})
		}
		return v
	}
	result, e := comparePreservation(ctx, x, native, ComparisonLimits{MaxResultBytes: 16 << 20})
	if e != nil {
		t.Fatal("permanent scratch reservation blocked 511 small entries", e)
	}
	v, e := result.Evidence(ctx, 16<<20)
	if e != nil || !v.Complete || v.EntriesObserved != 511 || v.AccountedBytes > 8<<20 {
		t.Fatal("scale evidence", v.EntriesObserved, v.AccountedBytes, e)
	}
	if _, e = comparePreservation(ctx, x, native, ComparisonLimits{MaxResultBytes: 1 << 20}); !errors.Is(e, ErrLimit) {
		t.Fatal("exhausted scratch/retained budget", e)
	}
}

func TestPreservationComparisonMissingEmptyShortNameIsUnresolved(t *testing.T) {
	x, native, _ := syntheticComparisonFixture(t)
	native.mutate = func(_ string, o *platform.MetadataObservation) {
		o.ShortName = platform.MetadataField{Status: "unsupported"}
	}
	r, e := comparePreservation(context.Background(), x, native, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := r.Evidence(context.Background(), 32<<20)
	if e != nil || v.Complete || !hasComparisonField(v, "short-name") {
		t.Fatal("missing absence observation accepted", v.Complete, e)
	}
}

func TestPreservationComparisonPrechargesNativeFailureExport(t *testing.T) {
	x, native, _ := syntheticComparisonFixture(t)
	native.paths = func(v []platform.InventoryEntry) []platform.InventoryEntry {
		v[0].Status = "failed"
		v[0].Failure = strings.Repeat("x", 64<<10)
		return v
	}
	r, e := comparePreservation(context.Background(), x, native, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Serialize(context.Background(), 512<<10); !errors.Is(e, ErrLimit) {
		t.Fatal("native cause omitted from pre-serialization bound", e)
	}
}

func TestPreservationComparisonFingerprintRechecksAllMetadataFields(t *testing.T) {
	x, _, _ := syntheticComparisonFixture(t)
	cases := map[string]func(*platform.MetadataObservation){
		"identity-volume": func(o *platform.MetadataObservation) { o.Identity.VolumeSerial++ }, "identity-file": func(o *platform.MetadataObservation) { o.Identity.FileIndex++ },
		"volume": func(o *platform.MetadataObservation) { o.VolumeSerial++ }, "file-id": func(o *platform.MetadataObservation) { o.FileID128[15]++ },
		"attributes": func(o *platform.MetadataObservation) { o.Attributes++ }, "links": func(o *platform.MetadataObservation) { o.LinkCount++ },
		"creation": func(o *platform.MetadataObservation) { o.CreationTime++ }, "access": func(o *platform.MetadataObservation) { o.AccessTime++ }, "write": func(o *platform.MetadataObservation) { o.WriteTime++ }, "change": func(o *platform.MetadataObservation) { o.ChangeTime++ },
		"stream-name": func(o *platform.MetadataObservation) { o.NamedStreams[0].Name[0]++ }, "stream-size": func(o *platform.MetadataObservation) { o.NamedStreams[0].Size++ }, "stream-allocation": func(o *platform.MetadataObservation) { o.NamedStreams[0].Allocation++ },
		"ea": func(o *platform.MetadataObservation) {
			o.ExtendedAttributes = []platform.EAObservation{{Name: []byte("X"), Flags: 0x80, Value: []byte{7}}}
		},
		"reparse-tag": func(o *platform.MetadataObservation) { o.ReparseTag++ }, "read-count": func(o *platform.MetadataObservation) { o.ReadBytes++ }, "complete": func(o *platform.MetadataObservation) { o.Complete = false },
		"short-code-units": func(o *platform.MetadataObservation) { o.ShortNameUTF16 = []uint16{'X'} },
		"slice-nil-empty":  func(o *platform.MetadataObservation) { o.ExtendedAttributes = []platform.EAObservation{} },
	}
	fields := map[string]func(*platform.MetadataObservation) *platform.MetadataField{
		"basic": func(o *platform.MetadataObservation) *platform.MetadataField { return &o.Basic }, "file-id": func(o *platform.MetadataObservation) *platform.MetadataField { return &o.FileID }, "security": func(o *platform.MetadataObservation) *platform.MetadataField { return &o.Security }, "sacl": func(o *platform.MetadataObservation) *platform.MetadataField { return &o.SACL }, "streams": func(o *platform.MetadataObservation) *platform.MetadataField { return &o.Streams }, "ea": func(o *platform.MetadataObservation) *platform.MetadataField { return &o.EAs }, "reparse": func(o *platform.MetadataObservation) *platform.MetadataField { return &o.Reparse }, "short": func(o *platform.MetadataObservation) *platform.MetadataField { return &o.ShortName },
	}
	for name, field := range fields {
		for _, part := range []string{"status", "code", "detail", "raw"} {
			cases[name+"-"+part] = func(o *platform.MetadataObservation) {
				f := field(o)
				switch part {
				case "status":
					f.Status = "changed"
				case "code":
					f.NativeCode++
				case "detail":
					f.Detail = "changed"
				case "raw":
					f.Raw = append(f.Raw, 0x37)
				}
			}
		}
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			native := &syntheticPreservationPort{id: platform.TreeIdentity{SourceDigest: x.state.ProofDigest, OperationID: "synthetic-drift", Root: platform.FileIdentity{VolumeSerial: 1, FileIndex: 1}}}
			native.mutate = func(path string, o *platform.MetadataObservation) {
				if path == "Windows/System32/named" && native.calls[path] > 1 {
					change(o)
				}
			}
			r, e := comparePreservation(context.Background(), x, native, ComparisonLimits{})
			if e != nil {
				t.Fatal(e)
			}
			v, e := r.Evidence(context.Background(), 32<<20)
			if e != nil || v.Complete || !hasComparisonField(v, "observation.drift") {
				t.Fatal("final metadata field escaped fingerprint", name, v.Complete, e)
			}
		})
	}
}

var comparisonPaths = []string{".", "Windows", "Windows/System32", "Windows/System32/ntoskrnl.exe", "Windows/System32/kernel.link", "Windows/System32/config", "Windows/System32/config/SOFTWARE", "Windows/System32/config/SYSTEM", "Windows/System32/named", "Windows/System32/empty", "Windows/System32/reparse"}

func (s *syntheticPreservationPort) Identity() platform.TreeIdentity { return s.id }
func (s *syntheticPreservationPort) CheckObservationLive(ctx context.Context) error {
	if s.closed {
		return ErrInput
	}
	return ctx.Err()
}
func (s *syntheticPreservationPort) ObserveInventory(ctx context.Context, _ platform.TreeLimits) (platform.TreeInventory, error) {
	if e := s.CheckObservationLive(ctx); e != nil {
		return platform.TreeInventory{}, e
	}
	var entries []platform.InventoryEntry
	for j, name := range comparisonPaths {
		id := uint64(j + 1)
		if j == 4 {
			id = 4
		}
		attrs := uint32(32)
		if j < 3 || j == 5 {
			attrs = 16
		}
		if j == 10 {
			attrs = 0x420
		}
		entries = append(entries, platform.InventoryEntry{Path: name, Status: "known", Identity: platform.FileIdentity{VolumeSerial: 1, FileIndex: id}, Attributes: attrs})
	}
	if s.paths != nil {
		entries = s.paths(entries)
	}
	return platform.TreeInventory{Tree: s.id, Entries: entries, ReadBytes: 128, AccountedBytes: 8192, Complete: true}, nil
}
func independentSecurity() []byte {
	// Same callback ACE, independently laid out at offset 28 (source: 40).
	return []byte{1, 0, 4, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 2, 0, 32, 0, 1, 0, 0, 0, 9, 0, 24, 0, 0x89, 0, 0x12, 0, 1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0xde, 0xad, 0xca, 0xfe}
}
func (s *syntheticPreservationPort) Observe(ctx context.Context, name string, _ platform.MetadataLimits) (platform.MetadataObservation, error) {
	if e := s.CheckObservationLive(ctx); e != nil {
		return platform.MetadataObservation{}, e
	}
	inv, _ := s.ObserveInventory(ctx, platform.TreeLimits{})
	var item platform.InventoryEntry
	for _, v := range inv.Entries {
		if v.Path == name {
			item = v
		}
	}
	if item.Path == "" {
		return platform.MetadataObservation{}, ErrInput
	}
	complete := func(raw []byte) platform.MetadataField { return platform.MetadataField{Status: "complete", Raw: raw} }
	o := platform.MetadataObservation{Identity: item.Identity, VolumeSerial: 1, Attributes: item.Attributes, LinkCount: 1, CreationTime: 123, AccessTime: 456, WriteTime: 789, Basic: complete(nil), FileID: complete(nil), Security: complete(independentSecurity()), SACL: complete([]byte{1, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), Streams: complete(nil), EAs: complete(nil), Reparse: platform.MetadataField{Status: "not-present"}, ShortName: complete(nil), Complete: true}
	binary.LittleEndian.PutUint64(o.FileID128[:8], item.Identity.FileIndex)
	if item.Identity.FileIndex == 4 {
		o.LinkCount = 2
	}
	if item.Attributes&16 == 0 && item.Attributes&0x400 == 0 {
		data := s.literalContent(name, "")
		o.NamedStreams = append(o.NamedStreams, platform.StreamObservation{Name: utf16.Encode([]rune("::$DATA")), Size: uint64(len(data))})
		if name == "Windows/System32/named" {
			o.NamedStreams = append(o.NamedStreams, platform.StreamObservation{Name: utf16.Encode([]rune(":ads:$DATA")), Size: 11})
		}
	}
	if item.Attributes&0x400 != 0 {
		b := []byte("opaque reparse bytes")
		raw := make([]byte, 8+len(b))
		binary.LittleEndian.PutUint32(raw, 0xa0000003)
		binary.LittleEndian.PutUint16(raw[4:], uint16(len(b)))
		copy(raw[8:], b)
		o.Reparse = complete(raw)
		o.ReparseTag = 0xa0000003
	}
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[name]++
	if s.mutate != nil {
		s.mutate(name, &o)
	}
	return o, nil
}
func (s *syntheticPreservationPort) literalContent(name, stream string) []byte {
	if stream == "ads" {
		return []byte("named bytes")
	}
	if name == "Windows/System32/empty" {
		return nil
	}
	return []byte("shared original")
}
func (s *syntheticPreservationPort) ReadOwnedAt(ctx context.Context, name, stream string, b []byte, off int64) (int, error) {
	if e := s.CheckObservationLive(ctx); e != nil {
		return 0, e
	}
	v := s.literalContent(name, stream)
	if s.content != nil {
		v = s.content(name, stream, v)
	}
	return bytes.NewReader(v).ReadAt(b, off)
}
func syntheticComparisonFixture(t *testing.T) (*SourceExpectations, *syntheticPreservationPort, func()) {
	t.Helper()
	p, close := expectationFixture(t, true)
	x, e := BindSourceExpectations(context.Background(), p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	if !x.Descriptor().ComparableComplete {
		t.Fatal(x.requirements)
	}
	return x, &syntheticPreservationPort{id: platform.TreeIdentity{SourceDigest: p.state.Digest, OperationID: "synthetic", Root: platform.FileIdentity{VolumeSerial: 1, FileIndex: 1}}}, close
}
func hasComparisonField(e ComparisonEvidence, field string) bool {
	for _, m := range e.Mismatches {
		if m.Field == field {
			return true
		}
	}
	for _, r := range e.Unresolved {
		if r.Field == field {
			return true
		}
	}
	return false
}

func TestPreservationComparisonShortNameRequiresExactIndependentObservation(t *testing.T) {
	ctx := context.Background()
	in, _, _ := preservationFixtureRecords(t, false, 7, "NTOSKR~1.EXE", true)
	r, e := source.BindCanonical(ctx, in, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	a, e := Reconstruct(ctx, r, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	p, e := BindPreservationProof(ctx, r, a, PreservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"matched", "missing", "changed"} {
		t.Run(kind, func(t *testing.T) {
			native := &syntheticPreservationPort{id: platform.TreeIdentity{SourceDigest: p.state.Digest, OperationID: "synthetic", Root: platform.FileIdentity{VolumeSerial: 1, FileIndex: 1}}}
			native.mutate = func(name string, o *platform.MetadataObservation) {
				o.ShortName = platform.MetadataField{Status: "complete"}
				if name == "Windows/System32/ntoskrnl.exe" {
					o.ShortNameUTF16 = utf16.Encode([]rune("NTOSKR~1.EXE"))
					if kind == "missing" {
						o.ShortName.Status = "unsupported"
					}
					if kind == "changed" {
						o.ShortNameUTF16[0] = 'X'
					}
				}
			}
			out, e := comparePreservation(ctx, x, native, ComparisonLimits{})
			if e != nil {
				t.Fatal(e)
			}
			v, e := out.Evidence(ctx, 32<<20)
			if e != nil {
				t.Fatal(e)
			}
			if v.Complete != (kind == "matched") {
				t.Fatalf("%s complete=%t unresolved=%+v mismatches=%+v", kind, v.Complete, v.Unresolved, v.Mismatches)
			}
			if kind != "matched" && !hasComparisonField(v, "short-name") {
				t.Fatal("exact name requirement lost", v)
			}
		})
	}
}

func TestPreservationComparisonIndependentNegativeWitnesses(t *testing.T) {
	x, base, _ := syntheticComparisonFixture(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name, field string
		setup       func(*syntheticPreservationPort)
	}{
		{"missing", "path", func(s *syntheticPreservationPort) {
			s.paths = func(v []platform.InventoryEntry) []platform.InventoryEntry { return v[:len(v)-1] }
		}},
		{"extra", "path", func(s *syntheticPreservationPort) {
			s.paths = func(v []platform.InventoryEntry) []platform.InventoryEntry {
				return append(v, platform.InventoryEntry{Path: "foreign", Status: "unknown"})
			}
		}},
		{"bytes", "stream[0].content", func(s *syntheticPreservationPort) {
			s.content = func(n, st string, b []byte) []byte {
				if n == "Windows/System32/ntoskrnl.exe" {
					return []byte("changed content")
				}
				return b
			}
		}},
		{"ads-bytes", "stream[1].content", func(s *syntheticPreservationPort) {
			s.content = func(n, st string, b []byte) []byte {
				if st == "ads" {
					return []byte("wrong bytes")
				}
				return b
			}
		}},
		{"ads-name", "streams.names", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) {
				if n == "Windows/System32/named" {
					o.NamedStreams[1].Name = utf16.Encode([]rune(":different:$DATA"))
				}
			}
		}},
		{"same-bytes-not-link", "hardlinks.equivalence", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) {
				if n == "Windows/System32/kernel.link" {
					o.FileID128[0] = 99
				}
			}
		}},
		{"outside-link", "hardlinks.count", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) { o.LinkCount++ }
		}},
		{"attrs", "attributes", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) { o.Attributes ^= 2 }
		}},
		{"times", "time.creation", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) { o.CreationTime++ }
		}},
		{"control", "security.control", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) { o.Security.Raw[2] ^= 1 }
		}},
		{"sacl-shared-control", "security.control", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) { o.SACL.Raw[3] |= 0x40 }
		}},
		{"callback", "security.dacl", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) { o.Security.Raw[29] = 0x40 }
		}},
		{"callback-body", "security.dacl", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) { o.Security.Raw[len(o.Security.Raw)-1] ^= 1 }
		}},
		{"owner", "security.owner", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) {
				binary.LittleEndian.PutUint32(o.Security.Raw[4:], 52)
				o.Security.Raw = append(o.Security.Raw, []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}...)
			}
		}},
		{"group", "security.group", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) {
				binary.LittleEndian.PutUint32(o.Security.Raw[8:], 52)
				o.Security.Raw = append(o.Security.Raw, []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}...)
			}
		}},
		{"sacl", "security.sacl", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) {
				o.SACL.Raw = []byte{1, 0, 16, 128, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0}
			}
		}},
		{"ea", "ea", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) {
				o.ExtendedAttributes = []platform.EAObservation{{Name: []byte("X"), Value: []byte{1}}}
			}
		}},
		{"reparse", "reparse.data", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) {
				if n == "Windows/System32/reparse" {
					o.Reparse.Raw[8] ^= 1
				}
			}
		}},
		{"denied-sacl", "native.sacl", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) {
				o.SACL = platform.MetadataField{Status: "missing-privilege", NativeCode: 1314}
				o.Complete = false
			}
		}},
		{"malformed", "native.security", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) { o.Security.Raw = o.Security.Raw[:19] }
		}},
		{"drift", "observation.drift", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) {
				if s.calls[n] > 1 {
					o.WriteTime++
				}
			}
		}},
		{"opaque-flags", "security.dacl", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) { o.Security.Raw[29] = 0x20 }
		}},
		{"unknown-control", "native.security.security-control-semantics", func(s *syntheticPreservationPort) {
			s.mutate = func(n string, o *platform.MetadataObservation) { o.Security.Raw[2] |= 0x40 }
		}},
		{"inventory-drift", "inventory.drift", func(s *syntheticPreservationPort) {
			s.paths = func(v []platform.InventoryEntry) []platform.InventoryEntry {
				if s.calls["."] > 1 {
					return append(v, platform.InventoryEntry{Path: "late", Status: "unknown"})
				}
				return v
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &syntheticPreservationPort{id: base.id}
			tc.setup(s)
			r, e := comparePreservation(ctx, x, s, ComparisonLimits{})
			if e != nil {
				t.Fatal(e)
			}
			v, e := r.Evidence(ctx, 1<<24)
			if e != nil || v.Complete || !hasComparisonField(v, tc.field) {
				t.Fatal("independent difference lost", tc.field, v, e)
			}
		})
	}
}

func TestPreservationComparisonSourceEAsAreIndependentFromNativeBytes(t *testing.T) {
	p, _ := expectationFixture(t, true, true)
	x, e := BindSourceExpectations(context.Background(), p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	if !x.state.ComparableComplete || x.state.Oracle.MetadataComplete {
		t.Fatal("original EA/callback gaps rewritten", x.state)
	}
	for _, change := range []string{"none", "name", "flags", "value"} {
		t.Run(change, func(t *testing.T) {
			s := &syntheticPreservationPort{id: platform.TreeIdentity{SourceDigest: p.state.Digest, OperationID: "synthetic", Root: platform.FileIdentity{VolumeSerial: 1, FileIndex: 1}}}
			s.mutate = func(n string, o *platform.MetadataObservation) {
				if n != "Windows/System32/named" {
					return
				}
				ea := platform.EAObservation{Name: []byte("X"), Flags: 0x80, Value: []byte{9, 8, 7}}
				switch change {
				case "name":
					ea.Name = []byte("Y")
				case "flags":
					ea.Flags = 0
				case "value":
					ea.Value[0] = 1
				}
				o.ExtendedAttributes = []platform.EAObservation{ea}
			}
			r, e := comparePreservation(context.Background(), x, s, ComparisonLimits{})
			if e != nil {
				t.Fatal(e)
			}
			v, e := r.Evidence(context.Background(), 1<<24)
			if e != nil {
				t.Fatal(e)
			}
			if change == "none" {
				if !v.Complete {
					t.Fatal(v)
				}
			} else if v.Complete || !hasComparisonField(v, "ea") {
				t.Fatal(change, v)
			}
		})
	}
}

func TestPreservationComparisonLiveCreatedB1FixtureIsIncompleteEvidence(t *testing.T) {
	ctx := context.Background()
	p, _ := expectationFixture(t, true)
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	w, e := platform.CreateWorkspace(t.TempDir(), "comparison-native-fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	tr, e := w.CreateOwnedTree("tree", "fixture", p.state.Digest, platform.TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer tr.Close()
	for _, n := range []string{"Windows", "Windows/System32", "Windows/System32/config"} {
		if e = tr.CreateDirectory(ctx, n); e != nil {
			t.Fatal(e)
		}
	}
	for _, n := range []string{"Windows/System32/ntoskrnl.exe", "Windows/System32/config/SOFTWARE", "Windows/System32/config/SYSTEM", "Windows/System32/named"} {
		if e = tr.CreateFile(ctx, n, []byte("shared original")); e != nil {
			t.Fatal(e)
		}
	}
	if e = tr.CreateHardlink(ctx, "Windows/System32/ntoskrnl.exe", "Windows/System32/kernel.link"); e != nil {
		t.Fatal(e)
	}
	if e = tr.CreateFile(ctx, "Windows/System32/empty", nil); e != nil {
		t.Fatal(e)
	}
	if e = tr.CreateNamedStream(ctx, "Windows/System32/named", "ads", []byte("named bytes")); e != nil {
		t.Fatal(e)
	}
	r, e := ComparePreservation(ctx, x, tr, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := r.Evidence(ctx, 1<<24)
	if e != nil {
		t.Fatal(e)
	}
	if v.Complete || !hasComparisonField(v, "native.sacl") || !hasComparisonField(v, "path") || v.StreamsCompared != 7 {
		t.Fatal(v)
	}
	t.Logf("ordinary created fixture: entries=%d streams=%d mismatches=%d unresolved=%d Complete=%v", v.EntriesObserved, v.StreamsCompared, len(v.Mismatches), len(v.Unresolved), v.Complete)
	if e = tr.Close(); !errors.Is(e, platform.ErrTreePreserved) {
		t.Fatal("file cleanup preservation changed", e)
	}
	if _, e = r.Serialize(ctx, 1<<24); e == nil {
		t.Fatal("closed B1 parent serialized comparison")
	}
}

func TestPreservationComparisonCompleteSyntheticStillRevokesAndBounds(t *testing.T) {
	x, s, close := syntheticComparisonFixture(t)
	ctx := context.Background()
	r, e := comparePreservation(ctx, x, s, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := r.Evidence(ctx, 1<<24)
	if e != nil || !v.Complete || v.StreamsCompared != 7 {
		t.Fatal(v, e)
	}
	if len(v.InitialInventory.Entries) != 11 || len(v.FinalInventory.Entries) != 11 {
		t.Fatal("actual inventory witness missing", v)
	}
	if _, e = r.Evidence(ctx, 0); !errors.Is(e, ErrLimit) {
		t.Fatal("result exhausted", e)
	}
	if _, e = r.Serialize(ctx, 1); !errors.Is(e, ErrLimit) {
		t.Fatal("serialization exhausted", e)
	}
	for _, l := range []ComparisonLimits{{MaxReadBytes: 1}, {MaxResultBytes: 1}, {MaxEntries: 1}, {MaxStringBytes: 1}, {MaxStreams: 1}} {
		if r, e := comparePreservation(ctx, x, s, l); r != nil || !errors.Is(e, ErrLimit) {
			t.Fatal("comparison bound", l, e)
		}
	}
	s.closed = true
	if _, e = r.Evidence(ctx, 1<<24); e == nil {
		t.Fatal("closed native result")
	}
	s.closed = false
	close()
	if _, e = r.Serialize(ctx, 1<<24); e == nil {
		t.Fatal("closed source serialized")
	}
}

func TestPreservationComparisonRetainsExactMissingAndExtraStreamNames(t *testing.T) {
	x, s, _ := syntheticComparisonFixture(t)
	s.mutate = func(n string, o *platform.MetadataObservation) {
		if n == "Windows/System32/named" {
			o.NamedStreams[1].Name = utf16.Encode([]rune(":renamed:$DATA"))
		}
	}
	r, e := comparePreservation(context.Background(), x, s, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := r.Evidence(context.Background(), 1<<24)
	if e != nil {
		t.Fatal(e)
	}
	missing, extra := false, false
	for _, m := range v.Mismatches {
		if m.Field == "streams.names" && m.Expected == ":ads:$DATA" && m.Observed == "missing" {
			missing = true
		}
		if m.Field == "streams.names" && m.Observed == ":renamed:$DATA" {
			extra = true
		}
	}
	if !missing || !extra {
		t.Fatal("exact stream name witness lost", v.Mismatches)
	}
}

func TestPreservationComparisonHardlinkWitnessRetainsBothNativeIdentities(t *testing.T) {
	x, s, _ := syntheticComparisonFixture(t)
	s.mutate = func(n string, o *platform.MetadataObservation) {
		if n == "Windows/System32/kernel.link" {
			o.FileID128[0] = 99
		}
	}
	r, e := comparePreservation(context.Background(), x, s, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := r.Evidence(context.Background(), 1<<24)
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range v.Mismatches {
		if m.Field == "hardlinks.equivalence" && len(m.ExpectedRaw) == 24 && len(m.ObservedRaw) == 24 && !bytes.Equal(m.ExpectedRaw, m.ObservedRaw) {
			return
		}
	}
	t.Fatal("native equivalence witness lost", v.Mismatches)
}

func TestPreservationComparisonEAWitnessIncludesNameFlagAndValue(t *testing.T) {
	x, s, _ := syntheticComparisonFixture(t)
	s.mutate = func(n string, o *platform.MetadataObservation) {
		if n == "Windows/System32/named" {
			o.ExtendedAttributes = []platform.EAObservation{{Name: []byte("X"), Flags: 0x80, Value: []byte{9, 8, 7}}}
		}
	}
	r, e := comparePreservation(context.Background(), x, s, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := r.Evidence(context.Background(), 1<<24)
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range v.Mismatches {
		if m.Field == "ea" && bytes.Equal(m.ObservedRaw, []byte{3, 0, 1, 0x80, 'X', 0, 9, 8, 7}) {
			return
		}
	}
	t.Fatal("EA exact name/flag/value witness lost", v.Mismatches)
}

func TestPreservationComparisonChargesOriginalMetadataRecheckBudget(t *testing.T) {
	x, s, _ := syntheticComparisonFixture(t)
	if r, e := comparePreservation(context.Background(), x, s, ComparisonLimits{MaxReadBytes: x.state.Oracle.Receipt.Size*2 - 1}); r != nil || !errors.Is(e, ErrLimit) {
		t.Fatal("comparison source rereads not precharged", e)
	}
}

func TestPreservationComparisonPartialReadDoesNotCountCompleteStream(t *testing.T) {
	x, s, _ := syntheticComparisonFixture(t)
	s.content = func(n, st string, b []byte) []byte {
		if n == "Windows/System32/ntoskrnl.exe" {
			return []byte("short")
		}
		return b
	}
	r, e := comparePreservation(context.Background(), x, s, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := r.Evidence(context.Background(), 1<<24)
	if e != nil {
		t.Fatal(e)
	}
	if v.Complete || v.StreamsCompared != 6 {
		t.Fatal("partial content counted as complete comparison", v.StreamsCompared, v.Complete)
	}
}

func TestPreservationComparisonLostNativeIdentityCannotPass(t *testing.T) {
	x, s, _ := syntheticComparisonFixture(t)
	s.mutate = func(n string, o *platform.MetadataObservation) {
		if n == "." {
			o.FileID128 = [16]byte{}
		}
	}
	r, e := comparePreservation(context.Background(), x, s, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := r.Evidence(context.Background(), 1<<24)
	if e != nil {
		t.Fatal(e)
	}
	if v.Complete || !hasComparisonField(v, "native.file-id") {
		t.Fatal("lost ID accepted", v)
	}
}

func TestPreservationComparisonRejectsForeignProofAndResultMutation(t *testing.T) {
	x, s, _ := syntheticComparisonFixture(t)
	ctx := context.Background()
	s.id.SourceDigest = "foreign"
	if r, e := comparePreservation(ctx, x, s, ComparisonLimits{}); r != nil || e == nil {
		t.Fatal("foreign source binding", e)
	}
	s.id.SourceDigest = x.state.ProofDigest
	s.content = func(n, st string, b []byte) []byte {
		if st == "ads" {
			return []byte("wrong bytes")
		}
		return b
	}
	r, e := comparePreservation(ctx, x, s, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := r.Evidence(ctx, 1<<24)
	if e != nil {
		t.Fatal(e)
	}
	v.InitialInventory.Entries[0].Path = "mutated"
	v.Mismatches[0].Expected = "mutated"
	fresh, e := r.Evidence(ctx, 1<<24)
	if e != nil || fresh.InitialInventory.Entries[0].Path == "mutated" || fresh.Mismatches[0].Expected == "mutated" {
		t.Fatal("caller changed result", e)
	}
	if _, e = r.Serialize(ctx, 1<<24); e != nil {
		t.Fatal("bounded serialization", e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = r.Serialize(canceled, 1<<24); !errors.Is(e, context.Canceled) {
		t.Fatal("canceled serialization", e)
	}
	if e = x.proof.artifact.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Evidence(ctx, 1<<24); e == nil {
		t.Fatal("closed output parent accepted")
	}
}

func TestPreservationComparisonEmptyOriginalSecurityStaysUnresolved(t *testing.T) {
	p, _ := expectationFixture(t, true, false, true)
	ctx := context.Background()
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	s := &syntheticPreservationPort{id: platform.TreeIdentity{SourceDigest: p.state.Digest, OperationID: "synthetic", Root: platform.FileIdentity{VolumeSerial: 1, FileIndex: 1}}}
	r, e := comparePreservation(ctx, x, s, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := r.Evidence(ctx, 1<<24)
	if e != nil || v.Complete || !hasComparisonField(v, "source.security") {
		t.Fatal("empty original security accepted", e)
	}
}

func TestPreservationComparisonHighBitSourceGroupAndSingletonHaveDisjointIdentity(t *testing.T) {
	ctx := context.Background()
	// The original group uses the literal full-width ID that previously collided
	// with the zero-ID SOFTWARE file at disk-order DFS ordinal 6. Build original
	// bytes before live production parsing; do not mutate an Oracle/expectation.
	in, _, _ := preservationFixtureWithHardlinkGroup(t, false, 0x8000000000000006, true)
	recipe, e := source.BindCanonical(ctx, in, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	artifact, e := Reconstruct(ctx, recipe, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := artifact.Close(); e != nil {
			t.Error(e)
		}
	})
	proof, e := BindPreservationProof(ctx, recipe, artifact, PreservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	expected, e := BindSourceExpectations(ctx, proof, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	group, e := expected.EntryAt(ctx, 3, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	singleton, e := expected.EntryAt(ctx, 6, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if group.Original.Path != "/Windows/System32/ntoskrnl.exe" || group.Original.HardlinkID != 0x8000000000000006 || group.ExpectedLinks != 2 || singleton.Original.Path != "/Windows/System32/config/SOFTWARE" || singleton.Original.HardlinkID != 0 || singleton.ExpectedLinks != 1 {
		t.Fatal("source fixture lost independent group/singleton identities")
	}
	for _, sameNative := range []bool{false, true} {
		name := "distinct native identities"
		if sameNative {
			name = "accidental native equivalence"
		}
		t.Run(name, func(t *testing.T) {
			observed := &syntheticPreservationPort{id: platform.TreeIdentity{SourceDigest: proof.state.Digest, OperationID: "synthetic", Root: platform.FileIdentity{VolumeSerial: 1, FileIndex: 1}}}
			if sameNative {
				// Three actual names of one native inode: the source hardlink pair
				// and its distinct source singleton. Link counts and equivalence
				// must each be checked independently of the equal literal bytes.
				observed.paths = func(entries []platform.InventoryEntry) []platform.InventoryEntry {
					for n := range entries {
						if entries[n].Path == "Windows/System32/config/SOFTWARE" {
							entries[n].Identity.FileIndex = 4
						}
					}
					return entries
				}
				observed.mutate = func(_ string, o *platform.MetadataObservation) {
					if o.Identity.FileIndex == 4 {
						o.LinkCount = 3
					}
				}
			}
			comparison, e := comparePreservation(ctx, expected, observed, ComparisonLimits{})
			if e != nil {
				t.Fatal(e)
			}
			evidence, e := comparison.Evidence(ctx, 1<<24)
			if e != nil {
				t.Fatal(e)
			}
			if !sameNative {
				if !evidence.Complete || len(evidence.Mismatches) != 0 || len(evidence.Unresolved) != 0 {
					t.Fatalf("distinct high-bit source group/singleton rejected: complete=%v mismatches=%+v unresolved=%+v", evidence.Complete, evidence.Mismatches, evidence.Unresolved)
				}
			} else if evidence.Complete || !hasComparisonField(evidence, "hardlinks.equivalence") || !hasComparisonField(evidence, "hardlinks.count") {
				t.Fatalf("accidental native equivalence lost independent witnesses: complete=%v mismatches=%+v", evidence.Complete, evidence.Mismatches)
			}
			if sameNative {
				wantSourceKeys := []byte{0, 6, 0, 0, 0, 0, 0, 0, 0x80, 1, 6, 0, 0, 0, 0, 0, 0, 0}
				found := false
				for _, m := range evidence.Mismatches {
					if m.Path == "/Windows/System32/config/SOFTWARE" && m.Field == "hardlinks.equivalence" && bytes.Equal(m.ExpectedRaw, wantSourceKeys) {
						found = true
					}
				}
				if !found {
					t.Fatal("source high-bit ID/singleton domain witness lost")
				}
			}
		})
	}
}
