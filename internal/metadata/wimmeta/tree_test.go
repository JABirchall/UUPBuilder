package wimmeta

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"unicode/utf16"
)

var le = binary.LittleEndian

// These are independent, literal format records, not output from the parser.
func diskEntry(name string, attrs uint32, child uint64) []byte {
	u := utf16.Encode([]rune(name))
	n := 102
	if len(u) != 0 {
		n += len(u)*2 + 2
	}
	b := make([]byte, (n+7)&^7)
	le.PutUint64(b, uint64(len(b)))
	le.PutUint32(b[8:], attrs)
	le.PutUint32(b[12:], 0)
	le.PutUint64(b[16:], child)
	le.PutUint64(b[40:], 123)
	le.PutUint64(b[48:], 456)
	le.PutUint64(b[56:], 789)
	le.PutUint16(b[100:], uint16(len(u)*2))
	for i, v := range u {
		le.PutUint16(b[102+i*2:], v)
	}
	return b
}
func diskStream(name string, hash byte) []byte {
	u := utf16.Encode([]rune(name))
	n := 38
	if len(u) > 0 {
		n += len(u)*2 + 2
	}
	b := make([]byte, (n+7)&^7)
	le.PutUint64(b, uint64(len(b)))
	for i := 16; i < 36; i++ {
		b[i] = hash
	}
	le.PutUint16(b[36:], uint16(len(u)*2))
	for i, v := range u {
		le.PutUint16(b[38+i*2:], v)
	}
	return b
}
func nestedFixture() []byte {
	// Prefix: 16-byte table, 20-byte self-relative descriptor, 4-byte padding.
	b := make([]byte, 40)
	le.PutUint32(b, 40)
	le.PutUint32(b[4:], 1)
	le.PutUint64(b[8:], 20)
	b[16] = 1
	le.PutUint16(b[18:], 0x8000)
	// Root 40..144, marker 144..152; children 152..400; nested list 400.
	b = append(b, diskEntry("", 16, 152)...)
	b = append(b, make([]byte, 8)...)
	b = append(b, diskEntry("Windows", 16, 400)...)
	f := diskEntry("empty", 32, 0)
	le.PutUint64(f[88:], 7)
	b = append(b, f...)
	b = append(b, make([]byte, 8)...)
	f = diskEntry("file", 32, 0)
	le.PutUint64(f[88:], 7)
	b = append(b, f...)
	b = append(b, make([]byte, 8)...)
	return b
}
func TestNestedTreeKeepsExactRecordsAndStreams(t *testing.T) {
	p, err := parseBytes(context.Background(), nestedFixture(), Limits{})
	if err != nil {
		t.Fatalf("nested metadata interpretation missing: %v", err)
	}
	s := p.state
	if len(s.Entries) != 4 || s.Entries[2].Path != "/Windows/file" || s.Entries[3].Path != "/empty" {
		t.Fatalf("wrong nested/sibling order: %+v", s.Entries)
	}
	e := s.Entries[2]
	if e.Parent != 1 || e.CreationTime != 123 || e.AccessTime != 456 || e.WriteTime != 789 || e.SecurityID != 0 || e.HardlinkID != 7 {
		t.Fatalf("lost raw dentry fields: %+v", e)
	}
	if len(e.Streams) != 1 || e.Streams[0].Kind != "data" || e.Streams[0].SizeProvenance != "metadata-empty" || !e.Streams[0].SizeKnown || e.Streams[0].Size != 0 {
		t.Fatalf("wrong empty stream: %+v", e.Streams)
	}
	if len(s.Security) != 1 || len(s.Security[0].Raw) != 20 || s.MetadataVerified {
		t.Fatal("lost security or synthetic bytes gained authority")
	}
}
func TestTreeRejectsInvalidStructureAndBudgets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
		limits Limits
		want   error
	}{
		{"cycle", func(b []byte) { le.PutUint64(b[168:], 152) }, Limits{}, ErrLayout},
		{"alias", func(b []byte) { le.PutUint64(b[288:], 400); le.PutUint32(b[280:], 16) }, Limits{}, ErrLayout},
		{"overlap", func(b []byte) { le.PutUint64(b[168:], 160) }, Limits{}, ErrLayout},
		{"unaligned-child", func(b []byte) { le.PutUint64(b[168:], 401) }, Limits{}, ErrLayout},
		{"outside-child", func(b []byte) { le.PutUint64(b[168:], ^uint64(0)-7) }, Limits{}, ErrLayout},
		{"short-entry", func(b []byte) { le.PutUint64(b[152:], 96) }, Limits{}, ErrLayout},
		{"unaligned-length", func(b []byte) { le.PutUint64(b[152:], 119) }, Limits{}, ErrLayout},
		{"security-id", func(b []byte) { le.PutUint32(b[164:], 1) }, Limits{}, ErrLayout},
		{"name-terminator", func(b []byte) { b[268] = 1 }, Limits{}, ErrLayout},
		{"entry-count", nil, Limits{MaxEntries: 2}, ErrLimit},
		{"depth", nil, Limits{MaxDepth: 1}, ErrLimit},
		{"memory", nil, Limits{MaxResultBytes: 1}, ErrLimit},
		{"variable", nil, Limits{MaxVariableBytes: 4}, ErrLimit},
		{"security-count", nil, Limits{MaxSecurity: 0, MaxSecurityBytes: 19}, ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := nestedFixture()
			if tc.mutate != nil {
				tc.mutate(b)
			}
			p, err := parseBytes(context.Background(), b, tc.limits)
			if p != nil || !errors.Is(err, tc.want) {
				t.Fatalf("accepted %s: %v", tc.name, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := parseBytes(ctx, nestedFixture(), Limits{}); p != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
}

func TestInvalidUTF16IsLosslessAndNeverBecomesAnotherPath(t *testing.T) {
	b := nestedFixture()
	le.PutUint16(b[502:], 0xd800)
	p, err := parseBytes(context.Background(), b, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	e := p.state.Entries[2]
	if e.Name[0] != 0xd800 || e.PathValid || e.Path != "" || len(p.state.Gaps) == 0 {
		t.Fatal("invalid name silently normalized", e)
	}
}

func TestRootNameAndNonzeroPaddingCannotBeSilentlyAccepted(t *testing.T) {
	b := make([]byte, 8)
	le.PutUint32(b, 8)
	r := diskEntry("root", 16, 0)
	le.PutUint32(r[12:], 0xffffffff)
	b = append(b, r...)
	b = append(b, make([]byte, 8)...)
	p, err := parseBytes(context.Background(), b, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if p.state.Entries[0].Path != "" || p.state.Entries[0].PathValid || len(p.state.Gaps) == 0 {
		t.Fatal("named root normalized into valid root path")
	}
	b = nestedFixture()
	b[142] = 1
	p, err = parseBytes(context.Background(), b, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if p.state.Entries[0].Padding[0] != 1 || len(p.state.Gaps) == 0 {
		t.Fatal("unknown nonzero padding treated as understood")
	}
}

func TestExactSiblingCollisionFailsAndCaseIsPreserved(t *testing.T) {
	for _, name := range []string{"x", "X"} {
		b := make([]byte, 8)
		le.PutUint32(b, 8)
		r := diskEntry("", 16, 120)
		le.PutUint32(r[12:], 0xffffffff)
		b = append(b, r...)
		b = append(b, make([]byte, 8)...)
		for _, v := range []string{"x", name} {
			e := diskEntry(v, 32, 0)
			le.PutUint32(e[12:], 0xffffffff)
			b = append(b, e...)
		}
		b = append(b, make([]byte, 8)...)
		p, err := parseBytes(context.Background(), b, Limits{})
		if name == "x" {
			if p != nil || !errors.Is(err, ErrLayout) {
				t.Fatal("duplicate sibling accepted", err)
			}
		} else if err != nil || p.state.Entries[2].Path != "/X" || p.state.Entries[1].Path != "/x" {
			t.Fatal("case changed", err)
		}
	}
}

func TestEndMarkerOriginalValuesAreRetained(t *testing.T) {
	b := nestedFixture()
	le.PutUint64(b[512:], 8)
	p, err := parseBytes(context.Background(), b, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.state.EndMarkers) != 3 || p.state.EndMarkers[0] != (EndMarker{144, 0}) || p.state.EndMarkers[1] != (EndMarker{512, 8}) {
		t.Fatal("original end markers lost", p.state.EndMarkers)
	}
}
