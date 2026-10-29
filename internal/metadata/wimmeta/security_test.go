package wimmeta

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestPublicDescriptorControlSemanticsGateCompleteness(t *testing.T) {
	for _, tc := range []struct{ control, unsupported uint16 }{
		{0x8000, 0}, {0xff3f, 0}, {0x8040, 0x0040}, {0x8080, 0x0080}, {0x80c0, 0x00c0},
	} {
		t.Run(fmt.Sprintf("0x%04x", tc.control), func(t *testing.T) {
			b := nestedFixture()
			le.PutUint16(b[18:], tc.control)
			a, idx := boundFixture(t, b, false)
			o, err := Parse(context.Background(), a, idx, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			s := o.Snapshot()
			if !s.MetadataVerified || s.ContentVerified || s.ConversionSupported || !bytes.Equal(s.Security[0].Raw, b[16:36]) {
				t.Fatal("descriptor bytes or verification boundary changed")
			}
			if tc.unsupported == 0 {
				if !s.Complete || len(s.Gaps) != 0 {
					t.Fatal("documented controls misclassified", s.Gaps)
				}
				return
			}
			if s.Complete || len(s.Gaps) != 1 || s.Gaps[0].Kind != "security-control-semantics" || s.Gaps[0].Offset != 18 {
				t.Fatalf("unsupported control %#04x counted complete or unresolved inventory lost: complete=%v gaps=%+v", tc.control, s.Complete, s.Gaps)
			}
			if s.Gaps[0].Detail != fmt.Sprintf("security=0 unsupported-control=0x%04x", tc.unsupported) {
				t.Fatal("unsupported original control bits not identified", s.Gaps[0])
			}
		})
	}
}

func securityFixture(aceType byte) []byte {
	// Relative descriptor: owner SID at 20, DACL at 32, one ACE at 40.
	d := make([]byte, 60)
	d[0] = 1
	le.PutUint16(d[2:], 0x8004)
	le.PutUint32(d[4:], 20)
	le.PutUint32(d[16:], 32)
	d[20] = 1
	d[21] = 1
	d[27] = 5
	le.PutUint32(d[28:], 18)
	d[32] = 2
	le.PutUint16(d[34:], 28)
	le.PutUint16(d[36:], 1)
	d[40] = aceType
	le.PutUint16(d[42:], 20)
	le.PutUint32(d[44:], 0x120089)
	d[48] = 1
	d[49] = 1
	d[55] = 5
	le.PutUint32(d[56:], 32)
	b := make([]byte, 80)
	le.PutUint32(b, 80)
	le.PutUint32(b[4:], 1)
	le.PutUint64(b[8:], 60)
	copy(b[16:], d)
	b = append(b, diskEntry("", 16, 0)...)
	b = append(b, make([]byte, 8)...)
	return b
}
func TestSecurityStructureAndUnknownACEArePreserved(t *testing.T) {
	for _, typ := range []byte{0, 3, 9, 0xfe} {
		p, err := parseBytes(context.Background(), securityFixture(typ), Limits{})
		if err != nil {
			t.Fatal(err)
		}
		s := p.state.Security[0]
		if len(s.Raw) != 60 || s.Raw[40] != typ || s.Owner.Offset != 20 || len(s.Owner.Raw) != 12 || len(s.DACL.ACEs) != 1 || s.DACL.ACEs[0].Type != typ {
			t.Fatal("security structure discarded", s)
		}
		if typ != 0 && len(p.state.Gaps) == 0 {
			t.Fatal("unknown ACE treated as understood")
		}
	}
}

func TestShortNamesAndMalformedExtraStreams(t *testing.T) {
	base := func() []byte {
		b := make([]byte, 8)
		le.PutUint32(b, 8)
		r := diskEntry("", 16, 120)
		le.PutUint32(r[12:], 0xffffffff)
		b = append(b, r...)
		return append(b, make([]byte, 8)...)
	}
	e := diskEntry("x", 32, 0)
	e = append(e, make([]byte, 8)...)
	le.PutUint64(e, 120)
	le.PutUint32(e[12:], 0xffffffff)
	le.PutUint16(e[98:], 6)
	for i, v := range []uint16{'X', '~', '1'} {
		le.PutUint16(e[106+i*2:], v)
	}
	b := append(base(), e...)
	b = append(b, make([]byte, 8)...)
	p, err := parseBytes(context.Background(), b, Limits{})
	if err != nil || len(p.state.Entries[1].ShortName) != 3 || p.state.Entries[1].ShortName[1] != '~' {
		t.Fatal("short name lost", err)
	}
	for _, change := range []func([]byte){func(b []byte) { le.PutUint64(b[232:], 32) }, func(b []byte) { le.PutUint64(b[232:], 41) }, func(b []byte) { le.PutUint16(b[268:], 3) }, func(b []byte) { b[276] = 1 }} {
		e = diskEntry("x", 32, 0)
		le.PutUint32(e[12:], 0xffffffff)
		le.PutUint16(e[96:], 1)
		b = append(base(), e...)
		b = append(b, diskStream("ads", 1)...)
		b = append(b, make([]byte, 8)...)
		change(b)
		if p, err := parseBytes(context.Background(), b, Limits{}); p != nil || !errors.Is(err, ErrLayout) {
			t.Fatal("malformed extra stream accepted", err)
		}
	}
}

func TestUnknownACEAndReparseFlagsRemainUnresolved(t *testing.T) {
	b := securityFixture(0)
	b[57] = 0x20
	p, err := parseBytes(context.Background(), b, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if p.state.Security[0].DACL.ACEs[0].Understood || len(p.state.Gaps) == 0 {
		t.Fatal("reserved ACE flag treated as understood")
	}
	b = nestedFixture()
	le.PutUint32(b[408:], 0x420)
	le.PutUint16(b[494:], 2)
	p, err = parseBytes(context.Background(), b, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range p.state.Gaps {
		if g.Kind == "reparse-semantics" {
			found = true
		}
	}
	if !found {
		t.Fatal("unknown reparse flag treated as understood")
	}
}
func TestSecurityRejectsInvalidExtents(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{
		{"relative", func(b []byte) { le.PutUint16(b[18:], 4) }},
		{"owner", func(b []byte) { le.PutUint32(b[20:], 59) }},
		{"SID-count", func(b []byte) { b[37] = 15 }},
		{"SID-revision", func(b []byte) { b[36] = 2 }},
		{"ACL-offset", func(b []byte) { le.PutUint32(b[32:], 64) }},
		{"ACL-length", func(b []byte) { le.PutUint16(b[50:], 40) }},
		{"ACE-count", func(b []byte) { le.PutUint16(b[52:], 2) }},
		{"ACE-length", func(b []byte) { le.PutUint16(b[58:], 24) }},
		{"ACE-SID", func(b []byte) { b[65] = 15 }},
		{"prefix-size", func(b []byte) { le.PutUint64(b[8:], 1000) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := securityFixture(0)
			tc.change(b)
			if p, err := parseBytes(context.Background(), b, Limits{}); p != nil || !errors.Is(err, ErrLayout) {
				t.Fatal("invalid security accepted", err)
			}
		})
	}
}

func TestExtraStreamsReparseAndTaggedMetadata(t *testing.T) {
	b := make([]byte, 8)
	le.PutUint32(b, 8)
	r := diskEntry("", 16, 120)
	le.PutUint32(r[12:], 0xffffffff)
	b = append(b, r...)
	b = append(b, make([]byte, 8)...)
	e := diskEntry("link", 0x420, 0)
	le.PutUint32(e[12:], 0xffffffff)
	le.PutUint32(e[88:], 0xa000000c)
	le.PutUint16(e[94:], 1)
	le.PutUint16(e[96:], 3)
	// One unknown tagged item follows the names/alignment.
	x := make([]byte, 16)
	le.PutUint32(x, 0x7777)
	le.PutUint32(x[4:], 3)
	copy(x[8:], []byte{1, 2, 3})
	e = append(e, x...)
	le.PutUint64(e, uint64(len(e)))
	b = append(b, e...)
	b = append(b, diskStream("", 1)...)
	b = append(b, diskStream("", 0)...)
	b = append(b, diskStream("ads", 2)...)
	b = append(b, make([]byte, 8)...)
	p, err := parseBytes(context.Background(), b, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	e1 := p.state.Entries[1]
	if e1.ReparseTag != 0xa000000c || e1.ReparseFlags != 1 || e1.HardlinkID != 0 || len(e1.Tags) != 1 || string(e1.Tags[0].Data) != "\x01\x02\x03" || e1.Tags[0].Offset != 232 {
		t.Fatal("lost reparse/tag data", e1)
	}
	if len(e1.Streams) != 4 || e1.Streams[0].Kind != "unused-main" || e1.Streams[1].Kind != "reparse" || e1.Streams[2].Kind != "data" || e1.Streams[3].Kind != "named-data" || e1.Streams[1].SizeKnown || !e1.Streams[2].SizeKnown {
		t.Fatal("wrong stream semantics", e1.Streams)
	}
}

func TestIndependentRecordAndVariableFieldCountCeilings(t *testing.T) {
	b := nestedFixture()
	le.PutUint32(b[4:], 2)
	if p, err := parseBytes(context.Background(), b, Limits{MaxSecurity: 1}); p != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("security count ceiling", err)
	}
	b = securityFixture(0)
	le.PutUint16(b[18:], 0x8014)
	le.PutUint32(b[28:], 32)
	if p, err := parseBytes(context.Background(), b, Limits{MaxACEs: 1}); p != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("ACE count ceiling", err)
	}
	if p, err := parseBytes(context.Background(), nestedFixture(), Limits{MaxStreams: 3}); p != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("stream count ceiling", err)
	}
	b = make([]byte, 8)
	le.PutUint32(b, 8)
	r := diskEntry("", 16, 0)
	le.PutUint32(r[12:], 0xffffffff)
	x := make([]byte, 16)
	le.PutUint32(x, 77)
	le.PutUint32(x[8:], 78)
	r = append(r, x...)
	le.PutUint64(r, uint64(len(r)))
	b = append(b, r...)
	b = append(b, make([]byte, 8)...)
	if p, err := parseBytes(context.Background(), b, Limits{MaxExtraFields: 1}); p != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("extra metadata count ceiling", err)
	}
}
