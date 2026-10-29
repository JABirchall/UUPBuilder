package wimmeta

import (
	"context"
	"errors"
	"testing"
)

// A missing pre-copy charge or shallow nested clone must break this test.
func TestOriginalRecordsBoundCopiesAndKeepOracleUnchanged(t *testing.T) {
	a, idx := boundFixture(t, securityFixture(9), false)
	o, err := Parse(context.Background(), a, idx, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	c := o.RecordCounts()
	if c.Entries < 1 || c.Security != 1 || c.Gaps < 1 || c.MaxStringBytes != 2 {
		t.Fatal(c)
	}
	if _, _, err = o.EntryAt(0, 0); !errors.Is(err, ErrLimit) {
		t.Fatal("zero copy budget accepted", err)
	}
	e, cost, err := o.EntryAt(0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = o.EntryAt(0, cost-1); !errors.Is(err, ErrLimit) {
		t.Fatal("entry residual accepted", err)
	}
	e.Streams[0].SHA1 = "caller mutation"
	e2, _, _ := o.EntryAt(0, cost)
	if e2.Streams[0].SHA1 == "caller mutation" {
		t.Fatal("entry aliases oracle")
	}
	s, cost, err := o.SecurityAt(0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = o.SecurityAt(0, cost-1); !errors.Is(err, ErrLimit) {
		t.Fatal("security residual accepted", err)
	}
	s.Raw[0] = 7
	s.DACL.ACEs[0].SID.Raw[0] = 7
	s2, _, _ := o.SecurityAt(0, cost)
	if s2.Raw[0] != 1 || s2.DACL.ACEs[0].SID.Raw[0] != 1 {
		t.Fatal("security aliases oracle")
	}
	for _, invalid := range []*Oracle{nil, {}, {digest: "asserted"}} {
		if invalid.RecordCounts().Entries != 0 {
			t.Fatal("zero producer counts")
		}
		if _, _, err = invalid.EntryAt(0, 1<<20); !errors.Is(err, ErrInput) {
			t.Fatal("unverified record", err)
		}
	}
	if _, _, err = o.EntryAt(c.Entries, 1<<20); !errors.Is(err, ErrInput) {
		t.Fatal("out of range", err)
	}
	if o.Claim().MetadataComplete {
		t.Fatal("callback gap silently closed")
	}
}
