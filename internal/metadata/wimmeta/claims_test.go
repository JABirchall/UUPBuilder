package wimmeta

import (
	"context"
	"testing"
)

func TestValueClaimsRequireLiveVerifiedOracleAndCannotMutateIt(t *testing.T) {
	for _, o := range []*Oracle{nil, {}, {digest: "asserted"}} {
		if c := o.Claim(); c.Verified {
			t.Fatal("unverified oracle published claim")
		}
		if _, ok := o.ReferenceClaimAt(0); ok {
			t.Fatal("unverified reference")
		}
	}
	a, idx := boundFixture(t, nestedFixture(), false)
	o, e := Parse(context.Background(), a, idx, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	c := o.Claim()
	if !c.Verified || c.Digest != o.Digest() || c.References != o.Summary().References {
		t.Fatal("live claim incomplete", c)
	}
	if _, ok := o.ReferenceClaimAt(-1); ok {
		t.Fatal("negative reference")
	}
	if _, ok := o.ReferenceClaimAt(c.References); ok {
		t.Fatal("out of range")
	}
	if c.References > 0 {
		r, ok := o.ReferenceClaimAt(0)
		if !ok {
			t.Fatal("missing reference")
		}
		r.SHA1 = "mutated"
		r2, _ := o.ReferenceClaimAt(0)
		if r2.SHA1 == r.SHA1 {
			t.Fatal("reference aliases state")
		}
	}
	c.Receipt.Payload.Provenance.Name = "mutated"
	if o.Claim().Receipt.Payload.Provenance.Name == "mutated" {
		t.Fatal("receipt aliases state")
	}
}
