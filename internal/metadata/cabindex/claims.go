package cabindex

import (
	"os"
	"uupbuilder/internal/metadata/wimmeta"
)

// Claim contains only bounded immutable values/counts. It is historical after
// Close; Result.Binding additionally checks the live artifact owner.
type Claim struct {
	Oracle                wimmeta.Claim
	Digest                string
	Witnesses, References int
	Verified              bool
}

func (c *Catalog) Claim() Claim {
	if c == nil || c.digest == "" {
		return Claim{}
	}
	return Claim{c.state.Oracle, c.digest, len(c.state.Witnesses), len(c.state.References), true}
}
func (c *Catalog) WitnessAt(n int) (Witness, bool) {
	if c == nil || c.digest == "" || n < 0 || n >= len(c.state.Witnesses) {
		return Witness{}, false
	}
	return c.state.Witnesses[n], true
}
func (r *Result) Binding() (Claim, error) {
	if r == nil {
		return Claim{}, ErrInput
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Claim{}, os.ErrClosed
	}
	c := r.catalog.Claim()
	if !c.Verified {
		return Claim{}, ErrInput
	}
	return c, nil
}
