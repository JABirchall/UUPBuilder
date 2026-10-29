package wimcontent

import (
	"uupbuilder/internal/metadata/cabindex"
	"uupbuilder/internal/metadata/wimmeta"
)

// These are historical immutable values, never evidence of current readability.
// Consumers can charge actual counts and string lengths without a whole clone.
type ReferenceClaim struct {
	Oracle                       wimmeta.Claim
	Digest, WIMDigest, CABDigest string
	References                   int
	Verified, ReferenceClosure   bool
}
type ReferenceRecord struct {
	Original                   wimmeta.ReferenceClaim
	Size                       uint64
	SizeKnown, Ambiguous       bool
	WIMWitnesses, CABWitnesses int
}

func (v *ReferenceView) Claim() ReferenceClaim {
	if v == nil || v.digest == "" {
		return ReferenceClaim{}
	}
	s := v.state
	return ReferenceClaim{s.Oracle, v.digest, s.WIMDigest, s.CABDigest, len(s.References), true, s.ReferenceClosure}
}
func (v *ReferenceView) ReferenceAt(n int) (ReferenceRecord, bool) {
	if v == nil || v.digest == "" || n < 0 || n >= len(v.state.References) {
		return ReferenceRecord{}, false
	}
	r := v.state.References[n]
	return ReferenceRecord{r.Original, r.Size, r.SizeKnown, r.Ambiguous, len(r.WIM), len(r.CAB)}, true
}
func (v *ReferenceView) WIMWitnessAt(n, j int) (Witness, bool) {
	if _, ok := v.ReferenceAt(n); !ok || j < 0 || j >= len(v.state.References[n].WIM) {
		return Witness{}, false
	}
	return v.state.References[n].WIM[j], true
}
func (v *ReferenceView) CABWitnessAt(n, j int) (cabindex.Witness, bool) {
	if _, ok := v.ReferenceAt(n); !ok || j < 0 || j >= len(v.state.References[n].CAB) {
		return cabindex.Witness{}, false
	}
	return v.state.References[n].CAB[j], true
}
func (v *ReferenceView) CheckLive() error {
	if v == nil || v.digest == "" {
		return ErrInput
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.checkLive()
}
