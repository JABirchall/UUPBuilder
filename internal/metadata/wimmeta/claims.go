package wimmeta

import "uupbuilder/internal/metadata/wimindex"

// Claim and ReferenceClaim contain immutable value fields only. They avoid a
// full oracle clone when a consumer first checks its own lower allocation cap.
type Claim struct {
	Receipt          wimindex.MetadataReceipt
	Digest           string
	References       int
	Verified         bool
	Summary          Summary
	MetadataComplete bool
}
type ReferenceClaim struct {
	SHA1                 string
	Size                 uint64
	SizeKnown, Ambiguous bool
	Witnesses            int
}

func (o *Oracle) Claim() Claim {
	if o == nil || o.digest == "" || !o.state.MetadataVerified {
		return Claim{}
	}
	return Claim{Receipt: o.state.Receipt, Digest: o.digest, References: len(o.state.References), Verified: true, Summary: o.state.Summary, MetadataComplete: o.state.Complete}
}
func (o *Oracle) ReferenceClaimAt(n int) (ReferenceClaim, bool) {
	if o == nil || o.digest == "" || !o.state.MetadataVerified || n < 0 || n >= len(o.state.References) {
		return ReferenceClaim{}, false
	}
	r := o.state.References[n]
	return ReferenceClaim{r.SHA1, r.Size, r.SizeKnown, r.Ambiguous, len(r.Witnesses)}, true
}
