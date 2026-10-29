package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"uupbuilder/internal/metadata/wimcontent"
)

func bindReferences(ctx context.Context, in Inputs, view wimcontent.ReferenceClaim, l Limits, accounted *uint64) ([]boundResource, error) {
	required := uint64(view.References+1) * 1024
	if required > l.MaxResultBytes-*accounted {
		return nil, ErrLimit
	}
	*accounted += required
	witnesses := 0
	var scratch uint64
	// No nested clone or JSON occurs until every scalar count/string is bounded.
	for n := 0; n < view.References; n++ {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		r, ok := in.References.ReferenceAt(n)
		original, _ := in.Oracle.ReferenceClaimAt(n)
		if !ok || r.Original != original || !r.SizeKnown || r.Size == 0 || r.WIMWitnesses+r.CABWitnesses == 0 {
			return nil, ErrInput
		}
		if r.WIMWitnesses > l.MaxWitnesses-witnesses {
			return nil, ErrLimit
		}
		witnesses += r.WIMWitnesses
		if r.CABWitnesses > l.MaxWitnesses-witnesses {
			return nil, ErrLimit
		}
		witnesses += r.CABWitnesses
		for j := 0; j < r.WIMWitnesses; j++ {
			w, ok := in.References.WIMWitnessAt(n, j)
			cost := identityCost(w.Payload)
			if !ok || cost > 32768 || len(w.SHA1) != 40 || len(w.SHA256) != 64 || w.Size != r.Size || w.SHA1 != r.Original.SHA1 {
				return nil, ErrInput
			}
			scratch = max(scratch, 4096+cost*8)
		}
		for j := 0; j < r.CABWitnesses; j++ {
			w, ok := in.References.CABWitnessAt(n, j)
			cost := identityCost(w.Payload) + uint64(len(w.Member.Name))
			if !ok || cost > 32768 || len(w.SHA1) != 40 || len(w.SHA256) != 64 || w.Size != r.Size || w.SHA1 != r.Original.SHA1 {
				return nil, ErrInput
			}
			scratch = max(scratch, 4096+cost*8)
		}
	}
	if scratch > l.MaxResultBytes-*accounted {
		return nil, ErrLimit
	}
	*accounted += scratch
	meta := in.Metadata.Receipt()
	result := make([]boundResource, 1, view.References+1)
	result[0] = boundResource{ResourceIdentity{meta.SHA1, meta.SHA256, digest(meta), meta.Size, 1}, -1}
	for n := 0; n < view.References; n++ {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		r, _ := in.References.ReferenceAt(n)
		h := sha256.New()
		enc := json.NewEncoder(h)
		enc.Encode(r)
		sha256Value := ""
		for j := 0; j < r.WIMWitnesses; j++ {
			w, _ := in.References.WIMWitnessAt(n, j)
			if sha256Value != "" && sha256Value != w.SHA256 {
				return nil, ErrIntegrity
			}
			sha256Value = w.SHA256
			if e := enc.Encode(w); e != nil {
				return nil, e
			}
		}
		for j := 0; j < r.CABWitnesses; j++ {
			w, _ := in.References.CABWitnessAt(n, j)
			if sha256Value != "" && sha256Value != w.SHA256 {
				return nil, ErrIntegrity
			}
			sha256Value = w.SHA256
			if e := enc.Encode(w); e != nil {
				return nil, e
			}
		}
		result = append(result, boundResource{ResourceIdentity{r.Original.SHA1, sha256Value, hex.EncodeToString(h.Sum(nil)), r.Size, 0}, n})
	}
	return result, nil
}
