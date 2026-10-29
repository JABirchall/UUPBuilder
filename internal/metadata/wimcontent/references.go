package wimcontent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"slices"
	"sync"
	"uupbuilder/internal/metadata/cabindex"
	"uupbuilder/internal/metadata/wimmeta"
)

type Resolution struct {
	Original             wimmeta.ReferenceClaim
	WIM                  []Witness
	CAB                  []cabindex.Witness
	Size                 uint64
	SizeKnown, Ambiguous bool
}
type ReferenceSnapshot struct {
	Oracle                                wimmeta.Claim
	WIMDigest, CABDigest                  string
	References                            []Resolution
	Unresolved                            []string
	ReadBytes, AccountedBytes             uint64
	ReferenceClosure, ConversionSupported bool
}
type contentLink struct {
	kind  string
	index int
}

// ReferenceView borrows both parents, preserves the original B3 claim verbatim,
// and owns no files. Close only revokes its own interval borrowers. A parent
// Close revokes view reads; receipts remain historical evidence of exact bytes.
type ReferenceView struct {
	mu       sync.RWMutex
	state    ReferenceSnapshot
	digest   string
	wim      *Result
	cab      *cabindex.Result
	cabClaim cabindex.Claim
	links    [][]contentLink
	closed   bool
}

func (v *ReferenceView) Snapshot() ReferenceSnapshot {
	s := v.state
	s.References = slices.Clone(s.References)
	for n := range s.References {
		s.References[n].WIM = slices.Clone(s.References[n].WIM)
		s.References[n].CAB = slices.Clone(s.References[n].CAB)
	}
	s.Unresolved = slices.Clone(s.Unresolved)
	return s
}
func (v *ReferenceView) Digest() string               { return v.digest }
func (v *ReferenceView) MarshalJSON() ([]byte, error) { return json.Marshal(v.state) }
func (v *ReferenceView) Close() error                 { v.mu.Lock(); defer v.mu.Unlock(); v.closed = true; return nil }
func (v *ReferenceView) checkLive() error {
	if v.closed {
		return os.ErrClosed
	}
	if e := v.wim.live(); e != nil {
		return e
	}
	c, e := v.cab.Binding()
	if e != nil {
		return e
	}
	if c != v.cabClaim {
		return ErrInput
	}
	return nil
}
func (v *ReferenceView) Content(reference, witness int) (*ReferenceArtifact, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if e := v.checkLive(); e != nil {
		return nil, e
	}
	if reference < 0 || reference >= len(v.links) || witness < 0 || witness >= len(v.links[reference]) {
		return nil, ErrInput
	}
	return &ReferenceArtifact{v, v.links[reference][witness]}, nil
}

type ReferenceArtifact struct {
	view *ReferenceView
	link contentLink
}

func (a *ReferenceArtifact) ReadAt(b []byte, off int64) (int, error) {
	v := a.view
	v.mu.RLock()
	defer v.mu.RUnlock()
	if e := v.checkLive(); e != nil {
		return 0, e
	}
	if a.link.kind == "wim" {
		r, e := v.wim.Content(a.link.index)
		if e != nil {
			return 0, e
		}
		return r.ReadAt(b, off)
	}
	r, e := v.cab.Content(a.link.index)
	if e != nil {
		return 0, e
	}
	return r.ReadAt(b, off)
}

// BindReferences derives a new view from live production authorities only. It
// verifies each used WIM/CAB witness's actual complete bytes, refuses conflicts,
// retains all provenance/ambiguity, and leaves original metadata gaps unchanged.
func BindReferences(ctx context.Context, r *Result, o *wimmeta.Oracle, c *cabindex.Result, limits Limits) (*ReferenceView, error) {
	if ctx == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	l, e := bounds(limits)
	if e != nil {
		return nil, e
	}
	if l.MaxBufferBytes < 64<<10 {
		return nil, ErrLimit
	}
	if e = r.live(); e != nil {
		return nil, e
	}
	claim := o.Claim()
	binding, e := c.Binding()
	if e != nil {
		return nil, e
	}
	index := r.catalog.state.Index
	if !claim.Verified || !binding.Verified || binding.Oracle != claim || claim.Receipt.Source != index.Source || claim.Receipt.ManifestDigest != index.ManifestDigest || claim.Receipt.IndexDigest != index.IndexDigest {
		return nil, ErrInput
	}
	wc, cc := len(r.catalog.state.Witnesses), binding.Witnesses
	if claim.References > l.MaxEntries || wc > l.MaxEntries || cc > l.MaxEntries-wc {
		return nil, ErrLimit
	}
	accounted := uint64(claim.References)*1024 + 4096
	charge := func(n uint64) bool {
		if n > l.MaxResultBytes-accounted {
			return false
		}
		accounted += n
		return true
	}
	if accounted > l.MaxResultBytes {
		return nil, ErrLimit
	}
	for _, w := range r.catalog.state.Witnesses {
		if !charge(4096 + identityBytes(w.Payload)*8) {
			return nil, ErrLimit
		}
	}
	for n := 0; n < cc; n++ {
		w, ok := c.Catalog().WitnessAt(n)
		if !ok || !charge(4096+identityBytes(w.Payload)*8+uint64(len(w.Member.Name))*8) {
			return nil, ErrLimit
		}
	}
	// No whole catalog/oracle Snapshot/JSON clone occurred before these caps.
	wimByHash := make(map[string][]int, wc)
	for n, w := range r.catalog.state.Witnesses {
		wimByHash[w.SHA1] = append(wimByHash[w.SHA1], n)
	}
	cabByHash := make(map[string][]int, cc)
	for n := 0; n < cc; n++ {
		w, _ := c.Catalog().WitnessAt(n)
		cabByHash[w.SHA1] = append(cabByHash[w.SHA1], n)
	}
	// Every planned complete read is checked before copying references/witnesses.
	var required uint64
	for n := 0; n < claim.References; n++ {
		ref, ok := o.ReferenceClaimAt(n)
		if !ok {
			return nil, ErrInput
		}
		for _, i := range wimByHash[ref.SHA1] {
			size := r.catalog.state.Witnesses[i].Size
			if size > l.MaxReadBytes-required {
				return nil, ErrLimit
			}
			required += size
		}
		for _, i := range cabByHash[ref.SHA1] {
			w, _ := c.Catalog().WitnessAt(i)
			if w.Size > l.MaxReadBytes-required {
				return nil, ErrLimit
			}
			required += w.Size
		}
	}
	v := &ReferenceView{state: ReferenceSnapshot{Oracle: claim, WIMDigest: r.Catalog().Digest(), CABDigest: binding.Digest, AccountedBytes: accounted}, wim: r, cab: c, cabClaim: binding}
	budget := &readBudget{limit: l.MaxReadBytes}
	for n := 0; n < claim.References; n++ {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		original, _ := o.ReferenceClaimAt(n)
		ref := Resolution{Original: original}
		seen := map[string]fingerprint{}
		var links []contentLink
		accept := func(size uint64, h256 string) error {
			if original.SizeKnown && size != original.Size {
				return ErrConflict
			}
			if e := recordFingerprint(seen, original.SHA1, fingerprint{size, h256}); e != nil {
				return e
			}
			ref.Size = size
			ref.SizeKnown = true
			return nil
		}
		for _, i := range wimByHash[original.SHA1] {
			w := r.catalog.state.Witnesses[i]
			a, e := r.Content(i)
			if e != nil {
				return nil, e
			}
			if a.Binding() != index || a.Receipt() != w {
				return nil, ErrInput
			}
			h1, h256, e := hashInterval(ctx, a, 0, w.Size, budget)
			if e != nil || h1 != w.SHA1 || h256 != w.SHA256 {
				return nil, joinIntegrity(e)
			}
			if e = accept(w.Size, h256); e != nil {
				return nil, e
			}
			ref.WIM = append(ref.WIM, w)
			links = append(links, contentLink{"wim", i})
		}
		for _, i := range cabByHash[original.SHA1] {
			w, ok := c.Catalog().WitnessAt(i)
			if !ok {
				return nil, ErrInput
			}
			a, e := c.Content(i)
			if e != nil {
				return nil, e
			}
			if a.Binding() != claim || a.Receipt() != w {
				return nil, ErrInput
			}
			h1, h256, e := hashInterval(ctx, a, 0, w.Size, budget)
			if e != nil || h1 != w.SHA1 || h256 != w.SHA256 {
				return nil, joinIntegrity(e)
			}
			if e = accept(w.Size, h256); e != nil {
				return nil, e
			}
			ref.CAB = append(ref.CAB, w)
			links = append(links, contentLink{"cab", i})
		}
		ref.Ambiguous = original.Ambiguous || len(links) > 1
		if len(links) == 0 {
			v.state.Unresolved = append(v.state.Unresolved, original.SHA1)
		}
		v.state.References = append(v.state.References, ref)
		v.links = append(v.links, links)
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e = v.checkLive(); e != nil {
		return nil, e
	}
	v.state.ReferenceClosure = len(v.state.Unresolved) == 0
	v.state.ReadBytes = budget.used
	b, e := json.Marshal(v.state)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(b)
	v.digest = hex.EncodeToString(h[:])
	return v, nil
}

var _ io.ReaderAt = (*ReferenceArtifact)(nil)
