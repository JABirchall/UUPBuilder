package engine

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf16"

	"uupbuilder/internal/engine/source"
	"uupbuilder/internal/metadata/wimmeta"
	"uupbuilder/internal/model"
)

// ComparisonLimits bound component data only. Public zero selects ceilings;
// internal residuals never pass through this defaulting function.
type ComparisonLimits struct {
	MaxEntries, MaxSecurity, MaxStreams, MaxRequirements, MaxStringBytes int
	MaxReadBytes, MaxResultBytes, MaxSerializationBytes                  uint64
}

func comparisonBounds(l ComparisonLimits) (ComparisonLimits, error) {
	for j, p := range []*int{&l.MaxEntries, &l.MaxSecurity, &l.MaxStreams, &l.MaxRequirements, &l.MaxStringBytes} {
		cap := []int{262144, 65536, 524288, 262144, 1 << 20}[j]
		if *p < 0 || *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	for j, p := range []*uint64{&l.MaxReadBytes, &l.MaxResultBytes, &l.MaxSerializationBytes} {
		cap := []uint64{64 << 30, 512 << 20, 512 << 20}[j]
		if *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	return l, nil
}

type FieldRequirement struct {
	Entry               int
	Path, Field, Detail string
	Offset              uint64
}
type EntryExpectation struct {
	Original      wimmeta.Entry
	Content       []source.ResourceIdentity // Original stream ordinal, including placeholders.
	EAs           []wimmeta.SourceEA
	ReparseData   []byte // Exact original blob, without the native 8-byte header.
	ExpectedLinks uint32
}
type ExpectationDescriptor struct {
	ProofDigest                                 string
	Oracle                                      wimmeta.Claim // Original completeness/gaps remain unchanged.
	Entries, Security, OriginalGaps, Unresolved int
	AccountedBytes, ReadBytes                   uint64
	ComparableComplete                          bool
}

// SourceExpectations is immutable and borrows the exact live sealed proof.
// It is comparison input, never descendant admission or a production capability.
type SourceExpectations struct {
	proof        *PreservationProof
	state        ExpectationDescriptor
	entries      []EntryExpectation
	security     []wimmeta.Security
	gaps         []wimmeta.Gap
	requirements []FieldRequirement
	limits       ComparisonLimits
}

func expectationError(e error) error {
	if errors.Is(e, wimmeta.ErrLimit) {
		return errors.Join(ErrLimit, e)
	}
	return e
}

// Callers precharge the exact declared size. This rereads only B1's fixed
// original-resource capability; no arbitrary reader/path/hash is accepted.
func verifyOriginalMetadata(ctx context.Context, p *PreservationProof) error {
	id, r, e := p.OriginalMetadata()
	if e != nil {
		return e
	}
	if len(p.state.Resources) == 0 || id != p.state.Resources[0] || id.Size != p.state.Source.Metadata.Size {
		return ErrInput
	}
	h1, h256 := sha1.New(), sha256.New()
	var b [64 << 10]byte
	for off := uint64(0); off < id.Size; {
		if e = ctx.Err(); e != nil {
			return e
		}
		n := min(uint64(len(b)), id.Size-off)
		got, e := r.ReadAt(b[:n], int64(off))
		if e != nil || uint64(got) != n {
			return errors.Join(source.ErrIntegrity, e)
		}
		h1.Write(b[:n])
		h256.Write(b[:n])
		off += n
	}
	if hex.EncodeToString(h1.Sum(nil)) != id.SHA1 || hex.EncodeToString(h256.Sum(nil)) != id.SHA256 {
		return source.ErrIntegrity
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	return p.CheckLive()
}

func (x *SourceExpectations) CheckLive() error {
	if x == nil || x.proof == nil || x.state.ProofDigest == "" || x.state.ProofDigest != x.proof.state.Digest {
		return ErrInput
	}
	return x.proof.CheckLive()
}
func (x *SourceExpectations) Descriptor() ExpectationDescriptor {
	if x == nil {
		return ExpectationDescriptor{}
	}
	return x.state
}

func (x *SourceExpectations) SecurityAt(ctx context.Context, n int, allowance uint64) (wimmeta.Security, error) {
	if ctx == nil {
		return wimmeta.Security{}, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return wimmeta.Security{}, expectationError(e)
	}
	if e := x.CheckLive(); e != nil {
		return wimmeta.Security{}, e
	}
	s, _, e := x.proof.recipe.OriginalSecurityAt(n, allowance)
	if e != nil {
		return wimmeta.Security{}, expectationError(e)
	}
	if e = x.CheckLive(); e != nil {
		return wimmeta.Security{}, e
	}
	return s, ctx.Err()
}
func (x *SourceExpectations) OriginalGapAt(ctx context.Context, n int, allowance uint64) (wimmeta.Gap, error) {
	if ctx == nil {
		return wimmeta.Gap{}, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return wimmeta.Gap{}, expectationError(e)
	}
	if e := x.CheckLive(); e != nil {
		return wimmeta.Gap{}, e
	}
	g, _, e := x.proof.recipe.OriginalGapAt(n, allowance)
	if e != nil {
		return wimmeta.Gap{}, expectationError(e)
	}
	if e = x.CheckLive(); e != nil {
		return wimmeta.Gap{}, e
	}
	return g, ctx.Err()
}
func (x *SourceExpectations) EntryAt(ctx context.Context, n int, allowance uint64) (EntryExpectation, error) {
	if ctx == nil {
		return EntryExpectation{}, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return EntryExpectation{}, e
	}
	if e := x.CheckLive(); e != nil {
		return EntryExpectation{}, e
	}
	if n < 0 || n >= len(x.entries) {
		return EntryExpectation{}, ErrInput
	}
	v := x.entries[n]
	extra := uint64(1024 + len(v.Content)*512 + len(v.ReparseData)*2)
	for _, ea := range v.EAs {
		extra += uint64(128 + (len(ea.Name)+len(ea.Value))*2)
	}
	if extra > allowance {
		return EntryExpectation{}, ErrLimit
	}
	en, _, e := x.proof.recipe.OriginalEntryAt(n, allowance-extra)
	if e != nil {
		return EntryExpectation{}, expectationError(e)
	}
	v.Original = en
	v.Content = slices.Clone(v.Content)
	v.ReparseData = slices.Clone(v.ReparseData)
	v.EAs = slices.Clone(v.EAs)
	for j := range v.EAs {
		v.EAs[j].Name = slices.Clone(v.EAs[j].Name)
		v.EAs[j].Value = slices.Clone(v.EAs[j].Value)
	}
	if e = x.CheckLive(); e != nil {
		return EntryExpectation{}, e
	}
	return v, ctx.Err()
}
func (x *SourceExpectations) ReadOriginalAt(ctx context.Context, entry, stream int, b []byte, off int64) (int, error) {
	if ctx == nil {
		return 0, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	if e := x.CheckLive(); e != nil {
		return 0, e
	}
	if len(b) > 64<<10 {
		return 0, ErrLimit
	}
	if entry < 0 || entry >= len(x.entries) || stream < 0 || stream >= len(x.entries[entry].Original.Streams) || off < 0 {
		return 0, ErrInput
	}
	s := x.entries[entry].Original.Streams[stream]
	if s.Reference < 0 {
		if len(b) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	id, r, e := x.proof.recipe.Resource(s.Reference + 1)
	if e != nil {
		return 0, e
	}
	if id != x.entries[entry].Content[stream] {
		return 0, ErrInput
	}
	n, e := r.ReadAt(b, off)
	if live := x.CheckLive(); live != nil {
		return 0, live
	}
	if ce := ctx.Err(); ce != nil {
		return 0, ce
	}
	return n, e
}

func BindSourceExpectations(ctx context.Context, p *PreservationProof, limits ComparisonLimits) (result *SourceExpectations, runErr error) {
	defer func() { runErr = expectationError(runErr) }()
	if ctx == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := p.CheckLive(); e != nil {
		return nil, e
	}
	l, e := comparisonBounds(limits)
	if e != nil {
		return nil, e
	}
	claim, counts, e := p.recipe.OriginalRecords()
	if e != nil {
		return nil, e
	}
	if claim != p.state.Source.Oracle || counts.Entries < 1 || counts.Entries > l.MaxEntries || counts.Security > l.MaxSecurity || claim.Summary.Streams > l.MaxStreams || counts.Gaps > l.MaxRequirements || counts.MaxStringBytes > l.MaxStringBytes {
		return nil, ErrLimit
	}
	if p.state.Source.Metadata.Size > l.MaxReadBytes/2 {
		return nil, ErrLimit
	}
	base := uint64((128 << 10) + 8192 + counts.Entries*256 + counts.Security*128 + counts.Gaps*128)
	if base > l.MaxResultBytes {
		return nil, ErrLimit
	}
	if e = verifyOriginalMetadata(ctx, p); e != nil {
		return nil, e
	}
	x := &SourceExpectations{proof: p, limits: l, state: ExpectationDescriptor{ProofDigest: p.state.Digest, Oracle: claim, Entries: counts.Entries, Security: counts.Security, OriginalGaps: counts.Gaps, AccountedBytes: base}}
	x.entries = make([]EntryExpectation, 0, counts.Entries)
	x.security = make([]wimmeta.Security, 0, counts.Security)
	x.gaps = make([]wimmeta.Gap, 0, counts.Gaps)
	charge := func(n uint64) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if n > l.MaxResultBytes-x.state.AccountedBytes {
			return ErrLimit
		}
		x.state.AccountedBytes += n
		return nil
	}
	require := func(entry int, path, field, detail string, off uint64) error {
		if len(x.requirements) >= l.MaxRequirements || len(path) > l.MaxStringBytes || len(detail) > l.MaxStringBytes {
			return ErrLimit
		}
		if e := charge(uint64(512 + (len(path)+len(field)+len(detail))*2)); e != nil {
			return e
		}
		x.requirements = append(x.requirements, FieldRequirement{entry, path, field, detail, off})
		return nil
	}
	for n := 0; n < counts.Security; n++ {
		s, c, e := p.recipe.OriginalSecurityAt(n, l.MaxResultBytes-x.state.AccountedBytes)
		if e != nil {
			return nil, e
		}
		x.state.AccountedBytes += c
		x.security = append(x.security, s)
	}
	links := map[uint64]uint32{}
	for n := 0; n < counts.Entries; n++ {
		en, c, e := p.recipe.OriginalEntryAt(n, l.MaxResultBytes-x.state.AccountedBytes)
		if e != nil {
			return nil, e
		}
		x.state.AccountedBytes += c
		if len(en.Path) > l.MaxStringBytes || len(en.Name)*2 > l.MaxStringBytes || len(en.ShortName)*2 > l.MaxStringBytes {
			return nil, ErrLimit
		}
		if e = charge(uint64(512 + len(en.Streams)*512)); e != nil {
			return nil, e
		}
		v := EntryExpectation{Original: en, Content: make([]source.ResourceIdentity, len(en.Streams))}
		if !en.PathValid {
			if e = require(n, en.Path, "path", "original UTF-16 path cannot be represented", en.Offset); e != nil {
				return nil, e
			}
		}
		if en.PathValid && en.Path != "/" {
			if _, pathErr := model.ValidateRelativePath(strings.TrimPrefix(en.Path, "/")); pathErr != nil {
				if e = require(n, en.Path, "path.native", "source path has no supported held native name", en.Offset); e != nil {
					return nil, e
				}
			}
		}
		if len(en.ShortName) > 0 {
			if e = require(n, en.Path, "short-name", "native short-name observation unavailable", en.Offset); e != nil {
				return nil, e
			}
		}
		if en.SecurityID == 0xffffffff {
			if e = require(n, en.Path, "security", "source has no recorded descriptor; inheritance cannot be invented", en.Offset); e != nil {
				return nil, e
			}
		}
		if en.Attributes&16 == 0 {
			v.ExpectedLinks = 1
			if en.HardlinkID != 0 {
				links[en.HardlinkID]++
			}
		}
		for j, s := range en.Streams {
			if len(s.Name)*2 > l.MaxStringBytes {
				return nil, ErrLimit
			}
			switch s.Kind {
			case "data", "named-data", "directory-placeholder", "unused-main", "reparse":
			default:
				if e = require(n, en.Path, "source.stream-role", s.Kind, s.Offset); e != nil {
					return nil, e
				}
			}
			if len(s.Name) > 0 {
				if e = charge(uint64(len(s.Name)*8 + 128)); e != nil {
					return nil, e
				}
				if strings.ContainsRune(string(utf16.Decode(s.Name)), ':') {
					if e = require(n, en.Path, "stream.name", "source stream name cannot use the held native reader", s.Offset); e != nil {
						return nil, e
					}
				}
			}
			if s.SHA1 == "0000000000000000000000000000000000000000" {
				h := sha256.Sum256(nil)
				v.Content[j] = source.ResourceIdentity{SHA1: s.SHA1, SHA256: hex.EncodeToString(h[:])}
				continue
			}
			id, _, e := p.recipe.Resource(s.Reference + 1)
			if e != nil {
				return nil, e
			}
			if id.SHA1 != s.SHA1 || !s.SizeKnown || id.Size != s.Size {
				return nil, ErrInput
			}
			v.Content[j] = id
		}
		eaTags := 0
		for _, tag := range en.Tags {
			if tag.Tag == 2 {
				eaTags++
			}
		}
		for _, tag := range en.Tags {
			if tag.Tag != 2 {
				continue
			}
			if eaTags != 1 {
				if e = require(n, en.Path, "ea.source", "duplicate source tag-2 records", tag.Offset); e != nil {
					return nil, e
				}
				continue
			}
			eas, c, parseErr := wimmeta.DecodeSourceEAs(ctx, tag.Data, min(l.MaxRequirements, 65536), l.MaxResultBytes-x.state.AccountedBytes)
			if errors.Is(parseErr, wimmeta.ErrLimit) {
				return nil, ErrLimit
			}
			if parseErr != nil {
				if e = require(n, en.Path, "ea.source", "malformed source tag-2 EA framing", tag.Offset); e != nil {
					return nil, e
				}
				continue
			}
			x.state.AccountedBytes += c
			v.EAs = eas
			if e = charge(uint64(len(eas)*128 + 128)); e != nil {
				return nil, e
			}
			eaNames := make(map[string]bool, len(eas))
			for _, ea := range eas {
				key := string(ea.Name)
				if eaNames[key] {
					if e = require(n, en.Path, "ea.source", "duplicate source EA name", tag.Offset+uint64(ea.Offset)); e != nil {
						return nil, e
					}
				}
				eaNames[key] = true
				if ea.Flags&^byte(0x80) != 0 {
					if e = require(n, en.Path, "ea.flags", "unsupported source EA flag bits", tag.Offset+uint64(ea.Offset)); e != nil {
						return nil, e
					}
				}
			}
		}
		x.entries = append(x.entries, v)
	}
	for n := range x.entries {
		v := &x.entries[n]
		if v.Original.Attributes&16 == 0 && v.Original.HardlinkID != 0 {
			v.ExpectedLinks = links[v.Original.HardlinkID]
		}
	}
	for n := 0; n < counts.Gaps; n++ {
		g, c, e := p.recipe.OriginalGapAt(n, l.MaxResultBytes-x.state.AccountedBytes)
		if e != nil {
			return nil, e
		}
		x.state.AccountedBytes += c
		x.gaps = append(x.gaps, g)
		// Raw ACE preservation does not evaluate conditions. Supported tag-2
		// framing is interpreted separately without rewriting the source Oracle.
		if g.Kind == "ace-semantics" {
			continue
		}
		if g.Kind == "tag-semantics" && g.Entry >= 0 && g.Entry < len(x.entries) {
			matched := false
			for _, tag := range x.entries[g.Entry].Original.Tags {
				if tag.Offset == g.Offset && tag.Tag == 2 {
					matched = true
				}
			}
			if matched {
				continue
			}
		}
		path := ""
		if g.Entry >= 0 && g.Entry < len(x.entries) {
			path = x.entries[g.Entry].Original.Path
		}
		if e = require(g.Entry, path, "source."+g.Kind, g.Detail, g.Offset); e != nil {
			return nil, e
		}
	}
	read := p.state.Source.Metadata.Size * 2
	for n := range x.entries {
		for j, s := range x.entries[n].Original.Streams {
			if s.Kind != "reparse" {
				continue
			}
			if s.Size > 16376 {
				if e = require(n, x.entries[n].Original.Path, "reparse.source", "source reparse data exceeds native framing limit", s.Offset); e != nil {
					return nil, e
				}
				continue
			}
			if s.Size > l.MaxReadBytes-read {
				return nil, ErrLimit
			}
			read += s.Size
			if e = charge(s.Size * 2); e != nil {
				return nil, e
			}
			b := make([]byte, int(s.Size))
			if len(b) > 0 {
				if got, e := x.ReadOriginalAt(ctx, n, j, b, 0); e != nil || got != len(b) {
					return nil, errors.Join(ErrInput, e)
				}
			}
			h := sha256.Sum256(b)
			if hex.EncodeToString(h[:]) != x.entries[n].Content[j].SHA256 {
				return nil, source.ErrIntegrity
			}
			x.entries[n].ReparseData = b
		}
	}
	x.state.Unresolved = len(x.requirements)
	x.state.ComparableComplete = len(x.requirements) == 0
	x.state.ReadBytes = read
	if e = verifyOriginalMetadata(ctx, p); e != nil {
		return nil, e
	}
	if e = x.CheckLive(); e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	return x, nil
}
