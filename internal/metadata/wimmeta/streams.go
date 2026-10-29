package wimmeta

import (
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"

	"uupbuilder/internal/metadata/wimindex"
)

const zeroHash = "0000000000000000000000000000000000000000"

func (p *parser) readStreams(e *Entry, main []byte, count int, off uint64) (uint64, error) {
	if count+1 > p.limits.MaxStreamsPerEntry || count+1 > p.limits.MaxStreams-p.streams {
		return 0, ErrLimit
	}
	if err := p.reserve(uint64(count+1) * 512); err != nil {
		return 0, err
	}
	e.Streams = make([]Stream, 0, count+1)
	e.Streams = append(e.Streams, Stream{Offset: e.Offset + 64, SHA1: hex.EncodeToString(main), Reference: -1, Kind: "unused-main"})
	for i := 0; i < count; i++ {
		if err := p.ctx.Err(); err != nil {
			return 0, err
		}
		if off&7 != 0 || off > uint64(len(p.data)) || uint64(len(p.data))-off < 38 {
			return 0, ErrLayout
		}
		n := disk.Uint64(p.data[off:])
		if n < 38 || n&7 != 0 || n > uint64(len(p.data))-off {
			return 0, ErrLayout
		}
		if err := p.take(off, n); err != nil {
			return 0, err
		}
		b := p.data[off : off+n]
		s := Stream{Offset: off, Length: n, Reserved: disk.Uint64(b[8:]), SHA1: hex.EncodeToString(b[16:36]), Reference: -1}
		var err error
		var at int
		s.Name, at, err = p.name(b, 38, int(disk.Uint16(b[36:])))
		if err != nil {
			return 0, err
		}
		s.Padding, err = p.field(b[at:])
		if err != nil {
			return 0, err
		}
		if len(s.Name) > 0 {
			s.Kind = "named-data"
			if !validName(s.Name) {
				if err := p.gap("unrepresentable-stream-name", len(p.state.Entries), off, "raw UTF-16 retained"); err != nil {
					return 0, err
				}
			}
		}
		if s.Reserved != 0 || nonzero(s.Padding) {
			if err := p.gap("stream-reserved", len(p.state.Entries), off, "reserved/padding bytes retained"); err != nil {
				return 0, err
			}
		}
		e.Streams = append(e.Streams, s)
		off += n
	}
	reparse, data := false, false
	for i := range e.Streams {
		s := &e.Streams[i]
		if len(s.Name) > 0 {
			continue
		}
		if i == 0 && s.SHA1 == zeroHash {
			continue
		}
		if e.Attributes&0x4000 != 0 {
			if !data && s.SHA1 != zeroHash {
				s.Kind = "encrypted-raw"
				data = true
			} else {
				s.Kind = "unresolved-unnamed"
			}
		} else if e.Attributes&0x400 != 0 && !reparse {
			s.Kind = "reparse"
			reparse = true
		} else if !data {
			s.Kind = "data"
			data = true
		} else {
			s.Kind = "unresolved-unnamed"
		}
	}
	if !reparse && !data {
		if e.Attributes&0x400 != 0 {
			e.Streams[0].Kind = "reparse"
		} else if e.Attributes&16 != 0 {
			e.Streams[0].Kind = "directory-placeholder"
		} else {
			e.Streams[0].Kind = "data"
		}
	}
	seen := map[string]bool{}
	for i := range e.Streams {
		s := &e.Streams[i]
		if s.Kind == "" {
			s.Kind = "unresolved-unnamed"
		}
		if s.Kind == "unresolved-unnamed" {
			if err := p.gap("stream-role", len(p.state.Entries), s.Offset, "extra unnamed stream has no unambiguous role"); err != nil {
				return 0, err
			}
		}
		if len(s.Name) > 0 {
			var key strings.Builder
			for _, u := range s.Name {
				fmt.Fprintf(&key, "%04x", u)
			}
			if seen[key.String()] {
				return 0, ErrLayout
			}
			seen[key.String()] = true
		}
		if s.SHA1 == zeroHash {
			s.SizeKnown = true
			s.SizeProvenance = "metadata-empty"
		}
	}
	p.streams += count + 1
	return off, nil
}

func (p *parser) resolve(idx *wimindex.Index) error {
	byHash := map[string]int{}
	for i := range p.state.Entries {
		for j := range p.state.Entries[i].Streams {
			if err := p.ctx.Err(); err != nil {
				return err
			}
			s := &p.state.Entries[i].Streams[j]
			if s.SHA1 == zeroHash {
				continue
			}
			id, ok := byHash[s.SHA1]
			if !ok {
				count := idx.LookupCount(s.SHA1)
				if count > p.limits.MaxWitnesses-p.witnesses {
					return ErrLimit
				}
				p.witnesses += count
				if err := p.reserve(512 + uint64(count)*1024); err != nil {
					return err
				}
				r := Reference{SHA1: s.SHA1, Witnesses: idx.Lookup(s.SHA1), Ambiguous: count > 1}
				for k, w := range r.Witnesses {
					if w.Source != p.state.Receipt.Source || w.ManifestDigest != p.state.Receipt.ManifestDigest {
						return ErrInput
					}
					if k == 0 {
						r.Size = w.LogicalSize
						r.SizeKnown = true
					} else if w.LogicalSize != r.Size {
						r.SizeKnown = false
					}
					if w.Kind != "ordinary" && w.Kind != "solid-blob" {
						if err := p.gap("non-content-reference", i, s.Offset, fmt.Sprintf("hash=%s kind=%s", s.SHA1, w.Kind)); err != nil {
							return err
						}
					}
				}
				if count == 0 {
					if err := p.gap("missing-stream-reference", i, s.Offset, s.SHA1); err != nil {
						return err
					}
				} else if !r.SizeKnown {
					if err := p.gap("conflicting-stream-size", i, s.Offset, s.SHA1); err != nil {
						return err
					}
				}
				id = len(p.state.References)
				byHash[s.SHA1] = id
				p.state.References = append(p.state.References, r)
			}
			s.Reference = id
			r := p.state.References[id]
			s.Size = r.Size
			s.SizeKnown = r.SizeKnown
			if r.SizeKnown {
				s.SizeProvenance = "index-witness"
			} else {
				s.SizeProvenance = "unresolved"
			}
		}
	}
	groups := map[uint64][]int{}
	for i, e := range p.state.Entries {
		if e.HardlinkID != 0 {
			if err := p.reserve(128); err != nil {
				return err
			}
			groups[e.HardlinkID] = append(groups[e.HardlinkID], i)
		}
	}
	ids := make([]uint64, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		members := groups[id]
		if err := p.reserve(256 + uint64(len(members))*16); err != nil {
			return err
		}
		g := HardlinkGroup{ID: id, Entries: members, Consistent: true}
		first := p.state.Entries[members[0]]
		for _, i := range members[1:] {
			e := p.state.Entries[i]
			if e.Attributes&16 != 0 || first.Attributes&16 != 0 || !sameInode(first, e) {
				g.Consistent = false
			}
		}
		if !g.Consistent {
			if err := p.gap("hardlink-conflict", members[0], first.Offset, fmt.Sprintf("group=%d", id)); err != nil {
				return err
			}
		}
		p.state.Hardlinks = append(p.state.Hardlinks, g)
	}
	p.state.Summary.References = len(p.state.References)
	p.state.Summary.HardlinkGroups = len(p.state.Hardlinks)
	return nil
}
func sameInode(a, b Entry) bool {
	if a.Attributes != b.Attributes || a.SecurityID != b.SecurityID || a.CreationTime != b.CreationTime || a.AccessTime != b.AccessTime || a.WriteTime != b.WriteTime || a.Reserved != b.Reserved || a.Unknown84 != b.Unknown84 || len(a.Tags) != len(b.Tags) || len(a.Streams) != len(b.Streams) {
		return false
	}
	for i, x := range a.Tags {
		y := b.Tags[i]
		if x.Tag != y.Tag || !slices.Equal(x.Data, y.Data) || !slices.Equal(x.Padding, y.Padding) {
			return false
		}
	}
	for i, x := range a.Streams {
		y := b.Streams[i]
		if x.SHA1 != y.SHA1 || x.Kind != y.Kind || x.Reserved != y.Reserved || !slices.Equal(x.Name, y.Name) {
			return false
		}
	}
	return true
}
