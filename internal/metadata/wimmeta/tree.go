package wimmeta

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"unicode/utf16"
)

var disk = binary.LittleEndian

type parser struct {
	ctx                                   context.Context
	data, occupied                        []byte
	limits                                Limits
	used                                  uint64
	streams, aces, extraFields, witnesses int
	state                                 Snapshot
}

func (p *parser) reserve(n uint64) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if n > p.limits.MaxResultBytes-p.used {
		return ErrLimit
	}
	p.used += n
	return nil
}
func (p *parser) gap(kind string, entry int, off uint64, detail string) error {
	if err := p.reserve(512 + uint64(len(detail))*2); err != nil {
		return err
	}
	p.state.Gaps = append(p.state.Gaps, Gap{kind, entry, off, detail})
	p.state.Summary.Gaps++
	return nil
}
func (p *parser) field(b []byte) ([]byte, error) {
	if len(b) > p.limits.MaxVariableBytes {
		return nil, ErrLimit
	}
	if err := p.reserve(uint64(len(b)) * 2); err != nil {
		return nil, err
	}
	return slices.Clone(b), nil
}
func (p *parser) take(off, n uint64) error {
	if off&7 != 0 || n&7 != 0 || off > uint64(len(p.data)) || n > uint64(len(p.data))-off {
		return ErrLayout
	}
	for u := off / 8; u < (off+n)/8; u++ {
		if u&8191 == 0 {
			if err := p.ctx.Err(); err != nil {
				return err
			}
		}
		bit := byte(1 << (u & 7))
		if p.occupied[u/8]&bit != 0 {
			return fmt.Errorf("%w: aliased/overlapping range at %d", ErrLayout, off)
		}
		p.occupied[u/8] |= bit
	}
	return nil
}
func parseBytes(ctx context.Context, b []byte, l Limits) (*parser, error) {
	if ctx == nil {
		return nil, ErrInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l, err := bounds(l)
	if err != nil {
		return nil, err
	}
	if uint64(len(b)) > l.MaxInputBytes {
		return nil, ErrLimit
	}
	if len(b) < 8 || len(b)&7 != 0 {
		return nil, ErrLayout
	}
	p := &parser{ctx: ctx, data: b, limits: l, state: Snapshot{Schema: 1}}
	if err := p.reserve(uint64(len(b)+63)/64 + 4096); err != nil {
		return nil, err
	}
	p.occupied = make([]byte, (len(b)+63)/64)
	root, err := p.security()
	if err != nil {
		return nil, err
	}
	e, next, marker, err := p.entry(root, -1)
	if err != nil {
		return nil, err
	}
	if marker || e.Attributes&16 == 0 {
		return nil, ErrLayout
	}
	if len(e.Name) != 0 || len(e.ShortName) != 0 {
		if err := p.gap("named-root", 0, root, "root name retained without normalization"); err != nil {
			return nil, err
		}
	}
	if err := p.setPath(&e); err != nil {
		return nil, err
	}
	p.state.Entries = append(p.state.Entries, e)
	// The root sibling list must also terminate. It cannot gain a second root.
	if _, _, end, err := p.entry(next, -1); err != nil {
		return nil, err
	} else if !end {
		return nil, ErrLayout
	}
	type frame struct {
		parent, depth int
		off           uint64
		names         map[string]bool
	}
	stack := []frame{}
	if e.ChildOffset != 0 {
		stack = append(stack, frame{0, 1, e.ChildOffset, map[string]bool{}})
	}
	for len(stack) > 0 {
		f := &stack[len(stack)-1]
		if f.depth > l.MaxDepth {
			return nil, ErrLimit
		}
		e, next, end, err := p.entry(f.off, f.parent)
		if err != nil {
			return nil, err
		}
		f.off = next
		if end {
			stack = stack[:len(stack)-1]
			continue
		}
		if err := p.setPath(&e); err != nil {
			return nil, err
		}
		if err := p.reserve(uint64(len(e.Name))*2 + 128); err != nil {
			return nil, err
		}
		key := make([]byte, len(e.Name)*2)
		for i, v := range e.Name {
			disk.PutUint16(key[i*2:], v)
		}
		if f.names[string(key)] {
			return nil, fmt.Errorf("%w: duplicate exact sibling name", ErrLayout)
		}
		f.names[string(key)] = true
		id := len(p.state.Entries)
		p.state.Entries = append(p.state.Entries, e)
		if e.ChildOffset != 0 {
			if e.Attributes&16 == 0 {
				return nil, ErrLayout
			}
			if f.depth >= l.MaxDepth {
				return nil, ErrLimit
			}
			stack = append(stack, frame{id, f.depth + 1, e.ChildOffset, map[string]bool{}})
		}
	}
	// Retain every unreachable byte explicitly; it can never count as complete.
	for off := uint64(0); off < uint64(len(b)); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p.occupied[off/64]&(1<<((off/8)&7)) != 0 {
			off += 8
			continue
		}
		start := off
		for off < uint64(len(b)) && p.occupied[off/64]&(1<<((off/8)&7)) == 0 {
			off += 8
		}
		if err := p.reserve(128 + (off-start)*2); err != nil {
			return nil, err
		}
		p.state.Uninterpreted = append(p.state.Uninterpreted, Uninterpreted{start, slices.Clone(b[start:off])})
		if err := p.gap("unreferenced-metadata", -1, start, fmt.Sprintf("%d bytes", off-start)); err != nil {
			return nil, err
		}
	}
	p.state.Summary.Entries = len(p.state.Entries)
	p.state.Summary.Streams = p.streams
	p.state.Summary.Security = len(p.state.Security)
	p.state.Summary.ACEs = p.aces
	return p, nil
}
func (p *parser) name(b []byte, at, n int) ([]uint16, int, error) {
	if n == 0 {
		return nil, at, nil
	}
	if n > p.limits.MaxVariableBytes {
		return nil, 0, ErrLimit
	}
	if n&1 != 0 || at > len(b) || n+2 > len(b)-at || disk.Uint16(b[at+n:]) != 0 {
		return nil, 0, ErrLayout
	}
	if err := p.reserve(uint64(n) * 4); err != nil {
		return nil, 0, err
	}
	u := make([]uint16, n/2)
	for i := range u {
		u[i] = disk.Uint16(b[at+i*2:])
	}
	return u, at + n + 2, nil
}
func validName(u []uint16) bool {
	if len(u) == 0 || (len(u) == 1 && u[0] == '.') || (len(u) == 2 && u[0] == '.' && u[1] == '.') {
		return false
	}
	for i := 0; i < len(u); i++ {
		v := u[i]
		if v == 0 || v == '/' || v == '\\' {
			return false
		}
		if v >= 0xd800 && v <= 0xdbff {
			i++
			if i == len(u) || u[i] < 0xdc00 || u[i] > 0xdfff {
				return false
			}
		} else if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
	}
	return true
}
func (p *parser) setPath(e *Entry) error {
	if e.Parent < 0 {
		e.PathUTF16 = []uint16{'/'}
		e.PathValid = len(e.Name) == 0 && len(e.ShortName) == 0
		if e.PathValid {
			e.Path = "/"
		}
		return nil
	}
	parent := p.state.Entries[e.Parent]
	n := len(parent.PathUTF16) + len(e.Name)
	if len(parent.PathUTF16) > 1 {
		n++
	}
	if n*2 > p.limits.MaxVariableBytes {
		return ErrLimit
	}
	if err := p.reserve(uint64(n) * 10); err != nil {
		return err
	}
	e.PathUTF16 = make([]uint16, 0, n)
	e.PathUTF16 = append(e.PathUTF16, parent.PathUTF16...)
	if len(parent.PathUTF16) > 1 {
		e.PathUTF16 = append(e.PathUTF16, '/')
	}
	e.PathUTF16 = append(e.PathUTF16, e.Name...)
	e.PathValid = parent.PathValid && validName(e.Name)
	if e.PathValid {
		e.Path = string(utf16.Decode(e.PathUTF16))
	} else if err := p.gap("unrepresentable-path", len(p.state.Entries), e.Offset, "raw UTF-16 and parent identity retained"); err != nil {
		return err
	}
	if len(e.ShortName) > 0 && !validName(e.ShortName) {
		return p.gap("unrepresentable-short-name", len(p.state.Entries), e.Offset, "raw UTF-16 retained")
	}
	return nil
}
func (p *parser) entry(off uint64, parent int) (Entry, uint64, bool, error) {
	e := Entry{Offset: off, Parent: parent}
	if err := p.ctx.Err(); err != nil {
		return e, 0, false, err
	}
	if off&7 != 0 || off > uint64(len(p.data)) || uint64(len(p.data))-off < 8 {
		return e, 0, false, ErrLayout
	}
	n := disk.Uint64(p.data[off:])
	if n == 0 || n == 8 {
		if err := p.reserve(64); err != nil {
			return e, 0, false, err
		}
		if err := p.take(off, 8); err != nil {
			return e, 0, false, err
		}
		p.state.EndMarkers = append(p.state.EndMarkers, EndMarker{off, n})
		return e, off + 8, true, nil
	}
	if len(p.state.Entries) >= p.limits.MaxEntries {
		return e, 0, false, ErrLimit
	}
	if n < 102 || n&7 != 0 || n > uint64(len(p.data))-off {
		return e, 0, false, ErrLayout
	}
	if err := p.reserve(1024); err != nil {
		return e, 0, false, err
	}
	if err := p.take(off, n); err != nil {
		return e, 0, false, err
	}
	b := p.data[off : off+n]
	e.Length = n
	e.Attributes = disk.Uint32(b[8:])
	e.SecurityID = disk.Uint32(b[12:])
	e.ChildOffset = disk.Uint64(b[16:])
	e.Reserved = [2]uint64{disk.Uint64(b[24:]), disk.Uint64(b[32:])}
	if e.SecurityID != 0xffffffff && uint64(e.SecurityID) >= uint64(len(p.state.Security)) {
		return e, 0, false, ErrLayout
	}
	e.CreationTime = disk.Uint64(b[40:])
	e.AccessTime = disk.Uint64(b[48:])
	e.WriteTime = disk.Uint64(b[56:])
	e.Unknown84 = disk.Uint32(b[84:])
	if e.Attributes&0x400 != 0 {
		e.ReparseTag = disk.Uint32(b[88:])
		e.ReparseReserved = disk.Uint16(b[92:])
		e.ReparseFlags = disk.Uint16(b[94:])
		if e.ReparseFlags&^uint16(1) != 0 || e.ReparseReserved != 0 {
			if err := p.gap("reparse-semantics", len(p.state.Entries), off+88, "unknown reparse flags/reserved value retained"); err != nil {
				return e, 0, false, err
			}
		}
		p.state.Summary.Reparse++
	} else {
		e.HardlinkID = disk.Uint64(b[88:])
	}
	if e.Attributes&16 != 0 {
		p.state.Summary.Directories++
	}
	var err error
	at := 102
	e.Name, at, err = p.name(b, at, int(disk.Uint16(b[100:])))
	if err != nil {
		return e, 0, false, err
	}
	e.ShortName, at, err = p.name(b, at, int(disk.Uint16(b[98:])))
	if err != nil {
		return e, 0, false, err
	}
	align := (at + 7) &^ 7
	if align > len(b) {
		return e, 0, false, ErrLayout
	}
	e.Padding, err = p.field(b[at:align])
	if err != nil {
		return e, 0, false, err
	}
	if nonzero(e.Padding) {
		if err := p.gap("dentry-padding", len(p.state.Entries), off+uint64(at), "nonzero alignment bytes retained"); err != nil {
			return e, 0, false, err
		}
	}
	for at = align; at < len(b); {
		if p.extraFields >= p.limits.MaxExtraFields {
			return e, 0, false, ErrLimit
		}
		p.extraFields++
		if len(b)-at < 8 {
			return e, 0, false, ErrLayout
		}
		size := uint64(disk.Uint32(b[at+4:]))
		total := 8 + ((size + 7) &^ 7)
		if total > uint64(len(b)-at) {
			return e, 0, false, ErrLayout
		}
		if err := p.reserve(128); err != nil {
			return e, 0, false, err
		}
		t := Tag{Offset: off + uint64(at), Tag: disk.Uint32(b[at:])}
		t.Data, err = p.field(b[at+8 : at+8+int(size)])
		if err != nil {
			return e, 0, false, err
		}
		t.Padding, err = p.field(b[at+8+int(size) : at+int(total)])
		if err != nil {
			return e, 0, false, err
		}
		e.Tags = append(e.Tags, t)
		if err := p.gap("tag-semantics", len(p.state.Entries), off+uint64(at), fmt.Sprintf("tag=%d length=%d", t.Tag, size)); err != nil {
			return e, 0, false, err
		}
		at += int(total)
	}
	if e.Reserved != [2]uint64{} || e.Unknown84 != 0 {
		if err := p.gap("reserved-dentry", len(p.state.Entries), off, "nonzero reserved values retained"); err != nil {
			return e, 0, false, err
		}
	}
	next, err := p.readStreams(&e, b[64:84], int(disk.Uint16(b[96:])), off+n)
	return e, next, false, err
}
