package wimmeta

import (
	"fmt"
	"slices"
)

func (p *parser) security() (uint64, error) {
	b := p.data
	n := uint64(disk.Uint32(b))
	count := uint64(disk.Uint32(b[4:]))
	p.state.SecurityLength = uint32(n)
	if n == 0 {
		n = 8
	}
	if n&7 != 0 || n > uint64(len(b)) || n < 8 {
		return 0, ErrLayout
	}
	if count > uint64(p.limits.MaxSecurity) {
		return 0, ErrLimit
	}
	if count > (n-8)/8 {
		return 0, ErrLayout
	}
	if err := p.take(0, n); err != nil {
		return 0, err
	}
	at := uint64(8) + count*8
	for i := uint64(0); i < count; i++ {
		if err := p.ctx.Err(); err != nil {
			return 0, err
		}
		size := disk.Uint64(b[8+i*8:])
		if size > uint64(p.limits.MaxSecurityBytes) {
			return 0, ErrLimit
		}
		if size > n-at {
			return 0, ErrLayout
		}
		if err := p.reserve(256 + size*2); err != nil {
			return 0, err
		}
		s := Security{Raw: slices.Clone(b[at : at+size])}
		if size == 0 {
			if err := p.gap("empty-security-descriptor", -1, at, fmt.Sprintf("security=%d", i)); err != nil {
				return 0, err
			}
		} else if err := p.descriptor(&s, int(i), at); err != nil {
			return 0, err
		}
		p.state.Security = append(p.state.Security, s)
		at += size
	}
	var err error
	p.state.SecurityPadding, err = p.field(b[at:n])
	if err != nil {
		return 0, err
	}
	if n-at > 7 || nonzero(b[at:n]) {
		if err := p.gap("security-prefix-extra", -1, at, "bounded trailing prefix bytes retained"); err != nil {
			return 0, err
		}
	}
	return n, nil
}
func nonzero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
func sidAt(b []byte, off uint32) (SID, uint32, error) {
	if off < 20 || off&3 != 0 || uint64(off)+8 > uint64(len(b)) {
		return SID{}, 0, ErrLayout
	}
	n := uint32(b[off+1])
	if b[off] != 1 || n > 15 {
		return SID{}, 0, ErrLayout
	}
	size := 8 + n*4
	if uint64(off)+uint64(size) > uint64(len(b)) {
		return SID{}, 0, ErrLayout
	}
	return SID{Offset: off, Raw: slices.Clone(b[off : off+size])}, size, nil
}
func (p *parser) descriptor(s *Security, index int, base uint64) error {
	b := s.Raw
	if len(b) < 20 || b[0] != 1 || disk.Uint16(b[2:])&0x8000 == 0 {
		return ErrLayout
	}
	control := disk.Uint16(b[2:])
	// Public SECURITY_DESCRIPTOR_CONTROL bits from winnt.h. Unknown stored
	// control semantics remain explicit even though the raw descriptor survives.
	const supportedControl uint16 = 0xff3f
	if unsupported := control &^ supportedControl; unsupported != 0 {
		if err := p.gap("security-control-semantics", -1, base+2, fmt.Sprintf("security=%d unsupported-control=0x%04x", index, unsupported)); err != nil {
			return err
		}
	}
	if b[1] != 0 && control&0x4000 == 0 {
		if err := p.gap("security-reserved", -1, base, fmt.Sprintf("security=%d", index)); err != nil {
			return err
		}
	}
	type span struct {
		off, size uint32
		kind      string
	}
	spans := []span{{0, 20, "header"}}
	for j, target := range []*SID{&s.Owner, &s.Group} {
		off := disk.Uint32(b[4+j*4:])
		if off == 0 {
			continue
		}
		v, n, err := sidAt(b, off)
		if err != nil {
			return err
		}
		*target = v
		spans = append(spans, span{off, n, "sid"})
	}
	for j, target := range []**ACL{&s.SACL, &s.DACL} {
		off := disk.Uint32(b[12+j*4:])
		present := control&(0x10>>uint(j*2)) != 0
		if !present && off != 0 {
			return ErrLayout
		}
		if off == 0 {
			continue
		}
		a, err := p.acl(b, off, index, base)
		if err != nil {
			return err
		}
		*target = a
		spans = append(spans, span{off, uint32(a.Size), "acl"})
	}
	for i, a := range spans {
		for _, z := range spans[:i] {
			if a.off < z.off+z.size && z.off < a.off+a.size && !(a.off == z.off && a.size == z.size && a.kind == z.kind) {
				return ErrLayout
			}
		}
	}
	// Raw descriptors retain padding, object GUIDs and unsupported ACE bodies.
	// Nonzero bytes outside all described components stay explicitly unresolved.
	for i := 20; i < len(b); i++ {
		covered := false
		for _, a := range spans {
			if uint32(i) >= a.off && uint32(i) < a.off+a.size {
				covered = true
				break
			}
		}
		if !covered && b[i] != 0 {
			return p.gap("security-extra", -1, base+uint64(i), fmt.Sprintf("security=%d", index))
		}
	}
	return nil
}
func (p *parser) acl(b []byte, off uint32, index int, base uint64) (*ACL, error) {
	if off < 20 || off&3 != 0 || uint64(off)+8 > uint64(len(b)) {
		return nil, ErrLayout
	}
	x := b[off:]
	size := disk.Uint16(x[2:])
	count := int(disk.Uint16(x[4:]))
	if size < 8 || uint64(size) > uint64(len(x)) || size&3 != 0 {
		return nil, ErrLayout
	}
	if count > p.limits.MaxACEs-p.aces {
		return nil, ErrLimit
	}
	if count > (int(size)-8)/4 {
		return nil, ErrLayout
	}
	if err := p.reserve(128 + uint64(count)*256); err != nil {
		return nil, err
	}
	a := &ACL{Offset: off, Revision: x[0], Size: size, ACEs: make([]ACE, 0, count)}
	if (x[0] != 2 && x[0] != 4) || x[1] != 0 || disk.Uint16(x[6:]) != 0 {
		if err := p.gap("acl-header-semantics", -1, base+uint64(off), fmt.Sprintf("security=%d", index)); err != nil {
			return nil, err
		}
	}
	at := 8
	for j := 0; j < count; j++ {
		if err := p.ctx.Err(); err != nil {
			return nil, err
		}
		if int(size)-at < 4 {
			return nil, ErrLayout
		}
		r := x[at:int(size)]
		n := disk.Uint16(r[2:])
		if n < 4 || n&3 != 0 || int(n) > len(r) {
			return nil, ErrLayout
		}
		r = r[:n]
		e := ACE{Offset: off + uint32(at), Type: r[0], Flags: r[1], Size: n}
		sidOff := -1
		switch e.Type {
		case 0, 1, 2, 3, 9, 10, 13, 14, 17, 18, 19, 20, 21:
			sidOff = 8
			e.Understood = e.Type <= 2 || e.Type == 17 || e.Type == 19 || e.Type == 20
		case 5, 6, 7, 8, 11, 12, 15, 16:
			if len(r) < 12 || a.Revision != 4 {
				return nil, ErrLayout
			}
			e.ObjectFlags = disk.Uint32(r[8:])
			sidOff = 12
			if e.ObjectFlags&1 != 0 {
				sidOff += 16
			}
			if e.ObjectFlags&2 != 0 {
				sidOff += 16
			}
			e.Understood = e.Type <= 7 && e.ObjectFlags&^uint32(3) == 0
		}
		if sidOff >= 0 {
			if len(r) < sidOff+8 {
				return nil, ErrLayout
			}
			e.Mask = disk.Uint32(r[4:])
			// SID validation takes descriptor-relative aligned offsets, then
			// independently checks that the complete SID fits this ACE.
			sid, n, err := sidAt(b, e.Offset+uint32(sidOff))
			if err != nil || uint32(sidOff)+n > uint32(e.Size) {
				return nil, ErrLayout
			}
			e.SID = sid
			if uint32(sidOff)+n != uint32(e.Size) {
				e.Understood = false
			}
		}
		if e.Flags&0x20 != 0 {
			e.Understood = false
		}
		if !e.Understood {
			if err := p.gap("ace-semantics", -1, base+uint64(e.Offset), fmt.Sprintf("security=%d type=%d", index, e.Type)); err != nil {
				return nil, err
			}
		}
		a.ACEs = append(a.ACEs, e)
		p.aces++
		at += int(n)
	}
	if nonzero(x[at:size]) {
		if err := p.gap("acl-unused-bytes", -1, base+uint64(off)+uint64(at), fmt.Sprintf("security=%d", index)); err != nil {
			return nil, err
		}
	}
	return a, nil
}
