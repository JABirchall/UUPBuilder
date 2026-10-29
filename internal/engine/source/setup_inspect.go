package source

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sort"
	"strings"
	"unicode/utf16"
)

// InspectMetadata walks actual output pointers independently of the writer's
// layout/offsets. It accounts for every byte, checks exact original raw records
// after undoing only declared fields, and rejects missing/duplicate/extra paths,
// cycles, collisions, unreferenced bytes and any undeclared mutation.
func (r *BoundSetupBoot) InspectMetadata(ctx context.Context, reader io.ReaderAt, size uint64) error {
	if e := contextValid(ctx); e != nil {
		return e
	}
	if e := r.CheckLive(); e != nil {
		return e
	}
	if reader == nil || size == 0 || size > 64<<20 || size > r.limits.MaxReadBytes {
		return ErrLimit
	}
	used := uint64(0)
	read := func(off uint64, b []byte) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if off > size || uint64(len(b)) > size-off || uint64(len(b)) > r.limits.MaxReadBytes-used {
			return ErrIntegrity
		}
		n, e := reader.ReadAt(b, int64(off))
		used += uint64(len(b))
		if e != nil || n != len(b) {
			return ErrIntegrity
		}
		return nil
	}
	le := binary.LittleEndian
	var header [8]byte
	if e := read(0, header[:]); e != nil {
		return e
	}
	prefix := uint64(le.Uint32(header[:]))
	if prefix < 8 || prefix > size || le.Uint32(header[4:]) != uint32(len(r.security)) {
		return ErrIntegrity
	}
	expectedPrefix := uint64(8 + len(r.security)*8)
	for _, s := range r.security {
		expectedPrefix += uint64(len(s))
	}
	expectedPrefix = (expectedPrefix + 7) &^ 7
	if prefix != expectedPrefix {
		return ErrIntegrity
	}
	table := make([]byte, len(r.security)*8)
	if e := read(8, table); e != nil {
		return e
	}
	off := uint64(8 + len(table))
	for i, want := range r.security {
		if le.Uint64(table[i*8:]) != uint64(len(want)) {
			return ErrIntegrity
		}
		got := make([]byte, len(want))
		if e := read(off, got); e != nil {
			return e
		}
		if !bytes.Equal(got, want) {
			return ErrIntegrity
		}
		off += uint64(len(got))
	}
	padding := make([]byte, prefix-off)
	if e := read(off, padding); e != nil {
		return e
	}
	if !bytes.Equal(padding, make([]byte, len(padding))) {
		return ErrIntegrity
	}
	type interval struct{ a, b uint64 }
	intervals := []interval{{0, prefix}}
	seen := map[int]bool{}
	type frame struct {
		off       uint64
		parent    int
		remaining int
		marker    uint64
		previous  string
	}
	stack := []frame{{off: prefix, parent: -1, remaining: 1, marker: r.rootMarker}}
	for len(stack) > 0 {
		f := &stack[len(stack)-1]
		if f.remaining == 0 {
			var b [8]byte
			if e := read(f.off, b[:]); e != nil {
				return e
			}
			if le.Uint64(b[:]) != f.marker {
				return ErrIntegrity
			}
			intervals = append(intervals, interval{f.off, f.off + 8})
			stack = stack[:len(stack)-1]
			continue
		}
		start := f.off
		var fixed [102]byte
		if e := read(start, fixed[:]); e != nil {
			return e
		}
		length := le.Uint64(fixed[:])
		nameBytes := int(le.Uint16(fixed[100:]))
		if length < 104 || length&7 != 0 || length > size-start || nameBytes&1 != 0 || nameBytes > 4096 || 102+nameBytes+2 > int(length) {
			return ErrIntegrity
		}
		name := make([]byte, nameBytes)
		if e := read(start+102, name); e != nil {
			return e
		}
		u := make([]uint16, nameBytes/2)
		for i := range u {
			u[i] = le.Uint16(name[i*2:])
		}
		path := "/"
		if f.parent >= 0 {
			path = r.nodes[f.parent].entry.Path
			if path != "/" {
				path += "/"
			}
			path += string(utf16.Decode(u))
		}
		key, e := setupKey(path)
		if e != nil {
			return e
		}
		collation := strings.ToUpper(path)
		if f.previous != "" && collation <= f.previous {
			return ErrIntegrity
		}
		f.previous = collation
		i, ok := r.paths[key]
		if !ok || seen[i] {
			return ErrIntegrity
		}
		n := r.nodes[i]
		if n.entry.Parent != f.parent || length != n.entry.Length {
			return ErrIntegrity
		}
		seen[i] = true
		got := make([]byte, len(n.raw))
		if e = read(start, got); e != nil {
			return e
		}
		child := le.Uint64(got[16:])
		if !n.listPresent && child != 0 || n.listPresent && (child == 0 || child&7 != 0) {
			return ErrIntegrity
		}
		le.PutUint64(got[16:], n.entry.ChildOffset)
		if n.graft {
			want := n.entry.SecurityID
			if want != 0xffffffff {
				want += uint32(r.state.OriginalSecurity)
			}
			if le.Uint32(got[12:]) != want {
				return ErrIntegrity
			}
			le.PutUint32(got[12:], n.entry.SecurityID)
		}
		if key == launchPath {
			if hex.EncodeToString(got[64:84]) != r.state.LaunchSHA1 {
				return ErrIntegrity
			}
			copy(got[64:84], n.raw[64:84])
		}
		if !bytes.Equal(got, n.raw) {
			return ErrIntegrity
		}
		end := start + uint64(len(got))
		intervals = append(intervals, interval{start, end})
		f.off = end
		f.remaining--
		if n.listPresent {
			stack = append(stack, frame{off: child, parent: i, remaining: len(n.children), marker: n.marker})
		}
	}
	if len(seen) != len(r.nodes) {
		return ErrIntegrity
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].a < intervals[j].a })
	off = 0
	for _, v := range intervals {
		if v.a != off || v.b < v.a {
			return ErrIntegrity
		}
		off = v.b
	}
	if off != size {
		return ErrIntegrity
	}
	return r.CheckLive()
}
