package source

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"
	"uupbuilder/internal/metadata/wimmeta"
)

// Only known framing fields are rewritten. Names, timestamps, inode IDs, all
// stream records and opaque extra-field payloads remain original raw spans.
func rawSetupNodes(s wimmeta.Snapshot, b []byte) ([]setupNode, uint64, error) {
	if len(s.Entries) == 0 || s.Entries[0].Path != "/" || len(s.Uninterpreted) != 0 || len(s.SecurityPadding) > 7 || !bytes.Equal(s.SecurityPadding, make([]byte, len(s.SecurityPadding))) {
		return nil, 0, ErrSetupShape
	}
	for _, g := range s.Hardlinks {
		if !g.Consistent {
			return nil, 0, ErrSetupShape
		}
	}
	for _, g := range s.Gaps {
		if g.Kind != "tag-semantics" {
			return nil, 0, ErrSetupShape
		}
	}
	markers := map[uint64]uint64{}
	for _, m := range s.EndMarkers {
		markers[m.Offset] = m.Length
	}
	nodes := make([]setupNode, len(s.Entries))
	for i, en := range s.Entries {
		if !en.PathValid || en.Parent >= i || en.Parent < 0 && i != 0 {
			return nil, 0, ErrSetupShape
		}
		if _, e := setupKey(en.Path); e != nil {
			return nil, 0, e
		}
		end := en.Offset + en.Length
		for j, stream := range en.Streams {
			if j == 0 {
				continue
			}
			if stream.Offset != end || stream.Length > uint64(len(b))-end {
				return nil, 0, ErrSetupShape
			}
			end += stream.Length
		}
		if en.Offset > uint64(len(b)) || end > uint64(len(b)) || end < en.Offset {
			return nil, 0, ErrSetupShape
		}
		nodes[i] = setupNode{entry: en, raw: b[en.Offset:end], listPresent: en.ChildOffset != 0}
		if en.Parent >= 0 {
			nodes[en.Parent].children = append(nodes[en.Parent].children, i)
		}
	}
	rootMarker, ok := markers[s.Entries[0].Offset+uint64(len(nodes[0].raw))]
	if !ok {
		return nil, 0, ErrSetupShape
	}
	for i := range nodes {
		n := &nodes[i]
		if n.entry.ChildOffset == 0 {
			if len(n.children) != 0 {
				return nil, 0, ErrSetupShape
			}
			continue
		}
		off := n.entry.ChildOffset
		for _, child := range n.children {
			if nodes[child].entry.Offset != off {
				return nil, 0, ErrSetupShape
			}
			off += uint64(len(nodes[child].raw))
		}
		marker, ok := markers[off]
		if !ok {
			return nil, 0, ErrSetupShape
		}
		n.marker = marker
	}
	return nodes, rootMarker, nil
}
func (r *BoundSetupBoot) planRecords(pe, media wimmeta.Snapshot, peRaw, mediaRaw []byte) error {
	nodes, marker, e := rawSetupNodes(pe, peRaw)
	if e != nil {
		return e
	}
	mn, _, e := rawSetupNodes(media, mediaRaw)
	if e != nil {
		return e
	}
	r.nodes = nodes
	r.rootMarker = marker
	for i, n := range r.nodes {
		key, e := setupKey(n.entry.Path)
		if e != nil {
			return e
		}
		if _, ok := r.paths[key]; ok {
			return ErrSetupShape
		}
		r.paths[key] = i
	}
	if _, ok := r.paths[launchPath]; !ok {
		return ErrSetupShape
	}
	for _, s := range pe.Security {
		r.security = append(r.security, s.Raw)
	}
	r.state.OriginalSecurity = len(r.security)
	for _, s := range media.Security {
		r.security = append(r.security, s.Raw)
	}
	r.state.ImportedSecurity = len(media.Security)
	r.state.OriginalRecords = len(nodes)
	if len(r.security) > 65536 {
		return ErrLimit
	}
	for _, n := range mn {
		key, e := setupKey(n.entry.Path)
		if e != nil {
			return e
		}
		if key != "/setup.exe" && !strings.HasPrefix(key, "/sources/") {
			continue
		}
		// Reserved generated images can never feed this fixed source-only graft.
		for _, p := range r.state.Media.ReservedPaths {
			reserved, e := setupKey("/" + p)
			if e != nil {
				return e
			}
			if key == reserved || strings.HasPrefix(key, reserved+"/") {
				return ErrSetupShape
			}
		}
		if old, ok := r.paths[key]; ok {
			if r.nodes[old].entry.Attributes&16 == 0 || n.entry.Attributes&16 == 0 {
				return ErrSetupShape
			}
			continue
		}
		at := strings.LastIndex(key, "/")
		parentKey := key[:at]
		if parentKey == "" {
			parentKey = "/"
		}
		parent, ok := r.paths[parentKey]
		if !ok || r.nodes[parent].entry.Attributes&16 == 0 {
			return ErrSetupShape
		}
		n.graft = true
		n.children = nil
		n.entry.Parent = parent
		id := len(r.nodes)
		r.nodes = append(r.nodes, n)
		r.paths[key] = id
		r.nodes[parent].children = append(r.nodes[parent].children, id)
		if n.entry.Attributes&16 != 0 {
			r.state.GraftDirectories++
		} else {
			r.state.GraftFiles++
		}
	}
	// The source sources directory itself must already exist in the PE image;
	// copying its descendants must never synthesize a generic Windows directory.
	if i, ok := r.paths["/sources"]; !ok || r.nodes[i].graft || r.nodes[i].entry.Attributes&16 == 0 {
		return ErrSetupShape
	}
	// The v1 namespace is ASCII-only, so uppercase comparison supplies the
	// Windows-style case-insensitive collation without a Unicode alias claim.
	for i := range r.nodes {
		children := r.nodes[i].children
		if len(children) > 0 {
			r.nodes[i].listPresent = true
		}
		sort.Slice(children, func(a, b int) bool {
			return strings.ToUpper(r.nodes[children[a]].entry.Path) < strings.ToUpper(r.nodes[children[b]].entry.Path)
		})
	}
	return nil
}
func (r *BoundSetupBoot) writeMetadata(ctx context.Context) error {
	prefix := uint64(8 + len(r.security)*8)
	for _, s := range r.security {
		prefix += uint64(len(s))
	}
	prefix = (prefix + 7) &^ 7
	size := prefix + 8
	for _, n := range r.nodes {
		size += uint64(len(n.raw))
		if n.listPresent {
			size += 8
		}
	}
	if size > 64<<20 || size*2 > r.limits.MaxReadBytes || size*3 > r.limits.MaxResultBytes {
		return ErrLimit
	}
	out := make([]byte, 0, int(size))
	out = append(out, make([]byte, int(prefix))...)
	le := binary.LittleEndian
	le.PutUint32(out, uint32(prefix))
	le.PutUint32(out[4:], uint32(len(r.security)))
	at := 8 + len(r.security)*8
	for i, s := range r.security {
		le.PutUint64(out[8+i*8:], uint64(len(s)))
		copy(out[at:], s)
		at += len(s)
	}
	// Each directory's complete sibling list is contiguous; only known absolute
	// child pointers need relocation. Parent traversal order is private framing.
	var list func([]int, uint64) error
	list = func(ids []int, marker uint64) error {
		for _, i := range ids {
			if e := ctx.Err(); e != nil {
				return e
			}
			n := &r.nodes[i]
			n.offset = uint64(len(out))
			out = append(out, n.raw...)
			le.PutUint64(out[n.offset+16:], 0)
			if n.graft && n.entry.SecurityID != 0xffffffff {
				le.PutUint32(out[n.offset+12:], n.entry.SecurityID+uint32(r.state.OriginalSecurity))
			}
			if i == r.paths[launchPath] {
				hash, _ := hex.DecodeString(r.state.LaunchSHA1)
				copy(out[n.offset+64:n.offset+84], hash)
			}
		}
		out = le.AppendUint64(out, marker)
		for _, i := range ids {
			n := &r.nodes[i]
			if !n.listPresent {
				continue
			}
			le.PutUint64(out[n.offset+16:], uint64(len(out)))
			if e := list(n.children, n.marker); e != nil {
				return e
			}
		}
		return nil
	}
	if e := list([]int{0}, r.rootMarker); e != nil {
		return e
	}
	if uint64(len(out)) != size {
		return ErrIntegrity
	}
	r.raw = out
	return nil
}
