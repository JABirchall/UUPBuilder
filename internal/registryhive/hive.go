// Package registryhive reads selected stable REGF keys as inert data. It never
// loads a hive into the host registry, replays logs, repairs data or writes it.
// Only clean v1.3-v1.5 base blocks, ordinary cells, li/lf/lh/ri lists and small
// values are supported. Successful selected queries do not validate a full hive.
package registryhive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

var ErrNotFound = errors.New("registry key or value not found")
var le = binary.LittleEndian

type Hive struct {
	cells map[uint32][]byte
	root  uint32
}
type Value struct {
	Name string
	Type uint32
	Data []byte
}

func invalid(s string) error { return fmt.Errorf("unsupported or corrupt REGF: %s", s) }

func Open(r io.ReaderAt, size int64) (*Hive, error) {
	if size < 8192 || size > 128<<20 || size%4096 != 0 {
		return nil, invalid("file size")
	}
	b := make([]byte, int(size))
	if _, err := r.ReadAt(b, 0); err != nil {
		return nil, err
	}
	if string(b[:4]) != "regf" || le.Uint32(b[4:]) == 0 || le.Uint32(b[4:]) != le.Uint32(b[8:]) {
		return nil, invalid("signature or dirty sequences")
	}
	if le.Uint32(b[20:]) != 1 || le.Uint32(b[24:]) < 3 || le.Uint32(b[24:]) > 5 || le.Uint32(b[28:]) != 0 || le.Uint32(b[32:]) != 1 || le.Uint32(b[44:]) != 1 {
		return nil, invalid("base block variant")
	}
	var sum uint32
	for i := 0; i < 508; i += 4 {
		sum ^= le.Uint32(b[i:])
	}
	if sum == 0 {
		sum = 1
	}
	if sum == 0xffffffff {
		sum = 0xfffffffe
	}
	if sum != le.Uint32(b[508:]) {
		return nil, invalid("checksum")
	}
	bins := int64(le.Uint32(b[40:]))
	if bins < 4096 || bins%4096 != 0 || bins > size-4096 {
		return nil, invalid("bin range")
	}
	h := &Hive{cells: map[uint32][]byte{}, root: le.Uint32(b[36:])}
	for pos := int64(4096); pos < 4096+bins; {
		if string(b[pos:pos+4]) != "hbin" || int64(le.Uint32(b[pos+4:])) != pos-4096 {
			return nil, invalid("bin signature/offset")
		}
		n := int64(le.Uint32(b[pos+8:]))
		if n < 4096 || n%4096 != 0 || n > 4096+bins-pos {
			return nil, invalid("bin size")
		}
		for off := pos + 32; off < pos+n; {
			if off+4 > pos+n {
				return nil, invalid("cell prefix")
			}
			signed := int32(le.Uint32(b[off:]))
			length := int64(signed)
			if length < 0 {
				length = -length
			}
			if length < 8 || length%8 != 0 || length > pos+n-off {
				return nil, invalid("cell range")
			}
			if signed < 0 {
				if len(h.cells) >= 2000000 {
					return nil, invalid("cell count")
				}
				h.cells[uint32(off-4096)] = b[off+4 : off+length]
			}
			off += length
		}
		pos += n
	}
	if _, err := h.key(h.root); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Hive) cell(off uint32) ([]byte, error) {
	b, ok := h.cells[off]
	if !ok {
		return nil, invalid("unallocated cell reference")
	}
	return b, nil
}
func text(b []byte, compressed bool) (string, error) {
	if compressed {
		for _, c := range b {
			if c == 0 || c >= 128 {
				return "", invalid("compressed name")
			}
		}
		return string(b), nil
	}
	if len(b)%2 != 0 {
		return "", invalid("UTF16 length")
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[i*2:])
	}
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 == len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return "", invalid("UTF16 surrogate")
			}
			i++
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			return "", invalid("UTF16 surrogate")
		}
	}
	return string(utf16.Decode(u)), nil
}
func (h *Hive) key(off uint32) ([]byte, error) {
	b, err := h.cell(off)
	if err != nil {
		return nil, err
	}
	if len(b) < 76 || string(b[:2]) != "nk" || int(le.Uint16(b[72:])) > len(b)-76 {
		return nil, invalid("key shape")
	}
	if le.Uint32(b[24:]) != 0 {
		return nil, invalid("volatile keys")
	}
	return b, nil
}
func (h *Hive) keyName(off uint32) (string, error) {
	b, err := h.key(off)
	if err != nil {
		return "", err
	}
	s, err := text(b[76:76+int(le.Uint16(b[72:]))], le.Uint16(b[2:])&0x20 != 0)
	if strings.ContainsRune(s, 0) {
		return "", invalid("NUL key name")
	}
	return s, err
}
func (h *Hive) subkeys(off uint32, depth int, seen map[uint32]bool) ([]uint32, error) {
	if depth > 8 || seen[off] {
		return nil, invalid("subkey cycle/depth")
	}
	seen[off] = true
	b, err := h.cell(off)
	if err != nil {
		return nil, err
	}
	if len(b) < 4 {
		return nil, invalid("list header")
	}
	n := int(le.Uint16(b[2:]))
	if n == 0 || n > 16384 {
		return nil, invalid("list count")
	}
	stride := 4
	switch string(b[:2]) {
	case "lf", "lh":
		stride = 8
	case "li", "ri":
	default:
		return nil, invalid("list type")
	}
	if n > (len(b)-4)/stride {
		return nil, invalid("list bounds")
	}
	out := []uint32{}
	for i := 0; i < n; i++ {
		v := le.Uint32(b[4+i*stride:])
		if string(b[:2]) == "ri" {
			children, err := h.subkeys(v, depth+1, seen)
			if err != nil {
				return nil, err
			}
			out = append(out, children...)
		} else {
			out = append(out, v)
		}
		if len(out) > 200000 {
			return nil, invalid("subkey total")
		}
	}
	return out, nil
}
func (h *Hive) find(path string) (uint32, error) {
	off := h.root
	if path == "" {
		return off, nil
	}
	parts := strings.Split(path, `\`)
	if len(parts) > 32 {
		return 0, invalid("query depth")
	}
	visited := map[uint32]bool{}
	for _, part := range parts {
		if part == "" || visited[off] {
			return 0, invalid("empty query part or key cycle")
		}
		visited[off] = true
		b, err := h.key(off)
		if err != nil {
			return 0, err
		}
		count := le.Uint32(b[20:])
		if count == 0 {
			return 0, ErrNotFound
		}
		subs, err := h.subkeys(le.Uint32(b[28:]), 0, map[uint32]bool{})
		if err != nil {
			return 0, err
		}
		if uint64(count) != uint64(len(subs)) {
			return 0, invalid("key count")
		}
		found := false
		names := map[string]bool{}
		ids := map[uint32]bool{}
		for _, sub := range subs {
			name, err := h.keyName(sub)
			if err != nil {
				return 0, err
			}
			fold := strings.ToUpper(name)
			if ids[sub] || names[fold] {
				return 0, invalid("ambiguous subkeys")
			}
			ids[sub] = true
			names[fold] = true
			if strings.EqualFold(name, part) {
				off = sub
				found = true
			}
		}
		if !found {
			return 0, ErrNotFound
		}
		if visited[off] {
			return 0, invalid("cyclic key graph")
		}
	}
	return off, nil
}
func (h *Hive) values(path string, selectName *string) ([]Value, error) {
	off, err := h.find(path)
	if err != nil {
		return nil, err
	}
	b, err := h.key(off)
	if err != nil {
		return nil, err
	}
	count := le.Uint32(b[36:])
	if count > 16384 {
		return nil, invalid("value count")
	}
	if count == 0 {
		return nil, nil
	}
	list, err := h.cell(le.Uint32(b[40:]))
	if err != nil {
		return nil, err
	}
	if uint64(count)*4 > uint64(len(list)) {
		return nil, invalid("value list")
	}
	out := []Value{}
	names := map[string]bool{}
	for i := uint32(0); i < count; i++ {
		v, err := h.cell(le.Uint32(list[i*4:]))
		if err != nil {
			return nil, err
		}
		if len(v) < 20 || string(v[:2]) != "vk" || int(le.Uint16(v[2:])) > len(v)-20 {
			return nil, invalid("value shape")
		}
		name, err := text(v[20:20+int(le.Uint16(v[2:]))], le.Uint16(v[16:])&1 != 0)
		if err != nil {
			return nil, err
		}
		fold := strings.ToUpper(name)
		if strings.ContainsRune(name, 0) || names[fold] {
			return nil, invalid("ambiguous value names")
		}
		names[fold] = true
		if selectName != nil && !strings.EqualFold(name, *selectName) {
			continue
		}
		n := le.Uint32(v[4:]) & 0x7fffffff
		if n > 16344 {
			return nil, invalid("large value unsupported")
		}
		var data []byte
		if le.Uint32(v[4:])&0x80000000 != 0 {
			if n > 4 {
				return nil, invalid("inline length")
			}
			data = v[8 : 8+n]
		} else if n > 0 {
			data, err = h.cell(le.Uint32(v[8:]))
			if err != nil {
				return nil, err
			}
			if uint64(n) > uint64(len(data)) {
				return nil, invalid("data length")
			}
			data = data[:n]
		}
		value := Value{Name: name, Type: le.Uint32(v[12:]), Data: append([]byte(nil), data...)}
		if value.Type == 1 {
			if _, err := value.String(); err != nil {
				return nil, err
			}
		}
		if value.Type == 4 && len(data) != 4 {
			return nil, invalid("DWORD size")
		}
		out = append(out, value)
	}
	return out, nil
}
func (h *Hive) Values(path string) ([]Value, error) { return h.values(path, nil) }
func (h *Hive) Value(path, name string) (Value, error) {
	v, err := h.values(path, &name)
	if err != nil {
		return Value{}, err
	}
	if len(v) != 1 {
		return Value{}, ErrNotFound
	}
	return v[0], nil
}
func (v Value) String() (string, error) {
	if v.Type != 1 || len(v.Data) < 2 || len(v.Data)%2 != 0 || le.Uint16(v.Data[len(v.Data)-2:]) != 0 {
		return "", invalid("REG_SZ type/terminator")
	}
	s, err := text(v.Data[:len(v.Data)-2], false)
	if strings.ContainsRune(s, 0) {
		return "", invalid("REG_SZ embedded NUL")
	}
	return s, err
}
func (v Value) DWORD() (uint32, error) {
	if v.Type != 4 || len(v.Data) != 4 {
		return 0, invalid("REG_DWORD type/size")
	}
	return le.Uint32(v.Data), nil
}
