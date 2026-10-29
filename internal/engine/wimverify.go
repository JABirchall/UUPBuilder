package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
)

// This reader does not use the writer's descriptor encoder or resource offsets.
// It checks every framing byte, expected original digest, size and table field.
// Windows interoperability is a separate installed-provider observation.
func verifyStandard(ctx context.Context, r io.ReaderAt, size uint64, in writeInput, limits Limits) (Receipt, error) {
	var out Receipt
	l, e := bounds(limits)
	if e != nil {
		return out, e
	}
	_, total, e := shape(in, l)
	if e != nil || size != total {
		return out, ErrIntegrity
	}
	read := func(b []byte, off uint64) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if off > size || uint64(len(b)) > size-off {
			return ErrIntegrity
		}
		n, e := r.ReadAt(b, int64(off))
		if e != nil || n != len(b) {
			return ErrIntegrity
		}
		return nil
	}
	var h [208]byte
	if e = read(h[:], 0); e != nil {
		return out, e
	}
	le := binary.LittleEndian
	if string(h[:8]) != "MSWIM\x00\x00\x00" || le.Uint32(h[8:]) != 208 || le.Uint32(h[12:]) != 0x10d00 || le.Uint32(h[16:]) != in.HeaderFlags || le.Uint32(h[20:]) != 0 || bytes.Equal(h[24:40], make([]byte, 16)) || le.Uint16(h[40:]) != 1 || le.Uint16(h[42:]) != 1 || le.Uint32(h[44:]) != 1 || !bytes.Equal(h[96:], make([]byte, 112)) {
		return out, ErrIntegrity
	}
	// Descriptor widths, flags and logical/physical size are checked separately.
	descriptor := func(b []byte, off, n uint64, flags byte) bool {
		return le.Uint64(b)&0x00ffffffffffffff == n && b[7] == flags && le.Uint64(b[8:]) == off && le.Uint64(b[16:]) == n
	}
	offset := uint64(208)
	for _, v := range in.Resources {
		a, b, e := hashCopy(ctx, nil, io.NewSectionReader(r, int64(offset), int64(v.Size)), v.Size)
		if e != nil || a != v.SHA1 || b != v.SHA256 {
			return out, ErrIntegrity
		}
		out.Resources = append(out.Resources, Resource{v.SHA1, v.SHA256, offset, v.Size, v.References, v.Metadata})
		offset += v.Size
	}
	out.LookupOffset = offset
	tableSize := uint64(len(in.Resources)) * 50
	if !descriptor(h[48:72], offset, tableSize, 2) || !descriptor(h[72:96], offset+tableSize, uint64(len(in.XML)), 2) {
		return out, ErrIntegrity
	}
	for n, want := range out.Resources {
		var rec [50]byte
		if e = read(rec[:], offset+uint64(n)*50); e != nil {
			return out, e
		}
		flag := byte(0)
		if n == 0 {
			flag = 2
		}
		if !descriptor(rec[:24], want.Offset, want.Size, flag) || le.Uint16(rec[24:]) != 1 || le.Uint32(rec[26:]) != want.References || hex.EncodeToString(rec[30:]) != want.SHA1 {
			return out, ErrIntegrity
		}
	}
	out.XMLOffset = offset + tableSize
	xml := make([]byte, len(in.XML))
	if e = read(xml, out.XMLOffset); e != nil {
		return out, e
	}
	if !bytes.Equal(xml, in.XML) || out.XMLOffset+uint64(len(xml)) != size {
		return out, ErrIntegrity
	}
	_, out.SHA256, e = hashCopy(ctx, nil, r, size)
	if e != nil {
		return out, e
	}
	out.Size = size
	out.BytesVerified = true
	return out, ctx.Err()
}
