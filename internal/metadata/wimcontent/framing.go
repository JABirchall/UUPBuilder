package wimcontent

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"uupbuilder/internal/metadata/wimindex"
)

type chunk struct{ offset, size, logical uint64 }
type table struct {
	count, table uint64
	chunks       []chunk
}

func read(ctx context.Context, r io.ReaderAt, size, off uint64, b []byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if off > size || uint64(len(b)) > size-off {
		return ErrLayout
	}
	n, e := r.ReadAt(b, int64(off))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e != nil || n != len(b) {
		return errors.Join(ErrIntegrity, e)
	}
	return nil
}

// Pinned primary format: wimlib v1.14.5 resource.h alt_chunk_table_header_disk
// and resource.c read_compressed_wim_resource. Alternate tables store N sizes,
// always 32-bit, following a 16-byte header. Ordinary raw has no chunk table.
// Compressed ordinary resources are an explicit gap in this bounded slice.
func inspect(ctx context.Context, r io.ReaderAt, sourceSize uint64, e wimindex.Entry, l Limits) (table, error) {
	var p table
	d := e.Descriptor
	if e.LogicalSize == 0 || d.Offset > sourceSize || d.Size > sourceSize-d.Offset {
		return p, ErrLayout
	}
	if e.LogicalSize > l.MaxResourceBytes {
		return p, ErrLimit
	}
	if e.Kind == "ordinary" {
		if d.Flags != 0 || e.Location.Compression != 0 || e.Location.ChunkSize != 0 {
			return p, ErrUnsupported
		}
		if d.Size != e.LogicalSize || d.Original != e.LogicalSize {
			return p, ErrLayout
		}
		return p, nil
	}
	if e.Kind != "solid-resource" || d.Flags != 16 {
		return p, ErrUnsupported
	}
	if d.Size < 20 {
		return p, ErrLayout
	}
	var h [16]byte
	if er := read(ctx, r, sourceSize, d.Offset, h[:]); er != nil {
		return p, er
	}
	logical := binary.LittleEndian.Uint64(h[:])
	cs := uint64(binary.LittleEndian.Uint32(h[8:]))
	codec := binary.LittleEndian.Uint32(h[12:])
	if logical != e.LogicalSize || logical != e.Location.ResourceLogicalSize || cs != uint64(e.Location.ChunkSize) || codec != e.Location.Compression {
		return p, ErrIntegrity
	}
	if cs == 0 || cs&(cs-1) != 0 {
		return p, ErrLayout
	}
	if codec != 0 && codec != 3 {
		return p, ErrUnsupported
	}
	if cs > uint64(l.MaxChunkBytes) {
		return p, ErrLimit
	}
	p.count = 1 + (logical-1)/cs
	if p.count > uint64(l.MaxChunks) || p.count > uint64(l.MaxTotalChunks) || p.count*64 > l.MaxResultBytes {
		return p, ErrLimit
	}
	p.table = 16 + p.count*4
	if p.table >= d.Size {
		return p, ErrLayout
	}
	// Count/memory ceilings precede the only table allocation. No input/output
	// chunk buffer or native provider exists during this complete preflight.
	p.chunks = make([]chunk, int(p.count))
	pos := p.table
	var maxInput, maxOutput uint64
	for n := uint64(0); n < p.count; n++ {
		var v [4]byte
		if er := read(ctx, r, sourceSize, d.Offset+16+n*4, v[:]); er != nil {
			return table{}, er
		}
		size := uint64(binary.LittleEndian.Uint32(v[:]))
		out := min(cs, logical-n*cs)
		if size == 0 || size > out || size > d.Size-pos {
			return table{}, ErrLayout
		}
		if codec == 0 && size != out {
			return table{}, ErrLayout
		}
		buffers := size
		if size != out {
			buffers += out
		}
		if buffers > uint64(l.MaxBufferBytes) {
			return table{}, ErrLimit
		}
		p.chunks[n] = chunk{d.Offset + pos, size, out}
		maxInput = max(maxInput, size)
		if size != out {
			maxOutput = max(maxOutput, out)
		}
		pos += size
	}
	if pos != d.Size {
		return table{}, ErrLayout
	}
	if maxInput+maxOutput > uint64(l.MaxBufferBytes) {
		return table{}, ErrLimit
	}
	return p, nil
}
