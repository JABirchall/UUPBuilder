package wimindex

import (
	"context"
	"io"
	"math"
)

type standardTable struct{ count, width, bytes, data uint64 }

// Original WIM format (wimlib v1.14.5 resource.c): N-1 little-endian
// offsets relative to the table end; width changes at 4 GiB logical size.
// This is not the solid alternate header/table or pipable framing.
func standardShape(logical, physical, chunk uint64) (standardTable, error) {
	if logical == 0 || chunk == 0 || chunk&(chunk-1) != 0 {
		return standardTable{}, ErrLayout
	}
	n := 1 + (logical-1)/chunk // no logical+chunk overflow
	w := uint64(4)
	if logical >= 1<<32 {
		w = 8
	}
	if n-1 > math.MaxUint64/w {
		return standardTable{}, ErrLayout
	}
	table := (n - 1) * w
	if table >= physical {
		return standardTable{}, ErrLayout
	}
	return standardTable{n, w, table, physical - table}, nil
}
func (p standardTable) offset(ctx context.Context, r io.ReaderAt, size, base, ordinal uint64) (uint64, error) {
	if ordinal == 0 {
		return 0, nil
	}
	if ordinal == p.count {
		return p.data, nil
	}
	var b [8]byte
	if err := readRange(ctx, r, size, base+(ordinal-1)*p.width, b[:p.width]); err != nil {
		return 0, err
	}
	if p.width == 4 {
		return uint64(disk.Uint32(b[:])), nil
	}
	return disk.Uint64(b[:]), nil
}
func validateStandard(ctx context.Context, r io.ReaderAt, size uint64, e Entry, l DecodeLimits) (standardTable, error) {
	p, err := standardShape(e.LogicalSize, e.Descriptor.Size, uint64(e.Location.ChunkSize))
	if err != nil {
		return p, err
	}
	if p.count > uint64(l.MaxChunks) || uint64(e.Location.ChunkSize) > uint64(l.MaxChunkBytes) {
		return p, ErrLimit
	}
	if e.Descriptor.Offset > size || e.Descriptor.Size > size-e.Descriptor.Offset {
		return p, ErrLayout
	}
	// Table is traversed twice, once to validate every range before a native
	// call and once during decoding. Account for both before consuming it.
	if p.bytes > math.MaxUint64-e.Descriptor.Size || p.bytes+e.Descriptor.Size > l.MaxReadBytes {
		return p, ErrLimit
	}
	prev := uint64(0)
	for i := uint64(0); i < p.count; i++ {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		next, err := p.offset(ctx, r, size, e.Descriptor.Offset, i+1)
		if err != nil {
			return p, err
		}
		logical := min(uint64(e.Location.ChunkSize), e.LogicalSize-i*uint64(e.Location.ChunkSize))
		if next <= prev || next > p.data || next-prev > logical {
			return p, ErrLayout
		}
		if next-prev > uint64(l.MaxChunkBytes) || next-prev+logical > uint64(l.MaxBufferBytes) {
			return p, ErrLimit
		}
		prev = next
	}
	return p, nil
}
func streamStandard(ctx context.Context, r io.ReaderAt, size uint64, e Entry, l DecodeLimits, p standardTable, codec metadataCodec, w io.Writer) error {
	prev := uint64(0)
	for i := uint64(0); i < p.count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		next, err := p.offset(ctx, r, size, e.Descriptor.Offset, i+1)
		if err != nil {
			return err
		}
		logical := min(uint64(e.Location.ChunkSize), e.LogicalSize-i*uint64(e.Location.ChunkSize))
		// Re-check after the preflight: mutable source bytes never gain a larger
		// allocation or native call merely because a table was previously valid.
		if next <= prev || next > p.data || next-prev > logical {
			return ErrLayout
		}
		if next-prev > uint64(l.MaxChunkBytes) || next-prev+logical > uint64(l.MaxBufferBytes) {
			return ErrLimit
		}
		b := make([]byte, int(next-prev))
		if err := readRange(ctx, r, size, e.Descriptor.Offset+p.bytes+prev, b); err != nil {
			return err
		}
		out := b
		if uint64(len(b)) != logical {
			if codec == nil {
				return ErrUnsupported
			}
			out, err = codec.Decode(ctx, b, int(logical))
			if err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if uint64(len(out)) != logical {
			return ErrIntegrity
		}
		if n, err := w.Write(out); err != nil {
			return err
		} else if n != len(out) {
			return io.ErrShortWrite
		}
		prev = next
	}
	return nil
}
