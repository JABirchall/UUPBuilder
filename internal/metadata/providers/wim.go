// Package providers implements bounded, read-only container metadata inspection.
package providers

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"uupbuilder/internal/metadata"
)

var ErrUnsupported = errors.New("metadata container operation unimplemented")

type WIM struct{}

// WIM reads the uncompressed XML resource only. It does not decode file streams,
// reconstruct references, mount an image, or infer Setup/recovery from an index.
// Layout: wimlib v1.14.5 include/wimlib/{header,resource}.h, offsets 0x48..0x60.
func (WIM) Inspect(ctx context.Context, r metadata.LocalResource, limits metadata.Limits) (metadata.ProviderResult, error) {
	var out metadata.ProviderResult
	limit, err := documentLimit(limits)
	if err != nil {
		return out, err
	}
	f, err := verified(ctx, r)
	if err != nil {
		return out, err
	}
	defer f.Close()
	var h [208]byte
	if _, err := io.ReadFull(f, h[:]); err != nil || string(h[:8]) != "MSWIM\x00\x00\x00" || binary.LittleEndian.Uint32(h[8:]) != 208 {
		return out, metadata.ErrMalformedMetadata
	}
	version := binary.LittleEndian.Uint32(h[12:])
	if version != 0x10d00 && version != 0xe00 {
		return out, ErrUnsupported
	}
	if binary.LittleEndian.Uint16(h[40:]) != 1 || binary.LittleEndian.Uint16(h[42:]) != 1 || binary.LittleEndian.Uint32(h[16:])&0x48 != 0 {
		return out, ErrUnsupported
	}
	packed := binary.LittleEndian.Uint64(h[72:])
	size, flags := packed&0x00ffffffffffffff, byte(packed>>56)
	offset, original := binary.LittleEndian.Uint64(h[80:]), binary.LittleEndian.Uint64(h[88:])
	if flags != 0 && flags != 2 {
		return out, ErrUnsupported
	}
	if size == 0 || size != original || offset < 208 || offset > uint64(r.Identity.Size) || size > uint64(r.Identity.Size)-offset {
		return out, metadata.ErrMalformedMetadata
	}
	if size > uint64(limit) {
		return out, metadata.ErrLimit
	}
	body := make([]byte, int(size))
	if _, err := f.ReadAt(body, int64(offset)); err != nil {
		return out, metadata.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.Documents = []metadata.MetadataDocument{{Resource: metadata.ResourceReference{Payload: r.Identity, Member: "wim.xml"}, Format: metadata.FormatWIMXML, Original: body, Provenance: "uupbuilder:wim-xml-resource-v1"}}
	return out, nil
}
