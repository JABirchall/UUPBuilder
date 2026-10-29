package metadata

import (
	"bytes"
	"context"
	"errors"

	"uupbuilder/internal/metadata/cabformat"
)

const MaxMetadataCABBytes = 32 << 20

type CABMember struct {
	Name                 string
	Size, Offset, Folder int
}
type CABInventory struct {
	CabinetBytes, TrailingBytes, DecodedBytes int
	Members                                   []CABMember
}

// InspectCAB preserves the read-only metadata adapter's historical 32 MiB
// source, 1024-folder/member, 16 MiB/member, 128 MiB declared output and strict
// flat ASCII name policy. Framing is shared with the separately bounded content
// adapter; this directory alone does not establish verified artifact authority.
func InspectCAB(ctx context.Context, b []byte) (out CABInventory, err error) {
	if ctx == nil {
		return out, ErrInvalidInput
	}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	v, e := cabformat.Inspect(ctx, bytes.NewReader(b), uint64(len(b)), cabformat.Limits{MaxSourceBytes: MaxMetadataCABBytes, MaxMemberBytes: 16 << 20, MaxDecodedBytes: 128 << 20, MaxMetadataBytes: MaxMetadataCABBytes, MaxFolders: 1024, MaxMembers: 1024, MaxNameBytes: 255, FlatASCII: true})
	if e != nil {
		if errors.Is(e, cabformat.ErrLimit) {
			return out, ErrLimit
		}
		if errors.Is(e, cabformat.ErrLayout) || errors.Is(e, cabformat.ErrUnsupported) {
			return out, ErrMalformedMetadata
		}
		return out, e
	}
	out.CabinetBytes = int(v.CabinetBytes)
	out.TrailingBytes = int(v.TrailingBytes)
	out.DecodedBytes = int(v.DecodedBytes)
	for _, m := range v.Members {
		out.Members = append(out.Members, CABMember{m.Name, int(m.Size), int(m.Offset), m.Folder})
	}
	return out, nil
}
