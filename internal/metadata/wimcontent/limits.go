// Package wimcontent verifies exact indexed WIM file bytes using bounded data
// decoding. It grants no image operation, metadata semantics or conversion.
package wimcontent

import (
	"errors"
)

var ErrInput = errors.New("unbound WIM content input")
var ErrIntegrity = errors.New("WIM content integrity changed")
var ErrLayout = errors.New("malformed WIM content framing")
var ErrLimit = errors.New("WIM content limit exceeded")
var ErrUnsupported = errors.New("WIM content implementation gap")
var ErrConflict = errors.New("conflicting WIM content bytes")

// Zero selects hard ceilings; callers can only lower them. Result accounting
// reserves index traversal/reparse, records, framing, maps and seal copies. It
// excludes existing caller/index/oracle memory, caller accessor copies, runtime,
// native codec memory/DLL mappings and filesystem allocation/journal overhead.
type Limits struct {
	MaxSources, MaxManifestPayloads, MaxQueries, MaxProjectionPayloads, MaxVariableBytes, MaxPathBytes                    int
	MaxEntries, MaxResources, MaxChunks, MaxTotalChunks, MaxChunkBytes, MaxBufferBytes                                    int
	MaxManifestBytes, MaxSourceBytes, MaxTotalSourceBytes, MaxResourceBytes, MaxOutputBytes, MaxReadBytes, MaxResultBytes uint64
}

func bounds(l Limits) (Limits, error) {
	for i, p := range []*int{&l.MaxSources, &l.MaxManifestPayloads, &l.MaxQueries, &l.MaxProjectionPayloads, &l.MaxVariableBytes, &l.MaxPathBytes, &l.MaxEntries, &l.MaxResources, &l.MaxChunks, &l.MaxTotalChunks, &l.MaxChunkBytes, &l.MaxBufferBytes} {
		cap := []int{64, 4096, 64, 4096, 4096, 32768, 524288, 256, 131072, 262144, 64 << 20, 128 << 20}[i]
		if *p < 0 || *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	for i, p := range []*uint64{&l.MaxManifestBytes, &l.MaxSourceBytes, &l.MaxTotalSourceBytes, &l.MaxResourceBytes, &l.MaxOutputBytes, &l.MaxReadBytes, &l.MaxResultBytes} {
		cap := []uint64{16 << 20, 4 << 30, 8 << 30, 4 << 30, 8 << 30, 64 << 30, 512 << 20}[i]
		if *p > cap {
			return l, ErrLimit
		}
		if *p == 0 {
			*p = cap
		}
	}
	return l, nil
}
