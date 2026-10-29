package wimmeta

import (
	"bytes"
	"context"
	"slices"
)

type SourceEA struct {
	Offset      int
	Flags       byte
	Name, Value []byte
}

// DecodeSourceEAs interprets only the pinned tag-2 packed record framing from
// wimlib v1.14.5 xattr.h. Values and flags are opaque preservation bytes.
// Unlike public producer options, these are residual allowances: zero refuses.
func DecodeSourceEAs(ctx context.Context, raw []byte, maxRecords int, allowance uint64) ([]SourceEA, uint64, error) {
	if ctx == nil {
		return nil, 0, ErrInput
	}
	if len(raw) > 1<<20 || maxRecords < 0 || maxRecords > 65536 {
		return nil, 0, ErrLimit
	}
	cost, count := uint64(128), 0
	for at := 0; at < len(raw); {
		if e := ctx.Err(); e != nil {
			return nil, 0, e
		}
		if len(raw)-at < 4 {
			return nil, 0, ErrLayout
		}
		n, v := int(raw[at+2]), int(disk.Uint16(raw[at:]))
		end := at + 4 + n + 1 + v
		if n == 0 || end > len(raw) || raw[at+4+n] != 0 || bytes.IndexByte(raw[at+4:at+4+n], 0) >= 0 {
			return nil, 0, ErrLayout
		}
		if count >= maxRecords {
			return nil, 0, ErrLimit
		}
		count++
		cost += uint64(128 + (n+v)*2)
		if cost > allowance {
			return nil, 0, ErrLimit
		}
		at = end
	}
	if cost > allowance {
		return nil, 0, ErrLimit
	}
	result := make([]SourceEA, 0, count)
	for at := 0; at < len(raw); {
		n, v := int(raw[at+2]), int(disk.Uint16(raw[at:]))
		result = append(result, SourceEA{at, raw[at+3], slices.Clone(raw[at+4 : at+4+n]), slices.Clone(raw[at+5+n : at+5+n+v])})
		at += 5 + n + v
	}
	if e := ctx.Err(); e != nil {
		return nil, 0, e
	}
	return result, cost, nil
}

// InspectSecurity reuses the original security framing parser for an observed
// self-relative descriptor. It produces data only, never an Oracle or source
// authority. Raw descriptors and every semantic gap remain independent copies.
func InspectSecurity(ctx context.Context, raw []byte, allowance uint64) (Security, []Gap, uint64, error) {
	if ctx == nil {
		return Security{}, nil, 0, ErrInput
	}
	if len(raw) > 1<<20 || allowance > 512<<20 {
		return Security{}, nil, 0, ErrLimit
	}
	base := uint64(4096 + len(raw)*2)
	if base > allowance {
		return Security{}, nil, 0, ErrLimit
	}
	l, e := bounds(Limits{MaxResultBytes: allowance})
	if e != nil {
		return Security{}, nil, 0, e
	}
	p := parser{ctx: ctx, limits: l, used: base}
	s := Security{Raw: slices.Clone(raw)}
	if e = p.descriptor(&s, 0, 0); e != nil {
		return Security{}, nil, 0, e
	}
	if e = ctx.Err(); e != nil {
		return Security{}, nil, 0, e
	}
	return s, p.state.Gaps, p.used, nil
}
