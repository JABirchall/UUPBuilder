package rawlzms

import (
	"context"
	"errors"
)

const MaxSolidBytes = 64 << 20

var ErrSolidLimit = errors.New("native solid LZMS input/output exceeds bounded 64 MiB contract")

// SolidLimits is a separate source-data contract. Zero selects the fixed hard
// ceiling; positive values can only lower it. It never changes MaxBytes or the
// historical probe/metadata APIs. OS internal codec memory is separate.
type SolidLimits struct{ MaxInputBytes, MaxOutputBytes int }

// SolidProvider only uses the measured installed OS provider. DecodeInto borrows
// exactly one input/output pair; the caller retains them after the synchronous,
// noninterruptible call. Cancellation is checked before and after native work.
type SolidProvider struct {
	provider *Provider
	limits   SolidLimits
}

func OpenSolid(ctx context.Context, l SolidLimits) (*SolidProvider, error) {
	if ctx == nil {
		return nil, ErrProvider
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	for _, v := range []*int{&l.MaxInputBytes, &l.MaxOutputBytes} {
		if *v < 0 || *v > MaxSolidBytes {
			return nil, ErrSolidLimit
		}
		if *v == 0 {
			*v = MaxSolidBytes
		}
	}
	path, e := SystemPath()
	if e != nil {
		return nil, e
	}
	p, e := Open(ctx, path)
	if e != nil {
		return nil, e
	}
	return &SolidProvider{p, l}, nil
}
func (p *SolidProvider) Identity() Identity { return p.provider.Identity() }
func (p *SolidProvider) Close() error       { return p.provider.Close() }
func (p *SolidProvider) DecodeInto(ctx context.Context, b, out []byte) error {
	if ctx == nil {
		return ErrProvider
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if len(b) == 0 || len(out) == 0 || len(b) > p.limits.MaxInputBytes || len(out) > p.limits.MaxOutputBytes {
		return ErrSolidLimit
	}
	return p.provider.decodeInto(ctx, b, out)
}
