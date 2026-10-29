// Package rawlzms provides bounded data decompression using the installed OS
// Compression API. It has no WIM/image operations or target-supplied providers.
package rawlzms

import (
	"context"
	"errors"
)

const MaxBytes = 1 << 20

var ErrLimit = errors.New("native LZMS input/output exceeds 1 MiB bound")
var ErrProvider = errors.New("native LZMS provider must be pinned System32 cabinet.dll")

type Identity struct {
	Name, SHA256 string
	Size         int64
}

func bounds(ctx context.Context, b []byte, size int) error {
	if ctx == nil {
		return errors.New("nil LZMS context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(b) == 0 || len(b) > MaxBytes || size <= 0 || size > MaxBytes {
		return ErrLimit
	}
	return nil
}

// Decode retains the historical probe contract, including rejecting input
// bounds/cancellation before resolving or loading any provider.
func Decode(ctx context.Context, path string, b []byte, size int) (out []byte, err error) {
	if err = bounds(ctx, b, size); err != nil {
		return nil, err
	}
	p, err := Open(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, p.Close())
		if err != nil {
			out = nil
		}
	}()
	return p.Decode(ctx, b, size)
}
