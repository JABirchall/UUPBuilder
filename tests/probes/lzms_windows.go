//go:build windows

package probes

import (
	"context"

	"uupbuilder/internal/rawlzms"
)

// nativeLZMS keeps the historical bounded RAW LZMS probe contract. The shared
// primitive loads only the absolute installed System32 cabinet.dll provider.
func nativeLZMS(ctx context.Context, path string, compressed []byte, size int) (output []byte, runErr error) {
	return rawlzms.Decode(ctx, path, compressed, size)
}
