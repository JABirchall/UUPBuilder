//go:build windows

package probes

import (
	"context"
	"errors"
	"testing"
)

func TestNativeLZMSRejectsUnboundedInputsBeforeLoadingProvider(t *testing.T) {
	for _, test := range []struct {
		input []byte
		size  int
	}{{nil, 3}, {[]byte("x"), 0}, {[]byte("x"), (1 << 20) + 1}, {make([]byte, (1<<20)+1), 3}} {
		if _, err := nativeLZMS(context.Background(), "not-a-provider", test.input, test.size); err == nil {
			t.Fatal("unbounded native decompression accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := nativeLZMS(ctx, "not-a-provider", []byte("x"), 3); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was not checked before loading provider: %v", err)
	}
}
