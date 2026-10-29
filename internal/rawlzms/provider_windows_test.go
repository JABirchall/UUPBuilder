//go:build windows

package rawlzms

import (
	"context"
	"errors"
	"testing"
)

func TestDecodeBoundsAndProviderCannotBeRedirected(t *testing.T) {
	for _, v := range []struct {
		b []byte
		n int
	}{{nil, 1}, {[]byte{1}, 0}, {make([]byte, MaxBytes+1), 1}, {[]byte{1}, MaxBytes + 1}} {
		if _, err := Decode(context.Background(), "not-a-provider", v.b, v.n); !errors.Is(err, ErrLimit) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Decode(ctx, "not-a-provider", []byte{1}, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := Decode(context.Background(), "not-a-provider", []byte{1}, 1); !errors.Is(err, ErrProvider) {
		t.Fatal(err)
	}
}

func TestSystemProviderIdentityAndClosedLifetime(t *testing.T) {
	path, err := SystemPath()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Identity().Name != "cabinet.dll" || len(p.Identity().SHA256) != 64 || p.Identity().Size <= 0 {
		t.Fatal("unmeasured provider")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Decode(context.Background(), []byte{'x'}, 1); err == nil {
		t.Fatal("closed provider remained usable")
	}
}
