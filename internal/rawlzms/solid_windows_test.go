package rawlzms

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestSolidContractKeepsLegacyBoundAndRejectsBeforeProvider(t *testing.T) {
	if _, e := Decode(context.Background(), "invalid", []byte{1}, (1<<20)+1); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	for _, l := range []SolidLimits{{MaxInputBytes: (64 << 20) + 1}, {MaxOutputBytes: -1}} {
		if p, e := OpenSolid(context.Background(), l); e == nil || p != nil {
			t.Fatal("raised solid ceiling", e)
		}
	}
	p, e := OpenSolid(context.Background(), SolidLimits{MaxInputBytes: 1, MaxOutputBytes: 2})
	if e != nil {
		t.Fatal(e)
	}
	if e = p.DecodeInto(context.Background(), []byte{1, 2}, make([]byte, 2)); !errors.Is(e, ErrSolidLimit) {
		t.Fatal("input lower bound", e)
	}
	if e = p.DecodeInto(context.Background(), []byte{1}, make([]byte, 3)); !errors.Is(e, ErrSolidLimit) {
		t.Fatal("output lower bound", e)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	if e = p.DecodeInto(context.Background(), []byte{1}, make([]byte, 2)); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed lifetime", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = OpenSolid(ctx, SolidLimits{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
