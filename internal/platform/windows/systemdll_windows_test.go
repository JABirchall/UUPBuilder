package windows

import (
	"context"
	"errors"
	"testing"
)

func TestSystemDLLIsInstalledMeasuredAndCloseRevokesExports(t *testing.T) {
	for _, bad := range []string{"../cabinet.dll", `C:\Windows\System32\cabinet.dll`, "CABINET.DLL", "a.dll/../cabinet.dll"} {
		if p, e := OpenSystemDLL(context.Background(), bad); e == nil {
			p.Close()
			t.Fatalf("unsafe basename accepted: %s", bad)
		}
	}
	p, e := OpenSystemDLL(context.Background(), "cabinet.dll")
	if e != nil {
		t.Fatal("installed provider unavailable", e)
	}
	id := p.Identity()
	if id.Name != "cabinet.dll" || len(id.SHA256) != 64 || id.Size <= 0 {
		t.Fatal("unmeasured identity", id)
	}
	if v, e := p.Proc("FDICreate"); e != nil || v == 0 {
		t.Fatal("missing installed FDI", e)
	}
	if e := p.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Proc("FDICreate"); e == nil {
		t.Fatal("closed lifetime exported callable address")
	}
}

func TestSystemDLLCanceledCloseStillRevokesExports(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p, e := OpenSystemDLL(ctx, "cabinet.dll")
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	if !errors.Is(p.Close(), context.Canceled) {
		t.Fatal("provider cancellation lost")
	}
	if _, e := p.Proc("FDICreate"); e == nil {
		t.Fatal("canceled close retained callable export")
	}
}
