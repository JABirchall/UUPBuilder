package engine

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func callbackPath(t *testing.T, h *applyCallbackHub, token uintptr, msg uint32, name string) uintptr {
	t.Helper()
	u, e := windows.UTF16FromString(name)
	if e != nil {
		t.Fatal(e)
	}
	process := int32(1)
	var pin runtime.Pinner
	pin.Pin(&process)
	pin.Pin(&u[0])
	defer pin.Unpin()
	ret := h.deliver(token, msg, uintptr(unsafe.Pointer(&u[0])), uintptr(unsafe.Pointer(&process)))
	runtime.KeepAlive(u)
	return ret
}

// Dropping path validation, returning abort from FILEINFO, or treating progress
// as completion breaks this test. All native calls here are synthetic delivery.
func TestFixedApplyCallbackCopiesBoundsAndDocumentedAbortPoints(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	h := &applyCallbackHub{}
	s, e := h.begin(ctx, `C:\owned`, map[string]bool{".": true, "known": true}, applyCallbackLimits{})
	if e != nil {
		t.Fatal(e)
	}
	if r := callbackPath(t, h, s.token, 0x9479, `C:\owned\known`); r != 0 {
		t.Fatal(r)
	} // PROCESS
	if r := h.deliver(s.token, 0x9478, 100, 0); r != 0 {
		t.Fatal(r)
	}
	if s.snapshot().Returned {
		t.Fatal("progress fabricated completion")
	}
	info := windows.Win32finddata{FileAttributes: 32, Reserved0: 7, Reserved1: 8}
	u, _ := windows.UTF16FromString(`C:\owned\known`)
	var pin runtime.Pinner
	pin.Pin(&info)
	pin.Pin(&u[0])
	defer pin.Unpin()
	if r := h.deliver(s.token, 0x9483, uintptr(unsafe.Pointer(&u[0])), uintptr(unsafe.Pointer(&info))); r != 0 {
		t.Fatal(r)
	}
	u[3] = 'X'
	info.Reserved0 = 99
	v := s.snapshot()
	if v.LastFile.Path != `C:\owned\known` || v.LastFile.Data.Reserved0 != 7 {
		t.Fatal("native pointer retained", v.LastFile)
	}
	if r := callbackPath(t, h, s.token, 0x9479, `C:\owned-other\known`); r != 0xffffffff {
		t.Fatal("outside path allowed", r)
	}
	if s.snapshot().Failure == nil {
		t.Fatal("outside path omitted")
	}
	cancel()
	if r := h.deliver(s.token, 0x948e, 0, 0); r != 0xffffffff {
		t.Fatal("QUERY_ABORT did not abort", r)
	}
	if !s.snapshot().AbortDelivered {
		t.Fatal("abort delivery omitted")
	}
	if e := h.retire(s, true); e != nil {
		t.Fatal(e)
	}
	if r := h.deliver(s.token, 0x9479, 1, 1); r != 0xffffffff {
		t.Fatal("late callback touched stale data", r)
	}
	runtime.KeepAlive(u)
	runtime.KeepAlive(info)
}

func TestFixedApplyCallbackConcurrentDrainAndQuarantine(t *testing.T) {
	h := &applyCallbackHub{}
	s, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true}, applyCallbackLimits{MaxDeliveries: 8})
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for j := 0; j < 32; j++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.deliver(s.token, 0x9478, 100, 0) }()
	}
	wg.Wait()
	if !errors.Is(s.snapshot().Failure, ErrLimit) {
		t.Fatal("concurrent budget overrun accepted", s.snapshot())
	}
	// Model a delivery already admitted by the hub. Retirement must wait for
	// that copied delivery before releasing its slot.
	h.mu.Lock()
	s.inflight++
	h.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- h.retire(s, true) }()
	select {
	case <-done:
		t.Fatal("retired before drain")
	case <-time.After(10 * time.Millisecond):
	}
	h.mu.Lock()
	s.inflight--
	h.condition().Broadcast()
	h.mu.Unlock()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	next, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true}, applyCallbackLimits{})
	if e != nil || next.token == s.token {
		t.Fatal("token reused", e)
	}
	if e = h.retire(next, false); e == nil {
		t.Fatal("failed unregister forgotten")
	}
	if _, e = h.begin(context.Background(), filepath.Clean(`C:\owned`), map[string]bool{".": true}, applyCallbackLimits{}); e == nil {
		t.Fatal("quarantined slot reused")
	}
	if r := h.deliver(next.token, 0x9483, 1, 1); r != 0 {
		t.Fatal("FILEINFO invalid return", r)
	}
}

func TestFixedApplyCallbackUnknownMalformedAndOversizeRefuse(t *testing.T) {
	for _, kind := range []string{"unknown-name", "nil-process", "nil-fileinfo", "invalid-pointer", "unterminated", "malformed-utf16", "unknown-message", "native-error", "warning"} {
		t.Run(kind, func(t *testing.T) {
			h := &applyCallbackHub{}
			s, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true, "known": true}, applyCallbackLimits{})
			if e != nil {
				t.Fatal(e)
			}
			var pin runtime.Pinner
			defer pin.Unpin()
			path, _ := windows.UTF16FromString(`C:\owned\known`)
			pin.Pin(&path[0])
			wp := uintptr(unsafe.Pointer(&path[0]))
			switch kind {
			case "unknown-name":
				callbackPath(t, h, s.token, 0x9479, `C:\owned\foreign`)
			case "nil-process":
				h.deliver(s.token, 0x9479, wp, 0)
			case "nil-fileinfo":
				h.deliver(s.token, 0x9483, wp, 0)
			case "invalid-pointer":
				h.deliver(s.token, 0x9483, 2, 2)
			case "unterminated":
				u := make([]uint16, 4096)
				for j := range u {
					u[j] = 'a'
				}
				pin.Pin(&u[0])
				h.deliver(s.token, 0x9479, uintptr(unsafe.Pointer(&u[0])), 0)
			case "malformed-utf16":
				u := []uint16{0xd800, 0}
				pin.Pin(&u[0])
				h.deliver(s.token, 0x9479, uintptr(unsafe.Pointer(&u[0])), 0)
			case "unknown-message":
				h.deliver(s.token, 0x9499, 1, 1)
			case "native-error":
				if v := h.deliver(s.token, 0x947f, wp, 5); v != 0 {
					t.Fatal("native error skipped", v)
				}
			case "warning":
				h.deliver(s.token, 0x9485, wp, 5)
			}
			if s.snapshot().Failure == nil {
				t.Fatal("incomplete callback evidence accepted", kind)
			}
			if ret := h.deliver(s.token, 0x948e, 0, 0); ret != 0xffffffff {
				t.Fatal("failure did not request documented abort", ret)
			}
			if e = h.retire(s, true); e != nil {
				t.Fatal(e)
			}
		})
	}
}
