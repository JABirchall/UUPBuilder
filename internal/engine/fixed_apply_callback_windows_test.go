package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func callbackFileInfo(t *testing.T, h *applyCallbackHub, token uintptr, name string, info *windows.Win32finddata) uintptr {
	t.Helper()
	u, e := windows.UTF16FromString(name)
	if e != nil {
		t.Fatal(e)
	}
	var pin runtime.Pinner
	pin.Pin(info)
	pin.Pin(&u[0])
	defer pin.Unpin()
	ret := h.deliver(token, 0x9483, uintptr(unsafe.Pointer(&u[0])), uintptr(unsafe.Pointer(info)))
	runtime.KeepAlive(info)
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

func TestFixedApplyCallbackKnownRefusalsMalformedAndOversizeRefuse(t *testing.T) {
	for _, kind := range []string{"unknown-name", "nil-process", "nil-fileinfo", "invalid-pointer", "unterminated", "malformed-utf16", "known-operation", "native-error", "warning"} {
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
			case "known-operation":
				h.deliver(s.token, 0x9480, 1, 1)
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

type opaqueCallbackRecord struct {
	MessageID   uint32
	Count       uint64
	ReturnValue uint32
}

type unconsumedCallbackRecord struct {
	Unconsumed                   [16]opaqueCallbackRecord
	UnconsumedOverflowDeliveries uint64
}

func unconsumedRecord(t *testing.T, v applyCallbackEvidence) unconsumedCallbackRecord {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var record unconsumedCallbackRecord
	if e = json.Unmarshal(b, &record); e != nil {
		t.Fatal(e)
	}
	return record
}

func metadataExcludeRecord(t *testing.T, v applyCallbackEvidence) opaqueCallbackRecord {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var exported struct{ OpaqueMetadataExclude opaqueCallbackRecord }
	if e = json.Unmarshal(b, &exported); e != nil {
		t.Fatal(e)
	}
	return exported.OpaqueMetadataExclude
}

// Invalid words must never be treated as addresses or exclusion decisions.
// Following them with real valid callback payloads exposes a spurious failure
// latch that merely returning SUCCESS from the opaque message would hide.
func TestFixedApplyCallbackOpaqueMetadataExcludeContinuesWithoutParameterUse(t *testing.T) {
	h := &applyCallbackHub{}
	s, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true, "known": true}, applyCallbackLimits{})
	if e != nil {
		t.Fatal(e)
	}
	for _, words := range [][2]uintptr{{1, ^uintptr(0)}, {0, 2}} {
		if ret := h.deliver(s.token, 0x9495, words[0], words[1]); ret != 0 {
			t.Fatal("opaque notification did not return SUCCESS", ret)
		}
	}
	first, second := uint32(7), uint32(11)
	info := windows.Win32finddata{FileAttributes: 32, Reserved0: 17}
	path, _ := windows.UTF16FromString(`C:\owned\known`)
	var pin runtime.Pinner
	pin.Pin(&first)
	pin.Pin(&second)
	pin.Pin(&info)
	pin.Pin(&path[0])
	defer pin.Unpin()
	if ret := h.deliver(s.token, 0x9495, uintptr(unsafe.Pointer(&first)), uintptr(unsafe.Pointer(&second))); ret != 0 || first != 7 || second != 11 {
		t.Fatal("opaque notification changed caller values", ret, first, second)
	}
	if ret := callbackPath(t, h, s.token, 0x9479, `C:\owned\known`); ret != 0 {
		t.Fatal("PROCESS aborted after opaque notification", ret)
	}
	if ret := h.deliver(s.token, 0x9483, uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(&info))); ret != 0 {
		t.Fatal("FILEINFO response changed", ret)
	}
	v := s.snapshot()
	if v.Failure != nil || v.AbortDelivered || v.Returned || v.LastFile.Path != `C:\owned\known` || v.LastFile.Data.Reserved0 != 17 {
		t.Fatal("opaque notification changed later validation or minted completion", v.FailureText, v.AbortDelivered, v.Returned, v.LastFile.Path)
	}
	if got := metadataExcludeRecord(t, v); got != (opaqueCallbackRecord{MessageID: 0x9495, Count: 3, ReturnValue: 0}) {
		t.Fatalf("opaque dispatch evidence %+v", got)
	}
	if e = h.retire(s, true); e != nil {
		t.Fatal(e)
	}
	runtime.KeepAlive(first)
	runtime.KeepAlive(second)
	runtime.KeepAlive(info)
	runtime.KeepAlive(path)
}

func TestFixedApplyCallbackFeedbackKeepsFailureAndCancellation(t *testing.T) {
	kinds := []string{"outside-path", "outside-fileinfo", "cancel", "error", "info", "warning", "object-id", "text", "compress", "alignment", "retry", "split", "stale-mount-dir", "stale-mount-file", "mount-cleanup-progress", "cleanup-scanning-drive", "already-mounted", "cleanup-unmount", "bad-percent"}
	if ^uintptr(0) > 0xffffffff {
		kinds = append(kinds, "bad-time")
	}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := &applyCallbackHub{}
			s, e := h.begin(ctx, `C:\owned`, map[string]bool{".": true, "known": true}, applyCallbackLimits{})
			if e != nil {
				t.Fatal(e)
			}
			h.deliver(s.token, 0x9498, 1, ^uintptr(0))
			if v := s.snapshot(); v.Failure != nil {
				t.Fatal("unconsumed setup message poisoned later refusal test", v.FailureText)
			}
			if kind == "cancel" {
				cancel()
			} else if kind == "outside-path" {
				callbackPath(t, h, s.token, 0x9479, `C:\owned\foreign`)
			} else if kind == "outside-fileinfo" {
				path, _ := windows.UTF16FromString(`C:\owned\foreign`)
				info := windows.Win32finddata{FileAttributes: 32}
				var pin runtime.Pinner
				pin.Pin(&path[0])
				pin.Pin(&info)
				h.deliver(s.token, 0x9483, uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(&info)))
				pin.Unpin()
				runtime.KeepAlive(path)
				runtime.KeepAlive(info)
			} else if msg := map[string]uint32{"text": 0x9477, "compress": 0x947e, "alignment": 0x9480, "retry": 0x9481, "split": 0x9482, "stale-mount-dir": 0x9488, "stale-mount-file": 0x9489, "mount-cleanup-progress": 0x948a, "cleanup-scanning-drive": 0x948b, "already-mounted": 0x948c, "cleanup-unmount": 0x948d}[kind]; msg != 0 {
				h.deliver(s.token, msg, 1, ^uintptr(0))
			} else if kind == "bad-percent" {
				h.deliver(s.token, 0x9478, 101, 0)
			} else if kind == "bad-time" {
				h.deliver(s.token, 0x9478, 1, ^uintptr(0))
			} else {
				msg := map[string]uint32{"error": 0x947f, "info": 0x9484, "warning": 0x9485, "object-id": 0x9487}[kind]
				path, _ := windows.UTF16FromString(`C:\owned\known`)
				var pin runtime.Pinner
				pin.Pin(&path[0])
				h.deliver(s.token, msg, uintptr(unsafe.Pointer(&path[0])), 5)
				pin.Unpin()
				runtime.KeepAlive(path)
			}
			before := s.snapshot()
			if kind != "cancel" && before.Failure == nil {
				t.Fatal("existing failure was not latched")
			}
			for _, msg := range []uint32{0x947a, 0x947b, 0x947c, 0x947d, 0x9478, 0x9495, 0x9498, 0x9494, 0x9496, 0, 0xdeadbeef} {
				if ret := h.deliver(s.token, msg, 1, ^uintptr(0)); ret != 0 {
					t.Fatal("feedback used an undocumented abort return", msg, ret)
				}
			}
			after := s.snapshot()
			if after.Failure != before.Failure || after.FailureText != before.FailureText || kind == "cancel" && !after.CancellationRequested {
				t.Fatal("feedback cleared failure/cancel")
			}
			if unconsumedRecord(t, after) != unconsumedRecord(t, before) || unconsumedRecord(t, after).Unconsumed[0] != (opaqueCallbackRecord{MessageID: 0x9498, Count: 1, ReturnValue: 0}) {
				t.Fatal("unconsumed healthy evidence grew or was cleared after refusal/cancel")
			}
			if got := metadataExcludeRecord(t, after); got.Count != 0 {
				t.Fatalf("failed/cancelled dispatch counted as healthy opaque handling: %+v", got)
			}
			if ret := h.deliver(s.token, 0x948e, 0, 0); ret != 0xffffffff {
				t.Fatal("documented abort point bypassed", ret)
			}
			if !s.snapshot().AbortDelivered {
				t.Fatal("abort evidence lost")
			}
			if e = h.retire(s, true); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestFixedApplyCallbackUnconsumedDefaultAllowsFollowingFileCallbacks(t *testing.T) {
	for _, msg := range []uint32{0x9498, 0x9499, 0x9486, 0x948f, 0x9493, 0x9494, 0x9496, 0, 0x9476, 0x12345678, 0xffffffff, 0xdeadbeef} {
		t.Run(fmt.Sprintf("%x", msg), func(t *testing.T) {
			h := &applyCallbackHub{}
			s, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true, "known": true}, applyCallbackLimits{})
			if e != nil {
				t.Fatal(e)
			}
			for _, words := range [][2]uintptr{{0, 0}, {1, ^uintptr(0)}} {
				if ret := h.deliver(s.token, msg, words[0], words[1]); ret != 0 {
					t.Fatal("unconsumed default did not return SUCCESS", ret)
				}
			}
			first, second := uint32(7), uint32(11)
			var pin runtime.Pinner
			pin.Pin(&first)
			pin.Pin(&second)
			defer pin.Unpin()
			if ret := h.deliver(s.token, msg, uintptr(unsafe.Pointer(&first)), uintptr(unsafe.Pointer(&second))); ret != 0 {
				t.Fatal(ret)
			}
			processRet := callbackPath(t, h, s.token, 0x9479, `C:\owned\known`)
			info := windows.Win32finddata{FileAttributes: 32, Reserved0: 43}
			fileRet := callbackFileInfo(t, h, s.token, `C:\owned\known`, &info)
			info.Reserved0 = 99
			v := s.snapshot()
			if processRet != 0 || fileRet != 0 || v.Failure != nil || v.LastFile.Path != `C:\owned\known` || v.LastFile.Data.Reserved0 != 43 {
				t.Fatalf("unconsumed %#x poisoned PROCESS/FILEINFO: process=%#x file=%#x failure=%s", msg, processRet, fileRet, v.FailureText)
			}
			if first != 7 || second != 11 || v.Deliveries != 5 || v.Returned || v.AbortDelivered || v.Progress != 0 || v.OpaqueMetadataExclude.Count != 0 {
				t.Fatal("unconsumed delivery changed memory, consumed evidence or completion")
			}
			var want unconsumedCallbackRecord
			want.Unconsumed[0] = opaqueCallbackRecord{MessageID: msg, Count: 3, ReturnValue: 0}
			if got := unconsumedRecord(t, v); got != want {
				t.Fatalf("default evidence %+v", got)
			}
			if e = h.retire(s, true); e != nil {
				t.Fatal(e)
			}
			runtime.KeepAlive(first)
			runtime.KeepAlive(second)
		})
	}
}

func TestFixedApplyCallbackUnconsumedTableOverflowCapAndLifetime(t *testing.T) {
	h := &applyCallbackHub{}
	s, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true, "known": true}, applyCallbackLimits{MaxDeliveries: 105})
	if e != nil {
		t.Fatal(e)
	}
	for msg := uint32(0); msg < 16; msg++ {
		h.deliver(s.token, msg, 1, ^uintptr(0))
	}
	h.deliver(s.token, 0, 1, ^uintptr(0))
	for msg := uint32(16); msg < 96; msg++ {
		h.deliver(s.token, msg, 1, ^uintptr(0))
	}
	h.deliver(s.token, 95, 1, ^uintptr(0))
	h.deliver(s.token, 0, 1, ^uintptr(0))
	if ret := callbackPath(t, h, s.token, 0x9479, `C:\owned\known`); ret != 0 {
		t.Fatal("table saturation caused latent PROCESS abort", ret)
	}
	info := windows.Win32finddata{FileAttributes: 32, Reserved0: 47}
	if ret := callbackFileInfo(t, h, s.token, `C:\owned\known`, &info); ret != 0 {
		t.Fatal(ret)
	}
	if ret := h.deliver(s.token, 0x948e, 0, 0); ret != 0 {
		t.Fatal("table saturation requested abort", ret)
	}
	v := s.snapshot()
	record := unconsumedRecord(t, v)
	if v.Failure != nil || v.Returned || v.AbortDelivered || v.Deliveries != 102 || v.LastFile.Data.Reserved0 != 47 || record.UnconsumedOverflowDeliveries != 81 {
		t.Fatal("opaque table saturation did not summarize healthy deliveries", v.FailureText, v.Deliveries, record.UnconsumedOverflowDeliveries)
	}
	for j, entry := range record.Unconsumed {
		wantCount := uint64(1)
		if j == 0 {
			wantCount = 3
		}
		if entry != (opaqueCallbackRecord{MessageID: uint32(j), Count: wantCount, ReturnValue: 0}) {
			t.Fatalf("table slot %d lost first-distinct ID/count: %+v", j, entry)
		}
	}
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var exported map[string]json.RawMessage
	if e = json.Unmarshal(b, &exported); e != nil {
		t.Fatal(e)
	}
	var rows []map[string]json.RawMessage
	if e = json.Unmarshal(exported["Unconsumed"], &rows); e != nil || len(rows) != 16 || len(exported["Unconsumed"]) > 1280 {
		t.Fatal("unconsumed evidence is not a fixed bounded table", e, len(rows))
	}
	for _, row := range rows {
		if len(row) != 3 || row["MessageID"] == nil || row["Count"] == nil || row["ReturnValue"] == nil {
			t.Fatal("opaque evidence captured more than ID/count/return")
		}
	}
	for j := 0; j < 4; j++ {
		h.deliver(s.token, 0, 1, ^uintptr(0))
	}
	v = s.snapshot()
	record = unconsumedRecord(t, v)
	if !errors.Is(v.Failure, ErrLimit) || v.Deliveries != 105 || record.Unconsumed[0].Count != 6 || record.UnconsumedOverflowDeliveries != 81 {
		t.Fatal("unconsumed callback bypassed total cap", v.Deliveries, v.FailureText, record)
	}
	if ret := h.deliver(s.token, 0x948e, 0, 0); ret != 0xffffffff {
		t.Fatal("capped default did not abort", ret)
	}
	if e = h.retire(s, true); e != nil {
		t.Fatal(e)
	}
	before := s.snapshot()
	h.deliver(s.token, 0x9498, 1, ^uintptr(0))
	if s.snapshot() != before {
		t.Fatal("retired default grew evidence")
	}
	next, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true}, applyCallbackLimits{})
	if e != nil {
		t.Fatal(e)
	}
	h.deliver(s.token, 0x9498, 1, ^uintptr(0))
	if next.snapshot().Deliveries != 0 || unconsumedRecord(t, next.snapshot()) != (unconsumedCallbackRecord{}) {
		t.Fatal("stale default touched next generation")
	}
	if e = h.retire(next, false); e == nil {
		t.Fatal("failed unregister forgotten")
	}
	h.deliver(next.token, 0x9498, 1, ^uintptr(0))
	if next.snapshot().Deliveries != 0 || unconsumedRecord(t, next.snapshot()) != (unconsumedCallbackRecord{}) {
		t.Fatal("frozen default grew evidence")
	}
}

// An immediate SUCCESS is insufficient: the old unsupported branch returned
// it while poisoning the next valid PROCESS and suppressing FILEINFO copying.
func TestFixedApplyCallbackPassiveFeedbackAllowsFollowingFileCallbacks(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  uint32
	}{{"scanning", 0x947a}, {"set-range", 0x947b}, {"set-pos", 0x947c}} {
		t.Run(tc.name, func(t *testing.T) {
			h := &applyCallbackHub{}
			s, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true, "known": true}, applyCallbackLimits{})
			if e != nil {
				t.Fatal(e)
			}
			for _, words := range [][2]uintptr{{0, 0}, {0xffffffff, 0xffffffff}, {1, ^uintptr(0)}, {0, 2}} {
				if ret := h.deliver(s.token, tc.msg, words[0], words[1]); ret != 0 {
					t.Fatal("passive feedback did not return SUCCESS", ret)
				}
			}
			first, second := uint32(7), uint32(11)
			info := windows.Win32finddata{FileAttributes: 32, Reserved0: 23}
			path, _ := windows.UTF16FromString(`C:\owned\known`)
			var pin runtime.Pinner
			pin.Pin(&first)
			pin.Pin(&second)
			pin.Pin(&info)
			pin.Pin(&path[0])
			defer pin.Unpin()
			h.deliver(s.token, tc.msg, uintptr(unsafe.Pointer(&first)), uintptr(unsafe.Pointer(&second)))
			processRet := callbackPath(t, h, s.token, 0x9479, `C:\owned\known`)
			fileRet := h.deliver(s.token, 0x9483, uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(&info)))
			v := s.snapshot()
			if processRet != 0 || fileRet != 0 || v.Failure != nil || v.LastFile.Data.Reserved0 != 23 {
				t.Fatalf("feedback %#x poisoned PROCESS/FILEINFO: process=%#x file=%#x failure=%s", tc.msg, processRet, fileRet, v.FailureText)
			}
			if first != 7 || second != 11 || v.Deliveries != 7 || v.Progress != 0 || v.Returned || v.AbortDelivered || v.LastFile.Path != `C:\owned\known` || v.OpaqueMetadataExclude.Count != 0 {
				t.Fatal("passive feedback changed parameters, evidence or completion", first, second, v.Deliveries)
			}
			if e = h.retire(s, true); e != nil {
				t.Fatal(e)
			}
			runtime.KeepAlive(first)
			runtime.KeepAlive(second)
			runtime.KeepAlive(info)
			runtime.KeepAlive(path)
		})
	}
}

func TestFixedApplyCallbackPassiveFeedbackSequenceDoesNotComplete(t *testing.T) {
	h := &applyCallbackHub{}
	s, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true, "known": true}, applyCallbackLimits{})
	if e != nil {
		t.Fatal(e)
	}
	for _, msg := range []uint32{0x947a, 0x947b, 0x947c, 0x947d} {
		h.deliver(s.token, msg, 0, 0)
	}
	h.deliver(s.token, 0x9478, 37, 500)
	if ret := callbackPath(t, h, s.token, 0x9479, `C:\owned\known`); ret != 0 {
		t.Fatal("feedback sequence aborted PROCESS", ret)
	}
	if v := s.snapshot(); v.Progress != 37 || v.Returned {
		t.Fatal("file-count feedback replaced percent or completed application", v.Progress, v.Returned)
	}
	h.deliver(s.token, 0x947c, 0, 2)
	h.deliver(s.token, 0x947a, 1, 0)
	h.deliver(s.token, 0x9495, 1, ^uintptr(0))
	info := windows.Win32finddata{FileAttributes: 32, Reserved0: 31}
	path, _ := windows.UTF16FromString(`C:\owned\known`)
	var pin runtime.Pinner
	pin.Pin(&info)
	pin.Pin(&path[0])
	defer pin.Unpin()
	if ret := h.deliver(s.token, 0x9483, uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(&info))); ret != 0 {
		t.Fatal("interleaved feedback changed FILEINFO return", ret)
	}
	info.Reserved0 = 99
	path[3] = 'X'
	h.deliver(s.token, 0x947b, 0xffffffff, 0xffffffff)
	h.deliver(s.token, 0x947c, 1, ^uintptr(0))
	h.deliver(s.token, 0x947d, 1, ^uintptr(0))
	h.deliver(s.token, 0x9478, 100, 0xffffffff)
	h.deliver(s.token, 0x9495, 1, ^uintptr(0))
	if ret := h.deliver(s.token, 0x948e, 0, 0); ret != 0 {
		t.Fatal("healthy sequence requested abort", ret)
	}
	v := s.snapshot()
	if v.Failure != nil || v.Progress != 100 || v.Deliveries != 16 || v.Returned || v.AbortDelivered || v.LastFile.Path != `C:\owned\known` || v.LastFile.Data.Reserved0 != 31 {
		t.Fatal("feedback sequence corrupted evidence or fabricated completion", v.FailureText, v.Progress, v.Deliveries, v.Returned)
	}
	if got := metadataExcludeRecord(t, v); got != (opaqueCallbackRecord{MessageID: 0x9495, Count: 2, ReturnValue: 0}) {
		t.Fatalf("feedback changed existing opaque policy %+v", got)
	}
	if e = h.retire(s, true); e != nil {
		t.Fatal(e)
	}
	runtime.KeepAlive(info)
	runtime.KeepAlive(path)
}

func TestFixedApplyCallbackPassiveFeedbackBudgetAndLifetime(t *testing.T) {
	h := &applyCallbackHub{}
	s, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true}, applyCallbackLimits{MaxDeliveries: 3})
	if e != nil {
		t.Fatal(e)
	}
	for _, msg := range []uint32{0x947a, 0x947b, 0x947c} {
		h.deliver(s.token, msg, 1, ^uintptr(0))
	}
	if v := s.snapshot(); v.Failure != nil || v.Deliveries != 3 {
		t.Fatal("healthy feedback admission failed", v.Deliveries, v.FailureText)
	}
	for j := 0; j < 64; j++ {
		for _, msg := range []uint32{0x947a, 0x947b, 0x947c} {
			h.deliver(s.token, msg, 1, ^uintptr(0))
		}
	}
	if v := s.snapshot(); !errors.Is(v.Failure, ErrLimit) || v.Deliveries != 3 {
		t.Fatal("feedback bypassed delivery cap", v.Deliveries, v.FailureText)
	}
	if ret := h.deliver(s.token, 0x948e, 0, 0); ret != 0xffffffff {
		t.Fatal("exhausted feedback did not abort", ret)
	}
	if e = h.retire(s, true); e != nil {
		t.Fatal(e)
	}
	before := s.snapshot()
	for _, msg := range []uint32{0x947a, 0x947b, 0x947c} {
		if ret := h.deliver(s.token, msg, 1, ^uintptr(0)); ret != 0 {
			t.Fatal("late feedback returned abort", ret)
		}
	}
	if after := s.snapshot(); after != before {
		t.Fatal("late feedback touched retired evidence")
	}
	next, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true}, applyCallbackLimits{})
	if e != nil {
		t.Fatal(e)
	}
	for _, msg := range []uint32{0x947a, 0x947b, 0x947c} {
		h.deliver(s.token, msg, 1, ^uintptr(0))
	}
	if next.snapshot().Deliveries != 0 {
		t.Fatal("stale feedback touched next generation")
	}
	if e = h.retire(next, false); e == nil {
		t.Fatal("failed unregister forgotten")
	}
	for _, msg := range []uint32{0x947a, 0x947b, 0x947c} {
		h.deliver(next.token, msg, 1, ^uintptr(0))
	}
	if next.snapshot().Deliveries != 0 {
		t.Fatal("frozen feedback changed evidence")
	}
}

func TestFixedApplyCallbackOpaqueMetadataExcludeEvidenceStopsAtCapAndGeneration(t *testing.T) {
	h := &applyCallbackHub{}
	s, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true}, applyCallbackLimits{MaxDeliveries: 2})
	if e != nil {
		t.Fatal(e)
	}
	for j := 0; j < 2; j++ {
		if ret := h.deliver(s.token, 0x9495, 1, ^uintptr(0)); ret != 0 {
			t.Fatal(ret)
		}
	}
	for j := 0; j < 64; j++ {
		h.deliver(s.token, 0x9495, 1, ^uintptr(0))
	}
	v := s.snapshot()
	if !errors.Is(v.Failure, ErrLimit) || v.Deliveries != 2 {
		t.Fatal("opaque callback bypassed delivery bound", v.Deliveries, v.FailureText)
	}
	if got := metadataExcludeRecord(t, v); got != (opaqueCallbackRecord{MessageID: 0x9495, Count: 2, ReturnValue: 0}) {
		t.Fatalf("opaque evidence grew after exhaustion %+v", got)
	}
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var exported map[string]json.RawMessage
	if e = json.Unmarshal(b, &exported); e != nil {
		t.Fatal(e)
	}
	var record map[string]json.RawMessage
	if e = json.Unmarshal(exported["OpaqueMetadataExclude"], &record); e != nil || len(record) != 3 || len(exported["OpaqueMetadataExclude"]) > 80 {
		t.Fatalf("opaque evidence not fixed ID/count/return: %s %v", exported["OpaqueMetadataExclude"], e)
	}
	if ret := h.deliver(s.token, 0x948e, 0, 0); ret != 0xffffffff {
		t.Fatal("cap did not abort", ret)
	}
	if e = h.retire(s, true); e != nil {
		t.Fatal(e)
	}
	before := s.snapshot()
	if ret := h.deliver(s.token, 0x9495, 1, ^uintptr(0)); ret != 0 {
		t.Fatal(ret)
	}
	if after := s.snapshot(); after.Deliveries != before.Deliveries || metadataExcludeRecord(t, after) != metadataExcludeRecord(t, before) {
		t.Fatal("late delivery touched retired evidence")
	}
	next, e := h.begin(context.Background(), `C:\owned`, map[string]bool{".": true}, applyCallbackLimits{})
	if e != nil {
		t.Fatal(e)
	}
	h.deliver(s.token, 0x9495, 1, ^uintptr(0))
	if next.snapshot().Deliveries != 0 || metadataExcludeRecord(t, next.snapshot()).Count != 0 {
		t.Fatal("stale generation touched next session")
	}
	if e = h.retire(next, false); e == nil {
		t.Fatal("unproved unregister accepted")
	}
	h.deliver(next.token, 0x9495, 1, ^uintptr(0))
	if next.snapshot().Deliveries != 0 || metadataExcludeRecord(t, next.snapshot()).Count != 0 {
		t.Fatal("frozen delivery changed evidence")
	}
}
