package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Official 19041 wimgapi.h (SHA256 8aafd624...35cd7a) supplies
// WM_APP+0x1476 and the following sequential enum/return values.
const (
	applyMsgProgress        = uint32(0x9478)
	applyMsgProcess         = uint32(0x9479)
	applyMsgScanning        = uint32(0x947a)
	applyMsgSetRange        = uint32(0x947b)
	applyMsgSetPos          = uint32(0x947c)
	applyMsgStep            = uint32(0x947d)
	applyMsgError           = uint32(0x947f)
	applyMsgFileInfo        = uint32(0x9483)
	applyMsgInfo            = uint32(0x9484)
	applyMsgWarning         = uint32(0x9485)
	applyMsgObjectID        = uint32(0x9487)
	applyMsgQueryAbort      = uint32(0x948e)
	applyMsgMetadataExclude = uint32(0x9495)
	applyAbort              = uintptr(0xffffffff)
)

type applyCallbackLimits struct{ MaxDeliveries uint64 }
type applyFileMessage struct {
	Path string
	Data windows.Win32finddata
}

// Fixed-size evidence of healthy, admitted opaque dispatch only. It contains
// no parameters/addresses and establishes no payload or metadata semantics.
type applyOpaqueCallbackEvidence struct {
	MessageID   uint32
	Count       uint64
	ReturnValue uint32
}
type applyCallbackEvidence struct {
	Deliveries                                      uint64
	Progress                                        uint32
	LastFile                                        applyFileMessage
	CancellationRequested, AbortDelivered, Returned bool
	Failure                                         error `json:"-"`
	FailureText                                     string
	OpaqueMetadataExclude                           applyOpaqueCallbackEvidence
	Unconsumed                                      [16]applyOpaqueCallbackEvidence
	UnconsumedOverflowDeliveries                    uint64
}

// There is exactly one production trampoline, allocated once. UserData is a
// non-reused integer generation, never a Go/native pointer. Failed unregister
// permanently quarantines this one bounded slot and its native owner.
var installedApplyCallbacks applyCallbackHub
var applyCallbackOnce sync.Once
var applyCallbackAddress uintptr

func fixedApplyCallbackAddress() uintptr {
	applyCallbackOnce.Do(func() {
		applyCallbackAddress = syscall.NewCallback(func(msg, w, l, user uintptr) uintptr {
			return installedApplyCallbacks.deliver(user, uint32(msg), w, l)
		})
	})
	return applyCallbackAddress
}

type applyCallbackHub struct {
	mu       sync.Mutex
	cond     *sync.Cond
	next     uintptr
	current  *applyCallbackSession
	retained any // At most one quarantined native owner; never an unbounded registry.
}
type applyCallbackSession struct {
	mu          sync.Mutex
	hub         *applyCallbackHub
	ctx         context.Context
	token       uintptr
	destination string
	known       map[string]bool
	limit       uint64
	inflight    int  // Hub lock, including before copying native data.
	frozen      bool // Hub lock; frozen delivery never reads parameter pointers.
	v           applyCallbackEvidence
}

func (h *applyCallbackHub) condition() *sync.Cond {
	if h.cond == nil {
		h.cond = sync.NewCond(&h.mu)
	}
	return h.cond
}
func (h *applyCallbackHub) begin(ctx context.Context, destination string, known map[string]bool, limits applyCallbackLimits) (*applyCallbackSession, error) {
	return h.beginFor(nil, ctx, destination, known, limits)
}
func (h *applyCallbackHub) reserve(owner *fixedApplyRun) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if owner == nil || h.current != nil || h.retained != nil {
		return ErrInput
	}
	h.retained = owner
	return nil
}
func (h *applyCallbackHub) beginFor(owner *fixedApplyRun, ctx context.Context, destination string, known map[string]bool, limits applyCallbackLimits) (*applyCallbackSession, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || h.current != nil || h.retained != nil && h.retained != owner || h.next == ^uintptr(0) || !filepath.IsAbs(destination) || len(destination) > 4096 || len(known) == 0 || len(known) > 262144 || limits.MaxDeliveries > 1<<22 {
		return nil, ErrInput
	}
	if limits.MaxDeliveries == 0 {
		limits.MaxDeliveries = 1 << 22
	}
	h.next++
	s := &applyCallbackSession{hub: h, ctx: ctx, token: h.next, destination: destination, known: known, limit: limits.MaxDeliveries}
	h.current = s
	return s, nil
}
func (h *applyCallbackHub) retire(s *applyCallbackSession, unregistered bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.current != s || s == nil {
		return ErrInput
	}
	s.frozen = true
	for s.inflight != 0 {
		h.condition().Wait()
	}
	if !unregistered {
		return errors.New("native callback unregister unproved; fixed slot and native lifetimes quarantined")
	}
	h.current = nil
	return nil
}
func callbackIdleReturn(msg uint32) uintptr {
	if msg == applyMsgProcess || msg == applyMsgQueryAbort {
		return applyAbort
	}
	return 0 // FILEINFO requires SUCCESS, including late/malformed delivery.
}
func (h *applyCallbackHub) deliver(token uintptr, msg uint32, w, l uintptr) uintptr {
	h.mu.Lock()
	s := h.current
	if s == nil || s.token != token || s.frozen {
		h.mu.Unlock()
		return callbackIdleReturn(msg)
	}
	s.inflight++
	h.mu.Unlock()
	defer func() { h.mu.Lock(); s.inflight--; h.condition().Broadcast(); h.mu.Unlock() }()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v.Deliveries >= s.limit {
		s.fail(ErrLimit)
	} else {
		s.v.Deliveries++
	}
	if s.ctx.Err() != nil {
		s.v.CancellationRequested = true
	}
	abort := func() uintptr {
		if s.v.CancellationRequested || s.v.Failure != nil {
			s.v.AbortDelivered = true
			return applyAbort
		}
		return 0
	}
	// After exhaustion/cancellation only documented abort points are handled;
	// no pointers or unbounded payloads are read to build further evidence.
	if msg == applyMsgQueryAbort {
		return abort()
	}
	if s.v.Failure != nil || s.v.CancellationRequested {
		if msg == applyMsgProcess {
			return abort()
		}
		return 0
	}
	switch msg {
	case applyMsgMetadataExclude:
		// Explicit one-ID controller policy: generic SUCCESS continues default
		// subscriber dispatch. Neither word is accessed, copied or changed;
		// payload/default-exclusion semantics remain unproved. Existing failure,
		// cancellation and delivery-cap checks above still take precedence.
		s.v.OpaqueMetadataExclude.MessageID = applyMsgMetadataExclude
		s.v.OpaqueMetadataExclude.Count++
		s.v.OpaqueMetadataExclude.ReturnValue = 0
	case applyMsgProgress:
		if w > 100 || l > 0xffffffff {
			s.fail(ErrIntegrity)
		} else {
			s.v.Progress = uint32(w)
		}
	case applyMsgStep:
		// No parameters, no completion authority.
	case applyMsgScanning, applyMsgSetRange, applyMsgSetPos:
		// Documented passive count feedback requires SUCCESS. Neither word is
		// consumed or changed; counts supply no source or completion authority.
	case applyMsgProcess, applyMsgFileInfo:
		name, e := copyApplyCallbackString(w)
		if e == nil {
			e = s.checkPath(name)
		}
		if e != nil {
			s.fail(e)
		}
		if msg == applyMsgProcess {
			if l == 0 {
				s.fail(ErrIntegrity)
			} else {
				var value [4]byte
				if e := copyApplyNativeValue(l, value[:]); e != nil {
					s.fail(e)
				} else if binary.LittleEndian.Uint32(value[:]) == 0 {
					s.fail(errors.New("native processing suppression refused"))
				}
			}
			return abort() // Never writes pfProcessFile or skips a source entry.
		}
		if e == nil && l != 0 {
			var data windows.Win32finddata
			if e := copyApplyNativeValue(l, unsafe.Slice((*byte)(unsafe.Pointer(&data)), int(unsafe.Sizeof(data)))); e != nil {
				s.fail(e)
			} else {
				s.v.LastFile = applyFileMessage{Path: name, Data: data}
			}
		} else if l == 0 {
			s.fail(ErrIntegrity)
		}
	case applyMsgError, applyMsgWarning, applyMsgObjectID, applyMsgInfo:
		// Documented path + DWORD cause. These are diagnostic data and cannot
		// skip an error or authenticate creation. Any warning remains unresolved.
		name, e := copyApplyCallbackString(w)
		if e != nil {
			s.fail(e)
		} else {
			s.fail(fmt.Errorf("native message %#x path=%q code=%d", msg, name, uint32(l)))
		}
	case 0x9477, 0x947e, 0x9480, 0x9481, 0x9482,
		0x9488, 0x9489, 0x948a, 0x948b, 0x948c, 0x948d:
		// Known TEXT anomaly, compression/alignment/retry/split and mount/cleanup
		// operations remain refused without accessing either payload word.
		s.fail(fmt.Errorf("unsupported native callback message %#x", msg))
	default:
		// Uninterested-subscriber SUCCESS, not semantic admission or authority.
		// Neither word is accessed. Unknown-event anomaly detection is withdrawn;
		// fixed evidence saturation summarizes rather than aborting the operation.
		for j := range s.v.Unconsumed {
			entry := &s.v.Unconsumed[j]
			if entry.Count == 0 {
				*entry = applyOpaqueCallbackEvidence{MessageID: msg, Count: 1, ReturnValue: 0}
				return 0
			}
			if entry.MessageID == msg {
				entry.Count++
				return 0
			}
		}
		s.v.UnconsumedOverflowDeliveries++
	}
	return 0
}
func (s *applyCallbackSession) fail(e error) {
	if s.v.Failure == nil {
		s.v.Failure = e
	}
}
func (s *applyCallbackSession) snapshot() applyCallbackEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.v
	if v.Failure != nil {
		v.FailureText = v.Failure.Error()
	} // One bounded callback cause, never a retained pointer.
	if s.ctx.Err() != nil {
		v.CancellationRequested = true
	}
	return v
}
func (s *applyCallbackSession) checkPath(name string) error {
	if name == "" || !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return ErrInput
	}
	rel, e := filepath.Rel(s.destination, name)
	if e != nil || rel == ".." || strings.HasPrefix(rel, `..\`) || strings.Contains(rel, ":") {
		return ErrInput
	}
	rel = strings.ToLower(filepath.ToSlash(rel))
	if !s.known[rel] {
		return fmt.Errorf("%w: native callback path outside exact source set: %q", ErrInput, name)
	}
	return nil
}

func copyApplyCallbackString(p uintptr) (string, error) {
	if p == 0 || p%2 != 0 {
		return "", ErrInput
	}
	// Trusted installed-provider ABI only. Copy during delivery, bounded to
	// 4096 UTF-16 units; no native pointer survives this stack frame.
	var units [4096]uint16
	for j := 0; j < len(units); {
		// Current-process copies check native accessibility without converting
		// callback integer words into Go pointers. Never cross a memory page
		// while looking for NUL; no copied native pointer is retained.
		var block [64]byte
		address := p + uintptr(j)*2
		if address < p {
			return "", ErrLimit
		}
		n := min(len(block), int(uintptr(os.Getpagesize())-address%uintptr(os.Getpagesize())), (len(units)-j)*2)
		if e := copyApplyNativeValue(address, block[:n]); e != nil {
			return "", e
		}
		for k := 0; k < n; k += 2 {
			v := binary.LittleEndian.Uint16(block[k:])
			if v == 0 {
				x := string(utf16.Decode(units[:j]))
				if len(x) > 4096 {
					return "", ErrLimit
				}
				for k, v := range utf16.Encode([]rune(x)) {
					if k >= j || v != units[k] {
						return "", ErrInput
					}
				}
				return x, nil
			}
			units[j] = v
			j++
		}
	}
	return "", ErrLimit
}

func copyApplyNativeValue(address uintptr, b []byte) error {
	if address == 0 || len(b) == 0 || len(b) > 8192 {
		return ErrInput
	}
	var n uintptr
	e := windows.ReadProcessMemory(windows.CurrentProcess(), address, &b[0], uintptr(len(b)), &n)
	if e != nil || n != uintptr(len(b)) {
		return errors.Join(ErrIntegrity, e)
	}
	return nil
}
