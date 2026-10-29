//go:build windows

package cabindex

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"uupbuilder/internal/metadata/cabformat"
	platform "uupbuilder/internal/platform/windows"
)

// fdi_fci_types.h defines DIAMONDAPI as __cdecl. FDINOTIFICATION uses
// 32-bit LONG/UINT and pointer-sized INT_PTR; x86 packing is 4, Win64 natural.
// Go1.27's windows/386 asmstdcall explicitly calls stdcall or cdecl and
// restores SP from BP. Callbacks MUST use NewCallbackCDecl on x86.
type fdiNotification struct {
	CB                                             int32
	Name, P2, P3, User                             unsafe.Pointer
	Handle                                         uintptr
	Date, Time, Attributes, SetID, Cabinet, Folder uint16
	Error                                          int32
}
type fdiProvider struct {
	dll                   *platform.SystemDLL
	identity              ProviderIdentity
	create, copy, destroy uintptr
	closed                bool
}

func openFDI(ctx context.Context) (result dataProvider, runErr error) {
	dll, e := platform.OpenSystemDLL(ctx, "cabinet.dll")
	if e != nil {
		return nil, e
	}
	p := &fdiProvider{dll: dll}
	ok := false
	defer func() {
		if !ok {
			runErr = errors.Join(runErr, dll.Close())
		}
	}()
	for name, ptr := range map[string]*uintptr{"FDICreate": &p.create, "FDICopy": &p.copy, "FDIDestroy": &p.destroy} {
		*ptr, e = dll.Proc(name)
		if e != nil {
			return nil, e
		}
	}
	host, e := platform.DetectHost(ctx)
	if e != nil {
		return nil, e
	}
	p.identity = ProviderIdentity{DLL: dll.Identity(), ABI: "FDI DIAMONDAPI cdecl; LONG32/INT_PTR; numeric callback handles", ProcessArchitecture: string(host.ProcessArchitecture), NativeArchitecture: string(host.NativeArchitecture)}
	ok = true
	return p, nil
}
func (p *fdiProvider) Identity() ProviderIdentity { return p.identity }
func (p *fdiProvider) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	return p.dll.Close()
}

// Windows callback trampolines cannot be freed. Register exactly one fixed set
// for the process and serialize FDI calls with a context-aware gate. No callback
// points to a Go object retained by native code after Extract returns.
var fdiGate = make(chan struct{}, 1)
var fdiOnce sync.Once
var fdiCallbacks [8]uintptr
var fdiActive *fdiSession

func callbacks() {
	fdiOnce.Do(func() {
		fdiCallbacks = [8]uintptr{syscall.NewCallbackCDecl(fdiAlloc), syscall.NewCallbackCDecl(fdiFree), syscall.NewCallbackCDecl(fdiOpen), syscall.NewCallbackCDecl(fdiRead), syscall.NewCallbackCDecl(fdiWrite), syscall.NewCallbackCDecl(fdiClose), syscall.NewCallbackCDecl(fdiSeek), syscall.NewCallbackCDecl(fdiNotify)}
	})
}

type fdiSession struct {
	ctx         context.Context
	source      io.ReaderAt
	size        uint64
	table       cabformat.Inventory
	sink        *memberSink
	budget      *runBudget
	allocations map[uintptr]uint64
	inputs      map[uintptr]int64
	nextInput   uintptr
	err         error
	notified    int
}

func (s *fdiSession) fail(e error) uintptr { s.err = errors.Join(s.err, e); return ^uintptr(0) }
func (s *fdiSession) check() bool {
	if e := s.ctx.Err(); e != nil {
		s.err = errors.Join(s.err, e)
	}
	return s.err == nil
}
func (p *fdiProvider) Extract(ctx context.Context, r io.ReaderAt, size uint64, table cabformat.Inventory, sink *memberSink, budget *runBudget) (runErr error) {
	if e := ctx.Err(); e != nil {
		return e
	}
	if p.closed {
		return os.ErrClosed
	}
	select {
	case fdiGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-fdiGate }()
	callbacks()
	s := &fdiSession{ctx: ctx, source: r, size: size, table: table, sink: sink, budget: budget, allocations: map[uintptr]uint64{}, inputs: map[uintptr]int64{}, nextInput: 0x100000}
	fdiActive = s
	defer func() {
		fdiActive = nil
		for ptr, n := range s.allocations {
			_, e := windows.LocalFree(windows.Handle(ptr))
			runErr = errors.Join(runErr, ErrIntegrity, e)
			budget.nativeUsed -= n
		}
		runErr = errors.Join(runErr, s.err)
		if ctx.Err() != nil {
			runErr = errors.Join(runErr, ctx.Err())
		}
	}()
	var erf [3]int32
	var pin runtime.Pinner
	pin.Pin(&erf[0])
	defer pin.Unpin()
	h, _, _ := syscall.SyscallN(p.create, fdiCallbacks[0], fdiCallbacks[1], fdiCallbacks[2], fdiCallbacks[3], fdiCallbacks[4], fdiCallbacks[5], fdiCallbacks[6], ^uintptr(0), uintptr(unsafe.Pointer(&erf[0])))
	if h == 0 {
		return fmt.Errorf("FDICreate: %w (operation %d type %d)", ErrIntegrity, erf[0], erf[1])
	}
	defer func() {
		ok, _, _ := syscall.SyscallN(p.destroy, h)
		if ok == 0 {
			runErr = errors.Join(runErr, ErrIntegrity)
		}
	}()
	name := []byte("source.cab\x00")
	path := []byte{0}
	ok, _, _ := syscall.SyscallN(p.copy, h, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&path[0])), 0, fdiCallbacks[7], 0, 0)
	runtime.KeepAlive(name)
	runtime.KeepAlive(path)
	runtime.KeepAlive(erf)
	if ok == 0 {
		return fmt.Errorf("FDICopy: %w (operation %d type %d)", ErrIntegrity, erf[0], erf[1])
	}
	if s.notified != len(table.Members) || len(s.inputs) != 0 {
		return ErrIntegrity
	}
	return nil
}
func fdiAlloc(count uintptr) uintptr {
	s := fdiActive
	if s == nil || !s.check() {
		return 0
	}
	n := max(uint64(count), 1)
	b := s.budget
	if len(s.allocations) >= b.limits.MaxNativeAllocations || n > b.limits.MaxNativeBytes-b.nativeUsed || n > b.limits.MaxNativeTotalBytes-b.nativeTotal {
		s.fail(ErrLimit)
		return 0
	}
	ptr, e := windows.LocalAlloc(windows.LMEM_FIXED, uint32(n))
	if e != nil {
		s.fail(e)
		return 0
	}
	s.allocations[ptr] = n
	b.nativeUsed += n
	b.nativeTotal += n
	b.nativePeak = max(b.nativePeak, b.nativeUsed)
	return ptr
}
func fdiFree(ptr uintptr) uintptr {
	s := fdiActive
	if s == nil {
		return 0
	}
	if ptr == 0 {
		return 0
	}
	n, ok := s.allocations[ptr]
	if !ok {
		s.fail(ErrIntegrity)
		return 0
	}
	_, e := windows.LocalFree(windows.Handle(ptr))
	if e != nil {
		s.fail(e)
		return 0
	}
	delete(s.allocations, ptr)
	s.budget.nativeUsed -= n
	return 0
}

// PFNREAD/PFNWRITE lend native buffers for the synchronous callback; the SDK
// does not require those buffers to originate in PFNALLOC (header reads use
// native stack memory). Bound the borrowed range, use it immediately, and never
// retain it. Separately, PFNALLOC payloads remain fully tracked and budgeted.
func (s *fdiSession) buffer(ptr unsafe.Pointer, count uintptr) ([]byte, bool) {
	if count == 0 {
		return nil, true
	}
	if count > uintptr(s.budget.limits.MaxBufferBytes) || ptr == nil || uintptr(ptr) > ^uintptr(0)-count {
		return nil, false
	}
	return unsafe.Slice((*byte)(ptr), int(count)), true
}
func boundedName(ptr unsafe.Pointer) (string, bool) {
	if ptr == nil || uintptr(ptr) > ^uintptr(0)-256 {
		return "", false
	}
	var b [256]byte
	for i := range b {
		b[i] = *(*byte)(unsafe.Add(ptr, i))
		if b[i] == 0 {
			return string(b[:i]), true
		}
	}
	return "", false
}
func fdiOpen(name unsafe.Pointer, flags, mode uintptr) uintptr {
	s := fdiActive
	if s == nil {
		return ^uintptr(0)
	}
	if !s.check() {
		return ^uintptr(0)
	}
	n, ok := boundedName(name)
	if !ok || n != "source.cab" || flags&^uintptr(0x8000) != 0 || len(s.inputs) >= 16 {
		return s.fail(ErrUnsupported)
	}
	s.nextInput++
	s.inputs[s.nextInput] = 0
	return s.nextInput
}
func fdiRead(handle uintptr, ptr unsafe.Pointer, count uintptr) uintptr {
	s := fdiActive
	if !s.check() {
		return ^uintptr(0)
	}
	off, ok := s.inputs[handle]
	if !ok {
		return s.fail(ErrIntegrity)
	}
	b, ok := s.buffer(ptr, count)
	if !ok {
		return s.fail(fmt.Errorf("FDI read callback buffer count=%d allocations=%d: %w", count, len(s.allocations), ErrLimit))
	}
	n := min(uint64(len(b)), s.size-uint64(off))
	if n > s.budget.limits.MaxProviderReadBytes-s.budget.providerReads {
		return s.fail(ErrLimit)
	}
	got, e := s.source.ReadAt(b[:n], off)
	if e != nil && e != io.EOF {
		return s.fail(e)
	}
	if uint64(got) != n {
		return s.fail(ErrIntegrity)
	}
	s.inputs[handle] += int64(got)
	s.budget.providerReads += uint64(got)
	return uintptr(got)
}
func fdiWrite(handle uintptr, ptr unsafe.Pointer, count uintptr) uintptr {
	s := fdiActive
	if !s.check() {
		return ^uintptr(0)
	}
	b, ok := s.buffer(ptr, count)
	if !ok {
		return s.fail(ErrLimit)
	}
	n, e := s.sink.write(handle, b)
	if e != nil {
		return s.fail(e)
	}
	return uintptr(n)
}
func fdiClose(handle uintptr) uintptr {
	s := fdiActive
	if _, ok := s.inputs[handle]; ok {
		delete(s.inputs, handle)
		return 0
	}
	return s.fail(errors.Join(ErrIntegrity, s.sink.abort()))
}
func fdiSeek(handle, distance, whence uintptr) uintptr {
	s := fdiActive
	if !s.check() {
		return ^uintptr(0)
	}
	off, ok := s.inputs[handle]
	if !ok {
		return s.fail(ErrIntegrity)
	}
	d := int64(int32(distance))
	switch whence {
	case 0:
		off = d
	case 1:
		off += d
	case 2:
		off = int64(s.size) + d
	default:
		return s.fail(ErrIntegrity)
	}
	if off < 0 || uint64(off) > s.size || off > 0x7fffffff {
		return s.fail(ErrIntegrity)
	}
	s.inputs[handle] = off
	return uintptr(off)
}
func fdiNotify(kind uintptr, ptr unsafe.Pointer) uintptr {
	s := fdiActive
	if !s.check() {
		return ^uintptr(0)
	}
	n := (*fdiNotification)(ptr)
	switch kind {
	case 0:
		if n.Cabinet != 0 {
			return s.fail(ErrUnsupported)
		}
		return 0
	case 1, 4:
		return s.fail(ErrUnsupported)
	case 2:
		if s.notified >= len(s.table.Members) {
			return s.fail(ErrIntegrity)
		}
		m := s.table.Members[s.notified]
		name, ok := boundedName(n.Name)
		if !ok || name != m.Name || n.CB < 0 || uint64(n.CB) != m.Size || int(n.Folder) != m.Folder || n.Attributes != m.Attributes {
			return s.fail(ErrIntegrity)
		}
		h, e := s.sink.begin(s.notified)
		if e != nil {
			return s.fail(e)
		}
		s.notified++
		return h
	case 3:
		// cb is a run-after-extract flag here. This data-only adapter never executes
		// members or applies their dates/attributes. The numeric sink owns the data.
		if e := s.sink.end(n.Handle); e != nil {
			return s.fail(e)
		}
		return 1
	case 5:
		return 0
	default:
		return s.fail(ErrUnsupported)
	}
}
