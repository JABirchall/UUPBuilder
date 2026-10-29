package engine

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	platform "uupbuilder/internal/platform/windows"
)

type installedApplyProvider struct {
	mu       sync.Mutex
	dll      *platform.SystemDLL
	ports    *fixedApplyPorts
	closed   bool
	closeErr error
}

// This constructor/adapter is UNCALLED in ordinary tests. Only the configured
// test-only entry may compose it with a live exact source and two durable claims.
// It exposes no arbitrary provider, flags, command, path or fallback operation.
func openInstalledFixedApply(ctx context.Context) (p *installedApplyProvider, runErr error) {
	if ctx == nil {
		return nil, ErrInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	dll, e := platform.OpenSystemDLL(context.WithoutCancel(ctx), "wimgapi.dll")
	if e != nil {
		return nil, e
	}
	p = &installedApplyProvider{dll: dll}
	owner := p // Named return p may become nil on a constructor failure.
	ok := false
	defer func() {
		if !ok {
			runErr = errors.Join(runErr, owner.Close())
		}
	}()
	procs := make(map[string]uintptr, 10)
	for _, name := range []string{"WIMCreateFile", "WIMGetImageCount", "WIMGetImageInformation", "WIMSetTemporaryPath", "WIMLoadImage", "WIMRegisterMessageCallback", "WIMApplyImage", "WIMUnregisterMessageCallback", "WIMCloseHandle"} {
		address, e := dll.Proc(name)
		if e != nil || address == 0 {
			return nil, errors.Join(e, ErrIntegrity)
		}
		procs[name] = address
	}
	n := &fixedApplyPorts{id: dll.Identity(), installed: p, check: p.CheckLive, closeProvider: p.Close, modules: loadedModules}
	p.ports = n
	information := func(h uintptr) (runErr error) {
		var data unsafe.Pointer
		var size uint32
		yes, _, errno := syscall.SyscallN(procs["WIMGetImageInformation"], h, uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&size)))
		if yes == 0 {
			return nativeError("WIMGetImageInformation", errno)
		}
		if data == nil {
			return ErrIntegrity
		}
		defer func() { _, e := windows.LocalFree(windows.Handle(uintptr(data))); runErr = errors.Join(runErr, e) }()
		if size == 0 || size > 1<<20 || size%2 != 0 {
			return ErrLimit
		}
		v, e := imageInformation(unsafe.Slice((*byte)(data), int(size)))
		if e != nil || v != (ImageInformation{1, "0", "Professional", "Client", "10.0.19041.1"}) {
			return errors.Join(ErrIntegrity, e)
		}
		return nil
	}
	n.open = func(path string) (uintptr, error) {
		u, e := windows.UTF16PtrFromString(path)
		if e != nil {
			return 0, e
		}
		var creation uint32
		h, _, errno := syscall.SyscallN(procs["WIMCreateFile"], uintptr(unsafe.Pointer(u)), windows.GENERIC_READ, windows.OPEN_EXISTING, 0, 0, uintptr(unsafe.Pointer(&creation)))
		runtime.KeepAlive(u)
		if h == 0 {
			return 0, nativeError("WIMCreateFile", errno)
		}
		if creation != 1 {
			return h, ErrIntegrity
		}
		count, _, errno := syscall.SyscallN(procs["WIMGetImageCount"], h)
		if count != 1 {
			return h, errors.Join(ErrIntegrity, nativeError("WIMGetImageCount", errno))
		}
		return h, information(h)
	}
	n.temporary = func(h uintptr, path string) error {
		if h == 0 {
			return ErrInput
		}
		u, e := windows.UTF16PtrFromString(path)
		if e != nil {
			return e
		}
		yes, _, errno := syscall.SyscallN(procs["WIMSetTemporaryPath"], h, uintptr(unsafe.Pointer(u)))
		runtime.KeepAlive(u)
		if yes == 0 {
			return nativeError("WIMSetTemporaryPath", errno)
		}
		return nil
	}
	n.load = func(h uintptr, index uint32) (uintptr, error) {
		if h == 0 || index != 1 {
			return 0, ErrInput
		}
		image, _, errno := syscall.SyscallN(procs["WIMLoadImage"], h, 1)
		if image == 0 {
			return 0, nativeError("WIMLoadImage", errno)
		}
		return image, information(image)
	}
	n.register = func(h, token uintptr) (uint32, error) {
		if h == 0 || token == 0 {
			return 0, ErrInput
		}
		index, _, errno := syscall.SyscallN(procs["WIMRegisterMessageCallback"], h, fixedApplyCallbackAddress(), token)
		if uint32(index) == 0xffffffff {
			return uint32(index), nativeError("WIMRegisterMessageCallback", errno)
		}
		return uint32(index), nil
	}
	n.apply = func(b *fixedApplyBinding, image uintptr, flags uint32) (*nativeApplyCompletion, error) {
		if b == nil || image == 0 || flags != 0x182 || b.provider != n.id {
			return nil, ErrInput
		}
		u, e := windows.UTF16PtrFromString(claimApplyPath(b.destination))
		if e != nil {
			return nil, e
		}
		// The only production WIMApplyImage call site. Cancellation is delivered
		// by documented PROCESS/QUERY_ABORT callbacks; actual return is awaited.
		yes, _, errno := syscall.SyscallN(procs["WIMApplyImage"], image, uintptr(unsafe.Pointer(u)), 0x182)
		runtime.KeepAlive(u)
		runtime.KeepAlive(p)
		runtime.KeepAlive(b)
		seal := &nativeApplyCompletion{provider: p, binding: b, image: image, success: yes != 0}
		if yes == 0 {
			return seal, nativeError("WIMApplyImage", errno)
		}
		return seal, nil
	}
	n.unregister = func(h uintptr) error {
		if h == 0 {
			return ErrInput
		}
		// Exact function pointer, never registration index or NULL/global form.
		yes, _, errno := syscall.SyscallN(procs["WIMUnregisterMessageCallback"], h, fixedApplyCallbackAddress())
		if yes == 0 {
			return nativeError("WIMUnregisterMessageCallback", errno)
		}
		return nil
	}
	n.closeHandle = func(h uintptr) error {
		if h == 0 {
			return ErrInput
		}
		yes, _, errno := syscall.SyscallN(procs["WIMCloseHandle"], h)
		if yes == 0 {
			return nativeError("WIMCloseHandle", errno)
		}
		return nil
	}
	ok = true
	return p, nil
}
func (p *installedApplyProvider) CheckLive() error {
	if p == nil {
		return ErrInput
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.dll == nil || p.ports == nil || p.dll.Identity() != p.ports.id {
		return ErrInput
	}
	address, e := p.dll.Proc("WIMApplyImage")
	if e != nil || address == 0 {
		return errors.Join(ErrInput, e)
	}
	return nil
}
func (p *installedApplyProvider) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		if p.dll != nil {
			p.closeErr = p.dll.Close()
		}
	}
	return p.closeErr
}
