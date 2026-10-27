package windows

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (d WorkerDescriptor) Validate() error {
	if d.Version != 1 || !validID(d.JobID) || d.Workspace.JobID != d.JobID || !filepath.IsAbs(d.Workspace.Path) || !validToken(d.Workspace.Token) {
		return errors.New("invalid worker job descriptor")
	}
	b, err := hex.DecodeString(d.PlanDigest)
	if err != nil || len(b) != 32 || strings.ToLower(d.PlanDigest) != d.PlanDigest {
		return errors.New("worker requires canonical SHA-256 plan identity")
	}
	return nil
}
func (b WorkerBootstrap) Validate() error {
	if err := b.Descriptor.Validate(); err != nil {
		return err
	}
	if !validPipeName(b.PipeName) {
		return errors.New("invalid worker pipe")
	}
	return authorizePeer(b.Parent, b.Parent)
}
func workerArguments(b WorkerBootstrap) ([]string, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if len(data) > 12288 {
		return nil, errors.New("worker descriptor too large")
	}
	return []string{"--uup-worker", base64.RawURLEncoding.EncodeToString(data)}, nil
}

// ParseWorkerArguments recognizes only the private bootstrap envelope. It does
// not authorize operations. The app/J2 must dispatch this mode explicitly and
// validate the frozen plan before any mutation.
func ParseWorkerArguments(args []string) (WorkerBootstrap, error) {
	if len(args) != 2 || args[0] != "--uup-worker" || len(args[1]) > 16384 {
		return WorkerBootstrap{}, errors.New("invalid worker arguments")
	}
	data, err := base64.RawURLEncoding.DecodeString(args[1])
	if err != nil {
		return WorkerBootstrap{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var b WorkerBootstrap
	if err := decoder.Decode(&b); err != nil {
		return WorkerBootstrap{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return WorkerBootstrap{}, errors.New("trailing worker data")
	}
	if err := b.Validate(); err != nil {
		return WorkerBootstrap{}, err
	}
	return b, nil
}

// StartElevated invokes this executable with the normal Windows runas verb.
// It exposes no generic command runner. UAC is synchronous and cannot safely be
// dismissed by context cancellation; cancellation after consent closes only
// owned IPC/process handles and never searches for or kills elevated processes.
func StartElevated(ctx context.Context, descriptor WorkerDescriptor) (WorkerConnection, error) {
	return startElevated(ctx, descriptor, launchElevatedSelf)
}

func startElevated(ctx context.Context, descriptor WorkerDescriptor, launch func(string, []string) (windows.Handle, error)) (WorkerConnection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	w, err := OpenWorkspace(descriptor.Workspace)
	if err != nil {
		return nil, err
	}
	w.Close()
	parent, err := CurrentPeerIdentity()
	if err != nil {
		return nil, err
	}
	server, err := NewPipeServer()
	if err != nil {
		return nil, err
	}
	defer server.Close()
	args, err := workerArguments(WorkerBootstrap{Descriptor: descriptor, PipeName: server.Name(), Parent: parent})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	process, err := launch(parent.Executable, args)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(process)
	pid, err := windows.GetProcessId(process)
	if err != nil {
		return nil, err
	}
	child, h, err := inspectPeer(pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	if !child.Elevated || child.UserSID != parent.UserSID || child.SessionID != parent.SessionID || !strings.EqualFold(child.Executable, parent.Executable) {
		return nil, errors.New("elevation did not create the same executable/user/session worker")
	}
	// Bound a worker that fails before connecting (e.g. app has not wired the
	// private mode). This timeout does not imply any servicing cancellation.
	acceptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return server.Accept(acceptCtx, child)
}

// ConnectWorker authenticates the parent process and requires this process to
// be elevated under the same user/session/executable. The returned descriptor
// still needs J2's complete frozen-operation validation.
func ConnectWorker(ctx context.Context, b WorkerBootstrap) (WorkerConnection, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	self, err := CurrentPeerIdentity()
	if err != nil {
		return nil, err
	}
	if !self.Elevated || self.UserSID != b.Parent.UserSID || self.SessionID != b.Parent.SessionID || !strings.EqualFold(self.Executable, b.Parent.Executable) {
		return nil, errors.New("worker token/executable does not match parent")
	}
	w, err := OpenWorkspace(b.Descriptor.Workspace)
	if err != nil {
		return nil, err
	}
	w.Close()
	return DialWorkerPipe(ctx, b.PipeName, b.Parent)
}

func launchElevatedSelf(executable string, args []string) (windows.Handle, error) {
	// ShellExecuteEx can use COM shell extensions; initialize an STA on a pinned
	// OS thread. S_FALSE also requires balancing CoUninitialize.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ole := windows.NewLazySystemDLL("ole32.dll")
	hr, _, _ := ole.NewProc("CoInitializeEx").Call(0, 2|4)
	if int32(hr) < 0 {
		return 0, syscall.Errno(hr)
	}
	defer ole.NewProc("CoUninitialize").Call()
	type shellExecuteInfo struct {
		Size       uint32
		Mask       uint32
		Window     windows.Handle
		Verb       *uint16
		File       *uint16
		Parameters *uint16
		Directory  *uint16
		Show       int32
		Instance   windows.Handle
		IDList     uintptr
		Class      *uint16
		ClassKey   windows.Handle
		HotKey     uint32
		Icon       windows.Handle
		Process    windows.Handle
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return 0, err
	}
	escaped := make([]string, len(args))
	for i, a := range args {
		escaped[i] = syscall.EscapeArg(a)
	}
	parameters, err := windows.UTF16PtrFromString(strings.Join(escaped, " "))
	if err != nil {
		return 0, err
	}
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(executable))
	info := shellExecuteInfo{Mask: 0x40 | 0x100 | 0x400, Verb: verb, File: file, Parameters: parameters, Directory: dir, Show: windows.SW_HIDE}
	info.Size = uint32(unsafe.Sizeof(info))
	ok, _, callErr := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(info)
	if ok == 0 {
		return 0, callErr
	}
	if info.Process == 0 {
		return 0, errors.New("elevation returned no process handle")
	}
	return info.Process, nil
}
