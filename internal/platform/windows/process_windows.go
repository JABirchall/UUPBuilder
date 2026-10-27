package windows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
)

type Runner struct{}

func NewRunner() *Runner { return &Runner{} }

type ProcessExitError struct{ Code uint32 }

func (e *ProcessExitError) Error() string { return fmt.Sprintf("process exited with code %d", e.Code) }

func validateInvocation(inv Invocation) error {
	if !filepath.IsAbs(inv.Executable) || !strings.EqualFold(filepath.Ext(inv.Executable), ".exe") || strings.ContainsAny(inv.Executable, "\x00\r\n\"") {
		return errors.New("absolute native .exe required")
	}
	if inv.Workspace == nil || inv.JobID != inv.Workspace.identity.JobID || !validID(inv.JobID) || !validID(inv.OperationID) {
		return errors.New("owned workspace, job and operation identities required")
	}
	if inv.Cancellation != CancelTerminateTree && inv.Cancellation != CancelWait {
		return errors.New("explicit cancellation policy required")
	}
	for _, arg := range inv.Arguments {
		if strings.ContainsRune(arg, 0) {
			return errors.New("NUL in argument")
		}
	}
	return nil
}

func (r *Runner) Run(ctx context.Context, inv Invocation, emit model.Emit) (RunResult, error) {
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	if err := validateInvocation(inv); err != nil {
		return RunResult{}, err
	}
	dir, path, err := inv.Workspace.lockDirectory(inv.Directory)
	if err != nil {
		return RunResult{}, err
	}
	defer dir.Close()
	job, err := newOwnedJob()
	if err != nil {
		return RunResult{}, err
	}
	defer func() {
		if job != 0 {
			windows.CloseHandle(job)
		}
	}()
	outR, outW, err := os.Pipe()
	if err != nil {
		return RunResult{}, err
	}
	defer outR.Close()
	defer outW.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		return RunResult{}, err
	}
	defer errR.Close()
	defer errW.Close()
	in, err := os.Open(os.DevNull)
	if err != nil {
		return RunResult{}, err
	}
	defer in.Close()
	// Only these three duplicated handles are inherited. Other concurrently
	// launched jobs and pipe listeners never leak into this child.
	var inherited []windows.Handle
	for _, f := range []*os.File{in, outW, errW} {
		var h windows.Handle
		if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(f.Fd()), windows.CurrentProcess(), &h, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			for _, v := range inherited {
				windows.CloseHandle(v)
			}
			return RunResult{}, err
		}
		inherited = append(inherited, h)
	}
	defer func() {
		for _, h := range inherited {
			windows.CloseHandle(h)
		}
	}()
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return RunResult{}, err
	}
	defer attributes.Delete()
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherited[0]), uintptr(len(inherited))*unsafe.Sizeof(inherited[0])); err != nil {
		return RunResult{}, err
	}
	si := windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	si.StdInput = inherited[0]
	si.StdOutput = inherited[1]
	si.StdErr = inherited[2]
	si.ProcThreadAttributeList = attributes.List()
	application, err := windows.UTF16PtrFromString(inv.Executable)
	if err != nil {
		return RunResult{}, err
	}
	argv := append([]string{inv.Executable}, inv.Arguments...)
	escaped := make([]string, len(argv))
	for i, a := range argv {
		escaped[i] = syscall.EscapeArg(a)
	}
	command, err := windows.UTF16PtrFromString(strings.Join(escaped, " "))
	if err != nil {
		return RunResult{}, err
	}
	cwd, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return RunResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	var process windows.ProcessInformation
	err = windows.CreateProcess(application, command, nil, nil, true, windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW|windows.EXTENDED_STARTUPINFO_PRESENT, nil, cwd, &si.StartupInfo, &process)
	runtime.KeepAlive(si)
	runtime.KeepAlive(inherited)
	if err != nil {
		return RunResult{}, err
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	// The primary thread has never run: failure to attach the job cannot leave
	// an untracked helper or grandchild. Fail closed on restrictive outer jobs.
	if err := windows.AssignProcessToJobObject(job, process.Process); err != nil {
		windows.TerminateProcess(process.Process, 1)
		windows.WaitForSingleObject(process.Process, windows.INFINITE)
		return RunResult{}, err
	}
	for _, h := range inherited {
		windows.CloseHandle(h)
	}
	inherited = nil
	outW.Close()
	errW.Close()
	result := RunResult{ProcessID: process.ProcessId}
	var wg sync.WaitGroup
	var stdout, stderr string
	wg.Add(2)
	go func() { defer wg.Done(); stdout = captureOutput(outR, inv, emit) }()
	go func() { defer wg.Done(); stderr = captureOutput(errR, inv, emit) }()
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		windows.TerminateJobObject(job, 1)
		windows.WaitForSingleObject(process.Process, windows.INFINITE)
		windows.CloseHandle(job)
		job = 0
		wg.Wait()
		return result, err
	}
	done := make(chan error, 1)
	go func() { _, e := windows.WaitForSingleObject(process.Process, windows.INFINITE); done <- e }()
	var waitErr, errorCancel error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		result.Cancelled = true
		errorCancel = ctx.Err()
		if inv.Cancellation == CancelTerminateTree {
			waitErr = windows.TerminateJobObject(job, 1)
		} else if emit != nil {
			emit(model.Event{JobID: inv.JobID, StageID: inv.OperationID, Kind: model.EventLog, Message: "Cancellation deferred until the operation exits safely", Timestamp: time.Now()})
		}
		waitErr = errors.Join(waitErr, <-done)
	}
	// Successful parents cannot leave background children holding output open.
	// Closing this invocation's job kills only its remaining descendants.
	closeErr := windows.CloseHandle(job)
	job = 0
	exitErr := windows.GetExitCodeProcess(process.Process, &result.ExitCode)
	wg.Wait()
	result.Stdout = stdout
	result.Stderr = stderr
	if err := errors.Join(waitErr, closeErr, exitErr, errorCancel); err != nil {
		return result, err
	}
	if result.ExitCode != 0 {
		return result, &ProcessExitError{Code: result.ExitCode}
	}
	return result, nil
}

func captureOutput(reader io.Reader, inv Invocation, emit model.Emit) string {
	const limit = 64 * 1024
	tail := make([]byte, 0, limit)
	buffer := make([]byte, 4096)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if len(tail)+n > limit {
				drop := len(tail) + n - limit
				copy(tail, tail[drop:])
				tail = tail[:len(tail)-drop]
			}
			tail = append(tail, buffer[:n]...)
			if emit != nil {
				emit(model.Event{JobID: inv.JobID, StageID: inv.OperationID, Kind: model.EventLog, Message: string(buffer[:n]), Timestamp: time.Now()})
			}
		}
		if err != nil {
			break
		}
	}
	return string(tail)
}
