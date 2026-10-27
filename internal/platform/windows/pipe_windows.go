package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type pipeConnection struct {
	*os.File
	peer      PeerIdentity
	process   windows.Handle
	closeOnce sync.Once
	closeErr  error
}

func (c *pipeConnection) PeerIdentity() PeerIdentity { return c.peer }
func (c *pipeConnection) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.File.Close()
		if c.process != 0 {
			c.closeErr = errors.Join(c.closeErr, windows.CloseHandle(c.process))
		}
	})
	return c.closeErr
}

// PipeServer is single-use. Its unpredictable local name is created first with
// FILE_FLAG_FIRST_PIPE_INSTANCE, preventing precreation/squatting, and a DACL
// restricted to the current user and SYSTEM. No remote clients are accepted.
type PipeServer struct {
	mu        sync.Mutex
	handle    windows.Handle
	name      string
	used      bool
	closed    chan struct{}
	closeOnce sync.Once
}

func NewPipeServer() (*PipeServer, error) {
	self, err := CurrentPeerIdentity()
	if err != nil {
		return nil, err
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	name := `\\.\pipe\uupbuilder-` + token
	// Specific file rights omit FILE_CREATE_PIPE_INSTANCE (same bit as append).
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;0x12019b;;;" + self.UserSID + ")(A;;FA;;;SY)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, _ := windows.UTF16PtrFromString(name)
	h, err := windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &sa)
	if err != nil {
		return nil, err
	}
	return &PipeServer{handle: h, name: name, closed: make(chan struct{})}, nil
}
func (s *PipeServer) Name() string { return s.name }
func (s *PipeServer) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == 0 {
		return nil
	}
	err := windows.CloseHandle(s.handle)
	s.handle = 0
	return err
}

func (s *PipeServer) Accept(ctx context.Context, expected PeerIdentity) (WorkerConnection, error) {
	s.mu.Lock()
	if s.used || s.handle == 0 {
		s.mu.Unlock()
		return nil, errors.New("pipe server already consumed or closed")
	}
	s.used = true
	h := s.handle
	s.handle = 0 // Accept owns and drains native IO before closing this handle.
	s.mu.Unlock()
	transferred := false
	defer func() {
		if !transferred {
			windows.CloseHandle(h)
		}
	}()
	// Close is permitted concurrently: CancelIoEx is issued before releasing the
	// OVERLAPPED storage, and GetOverlappedResult drains the cancelled operation.
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(event)
	ov := windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(h, &ov)
	if err != nil && err != windows.ERROR_PIPE_CONNECTED && err != windows.ERROR_IO_PENDING {
		s.Close()
		return nil, err
	}
	if err == windows.ERROR_IO_PENDING {
		for {
			state, e := windows.WaitForSingleObject(event, 20)
			if e != nil {
				s.Close()
				return nil, e
			}
			if state == windows.WAIT_OBJECT_0 {
				var n uint32
				err = windows.GetOverlappedResult(h, &ov, &n, false)
				break
			}
			var stop error
			select {
			case <-s.closed:
				stop = os.ErrClosed
			default:
				stop = ctx.Err()
			}
			if e := stop; e != nil {
				windows.CancelIoEx(h, &ov)
				var n uint32
				windows.GetOverlappedResult(h, &ov, &n, true)
				s.Close()
				return nil, e
			}
		}
	}
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		s.Close()
		return nil, err
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		s.Close()
		return nil, err
	}
	peer, process, err := inspectPeer(pid)
	if err != nil {
		s.Close()
		return nil, err
	}
	if err := authorizePeer(expected, peer); err != nil {
		windows.CloseHandle(process)
		s.Close()
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
		windows.CloseHandle(process)
		return nil, os.ErrClosed
	default:
	}
	transferred = true
	return &pipeConnection{File: os.NewFile(uintptr(h), s.name), peer: peer, process: process}, nil
}

func validPipeName(name string) bool {
	const prefix = `\\.\pipe\uupbuilder-`
	return strings.HasPrefix(name, prefix) && validToken(strings.TrimPrefix(name, prefix))
}
func DialWorkerPipe(ctx context.Context, name string, expected PeerIdentity) (WorkerConnection, error) {
	if !validPipeName(name) {
		return nil, errors.New("invalid local worker pipe name")
	}
	p, _ := windows.UTF16PtrFromString(name)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == windows.ERROR_PIPE_BUSY || err == windows.ERROR_FILE_NOT_FOUND {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}
		if err != nil {
			return nil, err
		}
		var pid uint32
		if err := windows.GetNamedPipeServerProcessId(h, &pid); err != nil {
			windows.CloseHandle(h)
			return nil, err
		}
		peer, process, err := inspectPeer(pid)
		if err != nil {
			windows.CloseHandle(h)
			return nil, err
		}
		if err := authorizePeer(expected, peer); err != nil {
			windows.CloseHandle(process)
			windows.CloseHandle(h)
			return nil, err
		}
		return &pipeConnection{File: os.NewFile(uintptr(h), name), peer: peer, process: process}, nil
	}
}

func CurrentPeerIdentity() (PeerIdentity, error) {
	p, h, err := inspectPeer(uint32(os.Getpid()))
	if h != 0 {
		windows.CloseHandle(h)
	}
	return p, err
}
func inspectPeer(pid uint32) (PeerIdentity, windows.Handle, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return PeerIdentity{}, 0, err
	}
	fail := func(e error) (PeerIdentity, windows.Handle, error) {
		windows.CloseHandle(h)
		return PeerIdentity{}, 0, e
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return fail(err)
	}
	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return fail(err)
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		return fail(err)
	}
	var session, n uint32
	if err := windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &n); err != nil {
		return fail(err)
	}
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return fail(err)
	}
	return PeerIdentity{ProcessID: pid, CreationTime: uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime), UserSID: u.User.Sid.String(), SessionID: session, Elevated: token.IsElevated(), Executable: windows.UTF16ToString(buf[:size])}, h, nil
}
func authorizePeer(expected, actual PeerIdentity) error {
	if expected.ProcessID == 0 || expected.CreationTime == 0 || expected.UserSID == "" || expected.Executable == "" || expected.ProcessID != actual.ProcessID || expected.CreationTime != actual.CreationTime || expected.UserSID != actual.UserSID || expected.SessionID != actual.SessionID || expected.Elevated != actual.Elevated || !strings.EqualFold(expected.Executable, actual.Executable) {
		return fmt.Errorf("unauthorized worker pipe peer")
	}
	return nil
}
