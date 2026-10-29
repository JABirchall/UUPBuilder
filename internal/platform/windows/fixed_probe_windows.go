package windows

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// FixedPreservationBootstrap is only the fixed test probe's peer bootstrap.
// It contains no action, shell, argv, image path, flags or source capability.
type FixedPreservationBootstrap struct {
	Version    uint32
	PipeName   string
	Parent     PeerIdentity
	Executable ExecutableIdentity
}

func (b FixedPreservationBootstrap) validate() error {
	h, e := hex.DecodeString(b.Executable.SHA256)
	if b.Version != 1 || !validPipeName(b.PipeName) || authorizePeer(b.Parent, b.Parent) != nil || !samePinnedPath(b.Executable.Path, b.Parent.Executable) || e != nil || len(h) != 32 || strings.ToLower(b.Executable.SHA256) != b.Executable.SHA256 || b.Executable.Size <= 0 || b.Executable.Size > 128<<20 || b.Executable.File.FileIndex == 0 {
		return ErrPreparationCustody
	}
	return nil
}
func fixedPreservationArguments(b FixedPreservationBootstrap) ([]string, error) {
	if e := b.validate(); e != nil {
		return nil, e
	}
	v, e := json.Marshal(b)
	if e != nil {
		return nil, e
	}
	if len(v) > 12288 {
		return nil, ErrPreparationCustody
	}
	return []string{"-test.run=^TestConfiguredFixedSelectedSourceApply$", "-test.count=1", "-test.v=true", "-test.timeout=0", "-fixed-selected-bootstrap=" + base64.RawURLEncoding.EncodeToString(v)}, nil
}
func ParseFixedPreservationBootstrap(value string) (FixedPreservationBootstrap, error) {
	var b FixedPreservationBootstrap
	if len(value) == 0 || len(value) > 16384 {
		return b, ErrPreparationCustody
	}
	v, e := base64.RawURLEncoding.DecodeString(value)
	if e != nil {
		return b, e
	}
	d := json.NewDecoder(bytes.NewReader(v))
	d.DisallowUnknownFields()
	if e = d.Decode(&b); e != nil {
		return b, e
	}
	if d.Decode(new(any)) != io.EOF {
		return b, ErrPreparationCustody
	}
	return b, b.validate()
}

// StartFixedPreservationProbe is the fixed test-only direct runas-self route.
// Its caller must obtain explicit approval for the complete immutable scope
// BEFORE calling. It accepts no caller-selected executable, argv or commands.
// Native actions require the test's additional authenticated scope protocol.
// No process is killed on cancellation, including failed bootstrap.
func StartFixedPreservationProbe(ctx context.Context, pin *PinnedExecutable) (WorkerConnection, error) {
	if ctx == nil || pin == nil {
		return nil, ErrPreparationCustody
	}
	if e := pin.Verify(ctx); e != nil {
		return nil, e
	}
	self, e := CurrentPeerIdentity()
	if e != nil {
		return nil, e
	}
	if !samePinnedPath(self.Executable, pin.Identity().Path) {
		return nil, ErrPreparationCustody
	}
	s, e := NewPipeServer()
	if e != nil {
		return nil, e
	}
	defer s.Close()
	args, e := fixedPreservationArguments(FixedPreservationBootstrap{1, s.Name(), self, pin.Identity()})
	if e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	h, e := launchElevatedSelf(pin.Identity().Path, args)
	if e != nil {
		return nil, &FixedPreservationLaunchFailure{Phase: "launch", Cause: e}
	}
	// The actual launch handle immediately becomes the independent exit owner.
	// Accepted IPC has a different lifetime and cannot revoke this wait handle.
	return finishFixedPreservationLaunch(h, s.Close, func(h windows.Handle) (WorkerConnection, string, error) {
		pid, e := windows.GetProcessId(h)
		if e != nil {
			return nil, "identify-child", e
		}
		child, held, e := inspectPeer(pid)
		if e != nil {
			return nil, "inspect-child", e
		}
		defer windows.CloseHandle(held)
		if !child.Elevated || child.UserSID != self.UserSID || child.SessionID != self.SessionID || !strings.EqualFold(child.Executable, self.Executable) {
			return nil, "authenticate-child", ErrPreparationCustody
		}
		if e = pin.Verify(context.Background()); e != nil {
			return nil, "verify-executable", e
		}
		accept, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		c, e := s.Accept(accept, child)
		return c, "accept-bootstrap", e
	})
}

type FixedPreservationExit struct {
	WaitAttempted, Exited bool
	Code                  uint32
}
type FixedPreservationLaunchFailure struct {
	Phase string
	Exit  FixedPreservationExit
	Cause error
}

func (e *FixedPreservationLaunchFailure) Error() string {
	return fmt.Sprintf("fixed probe %s; wait-attempted=%t exited=%t exit=%d: %v", e.Phase, e.Exit.WaitAttempted, e.Exit.Exited, e.Exit.Code, e.Cause)
}
func (e *FixedPreservationLaunchFailure) Unwrap() error { return e.Cause }

// fixedProbeConnection keeps launch-process custody separate from IPC. Its
// Close disconnects then waits; it never kills or treats IPC loss as exit.
type fixedProbeConnection struct {
	connection          WorkerConnection
	process             windows.Handle
	waitOnce, closeOnce sync.Once
	exit                FixedPreservationExit
	waitErr, closeErr   error
}

func (c *fixedProbeConnection) Read(b []byte) (int, error)  { return c.connection.Read(b) }
func (c *fixedProbeConnection) Write(b []byte) (int, error) { return c.connection.Write(b) }
func (c *fixedProbeConnection) PeerIdentity() PeerIdentity  { return c.connection.PeerIdentity() }
func (c *fixedProbeConnection) disconnect() error {
	if c.connection == nil {
		return nil
	}
	return c.connection.Close()
}
func (c *fixedProbeConnection) wait() (FixedPreservationExit, error) {
	c.waitOnce.Do(func() {
		c.exit.WaitAttempted = true
		state, e := windows.WaitForSingleObject(c.process, windows.INFINITE)
		if e != nil || state != windows.WAIT_OBJECT_0 {
			c.waitErr = errors.Join(e, ErrPreparationCustody)
			return
		}
		c.exit.Exited = true
		c.waitErr = windows.GetExitCodeProcess(c.process, &c.exit.Code)
	})
	return c.exit, c.waitErr
}
func (c *fixedProbeConnection) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.disconnect()
		exit, e := c.wait()
		c.closeErr = errors.Join(c.closeErr, e)
		if exit.Exited {
			c.closeErr = errors.Join(c.closeErr, windows.CloseHandle(c.process))
		}
	})
	return c.closeErr
}

// This post-launch seam cannot select or launch a command. Tests inject only
// bootstrap refusal over an already owned unprivileged helper process.
func finishFixedPreservationLaunch(h windows.Handle, disconnectBootstrap func() error, connect func(windows.Handle) (WorkerConnection, string, error)) (WorkerConnection, error) {
	owner := &fixedProbeConnection{process: h}
	c, phase, e := connect(h)
	owner.connection = c
	if e == nil && c != nil {
		return owner, nil
	}
	if e == nil {
		e = ErrPreparationCustody
	}
	// Disconnect both partial IPC and the listener before waiting for refusal.
	disconnectErr := errors.Join(owner.disconnect(), disconnectBootstrap())
	exit, waitErr := owner.wait()
	closeErr := owner.Close()
	return nil, &FixedPreservationLaunchFailure{Phase: phase, Exit: exit, Cause: errors.Join(e, disconnectErr, waitErr, closeErr)}
}

// DisconnectFixedPreservationProbe cancels/drains only IPC. The independent
// actual-process owner survives for WaitFixedPreservationProbe and Close.
func DisconnectFixedPreservationProbe(c WorkerConnection) error {
	p, ok := c.(*fixedProbeConnection)
	if !ok {
		return ErrPreparationCustody
	}
	return p.disconnect()
}
func ConnectFixedPreservationProbe(ctx context.Context, b FixedPreservationBootstrap) (WorkerConnection, *PinnedExecutable, error) {
	if e := b.validate(); e != nil {
		return nil, nil, e
	}
	self, e := CurrentPeerIdentity()
	if e != nil {
		return nil, nil, e
	}
	if !self.Elevated || self.UserSID != b.Parent.UserSID || self.SessionID != b.Parent.SessionID || !samePinnedPath(self.Executable, b.Executable.Path) {
		return nil, nil, ErrPreparationCustody
	}
	p, e := OpenPinnedExecutable(ctx, self.Executable)
	if e != nil {
		return nil, nil, e
	}
	if p.Identity() != b.Executable {
		return nil, nil, errors.Join(ErrPreparationCustody, p.Close())
	}
	c, e := DialWorkerPipe(ctx, b.PipeName, b.Parent)
	if e != nil {
		return nil, nil, errors.Join(e, p.Close())
	}
	return c, p, nil
}

// WaitFixedPreservationProbe waits for actual target exit even after IPC loss.
// It never kills the target or treats cancellation as successful restoration.
func WaitFixedPreservationProbe(c WorkerConnection) (uint32, error) {
	p, ok := c.(*fixedProbeConnection)
	if !ok || p.process == 0 {
		return 0, ErrPreparationCustody
	}
	exit, e := p.wait()
	return exit.Code, e
}

// OpenPreparationParent checks current root/owner/ancestor identities. The
// returned object is custody only; an editable descriptor grants no operation
// or consent. The fixed test calls this only after authenticating its parent.
func OpenPreparationParent(expected PreparationParentIdentity) (*PinnedWorkspace, error) {
	w, e := OpenWorkspace(expected.Workspace)
	if e != nil {
		return nil, e
	}
	c, e := pinDirectoryChain(expected.Workspace.Path)
	if e != nil {
		return nil, errors.Join(e, w.Close())
	}
	p := &PinnedWorkspace{workspace: w, chain: c, id: expected, ownsWorkspace: true}
	p.owner, e = nativeTreeOpenShared(windows.Handle(c.files[len(c.files)-1].Fd()), ownerFile, windows.FILE_GENERIC_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_SHARE_READ, nil)
	if e == nil && (len(c.ids) < 2 || c.ids[len(c.ids)-1] != expected.Root || c.ids[len(c.ids)-2] != expected.Parent) {
		e = ErrPreparationCustody
	}
	if e == nil {
		e = p.Check(expected.Workspace.Path)
	}
	if e == nil {
		var marker WorkspaceIdentity
		body, readErr := io.ReadAll(io.LimitReader(p.owner, 4097))
		if readErr != nil || len(body) > 4096 || json.Unmarshal(body, &marker) != nil || marker != expected.Workspace {
			e = errors.Join(readErr, ErrPreparationCustody)
		}
	}
	if e != nil {
		return nil, errors.Join(e, p.Close(), w.Close())
	}
	return p, nil
}
