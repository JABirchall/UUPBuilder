package windows

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// This helper is an ordinary unprivileged subprocess. It only waits for its
// owned stdin EOF and exits; it never enters the configured proof/elevation path.
func TestFixedProbeLifecycleHelper(t *testing.T) {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "--fixed-probe-lifecycle-exit" {
		return
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(17)
}

func fixedProbeProcessFixture(t *testing.T) (windows.Handle, io.WriteCloser) {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestFixedProbeLifecycleHelper$", "--", "--fixed-probe-lifecycle-exit")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	in, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { in.Close(); cmd.Wait() })
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	if e != nil {
		t.Fatal(e)
	}
	return h, in
}

// Removing failure-path disconnect/wait would leave the actual helper alive
// when the wrapper returns, and erase the real exit from the launch failure.
func TestFixedProbePostLaunchFailuresDisconnectAndWaitActualChild(t *testing.T) {
	for _, phase := range []string{"inspect-child", "accept-bootstrap"} {
		t.Run(phase, func(t *testing.T) {
			h, in := fixedProbeProcessFixture(t)
			cause := errors.New("injected " + phase)
			done := make(chan error, 1)
			go func() {
				probe, e := finishFixedPreservationLaunch(h, in.Close, func(windows.Handle) (WorkerConnection, string, error) { return nil, phase, cause })
				if probe != nil {
					probe.Close()
				}
				done <- e
			}()
			var e error
			select {
			case e = <-done:
			case <-time.After(3 * time.Second):
				in.Close()
				e = <-done
				t.Error("post-launch failure did not disconnect before exit wait")
			}
			var failed *FixedPreservationLaunchFailure
			if !errors.As(e, &failed) || !errors.Is(e, cause) || failed.Phase != phase || !failed.Exit.WaitAttempted || !failed.Exit.Exited || failed.Exit.Code != 17 {
				t.Fatalf("lost launch/actual exit evidence: %#v %v", failed, e)
			}
		})
	}
}

type fixedLifecycleConnection struct {
	io.WriteCloser
	once sync.Once
	err  error
}

func (c *fixedLifecycleConnection) Read([]byte) (int, error)   { return 0, io.EOF }
func (c *fixedLifecycleConnection) PeerIdentity() PeerIdentity { return PeerIdentity{} }
func (c *fixedLifecycleConnection) Close() error {
	c.once.Do(func() { c.err = c.WriteCloser.Close() })
	return c.err
}

func TestFixedProbeDisconnectKeepsActualExitOwner(t *testing.T) {
	h, in := fixedProbeProcessFixture(t)
	c, e := finishFixedPreservationLaunch(h, func() error { return nil }, func(windows.Handle) (WorkerConnection, string, error) {
		return &fixedLifecycleConnection{WriteCloser: in}, "", nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = DisconnectFixedPreservationProbe(c); e != nil {
		t.Fatal(e)
	}
	exit, e := WaitFixedPreservationProbe(c)
	if e != nil || exit != 17 {
		t.Fatalf("disconnect revoked actual wait owner: %d %v", exit, e)
	}
	if e = c.Close(); e != nil {
		t.Fatal(e)
	}
}
