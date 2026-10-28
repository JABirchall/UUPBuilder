//go:build windows && windowsintegration

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
)

func sessionFixture(t *testing.T, job string) (*SessionRunner, *Workspace) {
	t.Helper()
	w, err := CreateWorkspace(t.TempDir(), job)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	s, err := NewSessionRunner(w)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, w
}

func sessionInvocation(w *Workspace, mode string, extra ...string) Invocation {
	exe, _ := os.Executable()
	args := append([]string{"-test.run=^TestSessionHelper$", "--", "--session-helper", mode}, extra...)
	return Invocation{Executable: exe, Arguments: args, Workspace: w, JobID: w.Identity().JobID, OperationID: "session-op", Cancellation: CancelTerminateTree}
}

func sessionRunPhase(t *testing.T, s ProcessRunner, inv Invocation) RunResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan processTestResult, 1)
	go func() { r, err := s.Run(ctx, inv, nil); done <- processTestResult{r, err} }()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("command %q: %#v %v", inv.Arguments, got.result, got.err)
		}
		return got.result
	case <-ctx.Done():
		t.Fatalf("parent-exit/pipe-drain phase timed out: %v", ctx.Err())
		return RunResult{}
	}
}

func sessionChild(t *testing.T, w *Workspace) windows.Handle {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(w.Path(), "child.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.ParseUint(strings.TrimSuffix(string(b), "\n"), 10, 32)
	if err != nil {
		t.Fatalf("complete child PID: %q %v", b, err)
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		t.Fatalf("retained child disappeared: %v", err)
	}
	t.Cleanup(func() { windows.CloseHandle(h) })
	return h
}

func assertSessionChild(t *testing.T, h windows.Handle, alive bool) {
	t.Helper()
	budget := uint32(0)
	want := uint32(windows.WAIT_TIMEOUT)
	if !alive {
		budget = 5000
		want = windows.WAIT_OBJECT_0
	}
	state, err := windows.WaitForSingleObject(h, budget)
	if err != nil || state != want {
		t.Fatalf("child alive=%t: state=%d error=%v", alive, state, err)
	}
}

func TestWindowsIntegrationSessionRetainsAcrossCommands(t *testing.T) {
	s, w := sessionFixture(t, "retained")
	sessionRunPhase(t, s, sessionInvocation(w, "retain"))
	child := sessionChild(t, w)
	assertSessionChild(t, child, true)
	query := sessionRunPhase(t, s, sessionInvocation(w, "query"))
	if query.Stdout != "alive" {
		t.Fatalf("later command could not use retained helper: %q", query.Stdout)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	assertSessionChild(t, child, false)
}

func TestWindowsIntegrationSessionHeldPipeReturnsParentTail(t *testing.T) {
	s, w := sessionFixture(t, "held-pipe")
	r := sessionRunPhase(t, s, sessionInvocation(w, "held"))
	child := sessionChild(t, w)
	assertSessionChild(t, child, true)
	if len(r.Stdout) != 65536 || !strings.HasSuffix(r.Stdout, "parent-out-tail") || len(r.Stderr) != 65536 || !strings.HasSuffix(r.Stderr, "parent-err-tail") {
		t.Fatalf("parent completed output lost: stdout=%d stderr=%d", len(r.Stdout), len(r.Stderr))
	}
	query := sessionRunPhase(t, s, sessionInvocation(w, "query"))
	if query.Stdout != "alive" {
		t.Fatalf("held-pipe descendant was not retained: %q", query.Stdout)
	}
}

func sessionWaitResult(t *testing.T, phase string, done <-chan processTestResult) processTestResult {
	t.Helper()
	select {
	case got := <-done:
		return got
	case <-time.After(10 * time.Second):
		t.Fatalf("%s phase timed out", phase)
		return processTestResult{}
	}
}

func sessionAwaitStarted(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("active-command readiness phase timed out")
	}
}

// Done is evaluated as Run enters its gate select, so tests can establish that
// a second call reached the queue before cancellation or Close begins.
type sessionQueuedContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *sessionQueuedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestWindowsIntegrationSessionForcedCancellationEndsOnlySession(t *testing.T) {
	s, w := sessionFixture(t, "cancel-session")
	other, ow := sessionFixture(t, "other-session")
	sessionRunPhase(t, s, sessionInvocation(w, "retain"))
	prior := sessionChild(t, w)
	sessionRunPhase(t, other, sessionInvocation(ow, "held"))
	otherChild := sessionChild(t, ow)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan processTestResult, 1)
	started := make(chan struct{}, 1)
	go func() {
		r, err := s.Run(ctx, sessionInvocation(w, "block"), func(e model.Event) {
			if e.Message == "started" {
				started <- struct{}{}
			}
		})
		done <- processTestResult{r, err}
	}()
	sessionAwaitStarted(t, started)
	activeChild := sessionChild(t, w)
	cancel()
	got := sessionWaitResult(t, "forced cancellation", done)
	if !errors.Is(got.err, context.Canceled) || !got.result.Cancelled {
		t.Fatalf("cancel result %#v %v", got.result, got.err)
	}
	assertSessionChild(t, prior, false)
	assertSessionChild(t, activeChild, false)
	assertSessionChild(t, otherChild, true)
	sessionRunPhase(t, other, sessionInvocation(ow, "query"))
	if r, err := s.Run(context.Background(), sessionInvocation(w, "retain"), nil); err == nil || r.ProcessID != 0 {
		t.Fatalf("cancelled session reused: %#v %v", r, err)
	}
}

func TestWindowsIntegrationSessionClosePreservesOtherOwnersAndStartupFailure(t *testing.T) {
	s, w := sessionFixture(t, "close-session")
	other, ow := sessionFixture(t, "surviving-session")
	sessionRunPhase(t, s, sessionInvocation(w, "retain"))
	child := sessionChild(t, w)
	sessionRunPhase(t, other, sessionInvocation(ow, "retain"))
	otherChild := sessionChild(t, ow)
	broken := sessionInvocation(w, "retain")
	broken.Executable = filepath.Join(w.Path(), "missing.exe")
	if r, err := s.Run(context.Background(), broken, nil); err == nil || r.ProcessID != 0 {
		t.Fatalf("missing executable launched: %#v %v", r, err)
	}
	broken.Executable = filepath.Join(w.Path(), "invalid.exe")
	if err := os.WriteFile(broken.Executable, []byte("invalid native image"), 0600); err != nil {
		t.Fatal(err)
	}
	if r, err := s.Run(context.Background(), broken, nil); err == nil || r.ProcessID != 0 {
		t.Fatalf("invalid native image launched: %#v %v", r, err)
	}
	sessionRunPhase(t, s, sessionInvocation(w, "query"))
	// A separate default Runner owns its own live invocation, even in the same workspace.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 1)
	done := make(chan processTestResult, 1)
	go func() {
		r, err := NewRunner().Run(ctx, sessionInvocation(w, "gated"), func(e model.Event) {
			if e.Message == "started" {
				started <- struct{}{}
			}
		})
		done <- processTestResult{r, err}
	}()
	sessionAwaitStarted(t, started)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	assertSessionChild(t, child, false)
	assertSessionChild(t, otherChild, true)
	sessionRunPhase(t, other, sessionInvocation(ow, "query"))
	if err := os.WriteFile(filepath.Join(w.Path(), "release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	got := sessionWaitResult(t, "unrelated owned invocation natural exit", done)
	if got.err != nil || got.result.Stdout != "startedcompleted" {
		t.Fatalf("unrelated invocation affected: %#v %v", got.result, got.err)
	}
}

func TestWindowsIntegrationSessionSerializesAndCloseWaitsForCancelWait(t *testing.T) {
	s, w := sessionFixture(t, "wait-session")
	defer os.WriteFile(filepath.Join(w.Path(), "release"), nil, 0600)
	sessionRunPhase(t, s, sessionInvocation(w, "retain"))
	child := sessionChild(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inv := sessionInvocation(w, "gated")
	inv.Cancellation = CancelWait
	started := make(chan struct{}, 1)
	done := make(chan processTestResult, 1)
	go func() {
		r, err := s.Run(ctx, inv, func(e model.Event) {
			if e.Message == "started" {
				started <- struct{}{}
			}
		})
		done <- processTestResult{r, err}
	}()
	sessionAwaitStarted(t, started)
	queuedCtx, queuedCancel := context.WithCancel(context.Background())
	queueContext := &sessionQueuedContext{Context: queuedCtx, entered: make(chan struct{})}
	queued := make(chan processTestResult, 1)
	go func() {
		r, err := s.Run(queueContext, sessionInvocation(w, "query"), nil)
		queued <- processTestResult{r, err}
	}()
	sessionAwaitStarted(t, queueContext.entered)
	queuedCancel()
	got := sessionWaitResult(t, "queued command cancellation", queued)
	if !errors.Is(got.err, context.Canceled) || got.result.ProcessID != 0 {
		t.Fatalf("queued command launched: %#v %v", got.result, got.err)
	}
	waitingContext := &sessionQueuedContext{Context: context.Background(), entered: make(chan struct{})}
	waiting := make(chan processTestResult, 1)
	go func() {
		r, err := s.Run(waitingContext, sessionInvocation(w, "query"), nil)
		waiting <- processTestResult{r, err}
	}()
	sessionAwaitStarted(t, waitingContext.entered)
	cancel()
	closed := make(chan error, 2)
	go func() { closed <- s.Close() }()
	go func() { closed <- s.Close() }()
	select {
	case <-s.closing:
	case <-time.After(10 * time.Second):
		t.Fatal("Close begin phase timed out")
	}
	got = sessionWaitResult(t, "already queued Run rejection after Close begins", waiting)
	if got.err == nil || got.result.ProcessID != 0 {
		t.Fatalf("Close launched queued work: %#v %v", got.result, got.err)
	}
	rejected := make(chan processTestResult, 1)
	go func() {
		r, err := s.Run(context.Background(), sessionInvocation(w, "query"), nil)
		rejected <- processTestResult{r, err}
	}()
	got = sessionWaitResult(t, "Run rejection after Close begins", rejected)
	if got.err == nil || got.result.ProcessID != 0 {
		t.Fatalf("closing session accepted queued work: %#v %v", got.result, got.err)
	}
	// The active helper cannot finish before this owned release; Close must preserve it.
	select {
	case err := <-closed:
		t.Fatalf("Close returned before safe natural exit: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	assertSessionChild(t, child, true)
	if err := os.WriteFile(filepath.Join(w.Path(), "release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	got = sessionWaitResult(t, "CancelWait natural exit", done)
	if !errors.Is(got.err, context.Canceled) || !got.result.Cancelled || got.result.ExitCode != 0 || got.result.Stdout != "startedcompleted" {
		t.Fatalf("wait result %#v %v", got.result, got.err)
	}
	for n := 0; n < 2; n++ {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Close completion phase timed out")
		}
	}
	assertSessionChild(t, child, false)
}

func TestWindowsIntegrationSessionCancelWaitKeepsSessionReusable(t *testing.T) {
	s, w := sessionFixture(t, "reusable-wait")
	defer os.WriteFile(filepath.Join(w.Path(), "release"), nil, 0600)
	sessionRunPhase(t, s, sessionInvocation(w, "retain"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inv := sessionInvocation(w, "gated")
	inv.Cancellation = CancelWait
	deferred := make(chan struct{}, 1)
	done := make(chan processTestResult, 1)
	go func() {
		r, err := s.Run(ctx, inv, func(e model.Event) {
			if e.Message == "started" {
				cancel()
			}
			if strings.Contains(e.Message, "Cancellation deferred") {
				deferred <- struct{}{}
			}
		})
		done <- processTestResult{r, err}
	}()
	sessionAwaitStarted(t, deferred)
	if err := os.WriteFile(filepath.Join(w.Path(), "release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	got := sessionWaitResult(t, "reusable CancelWait natural exit", done)
	if !errors.Is(got.err, context.Canceled) || !got.result.Cancelled || got.result.Stdout != "startedcompleted" {
		t.Fatalf("wait result %#v %v", got.result, got.err)
	}
	sessionRunPhase(t, s, sessionInvocation(w, "query"))
}

// Only this trusted Go test executable is launched; no shells or image tools.
func TestSessionHelper(t *testing.T) {
	i := -1
	for n, arg := range os.Args {
		if arg == "--session-helper" {
			i = n
			break
		}
	}
	if i < 0 {
		return
	}
	self, err := CurrentPeerIdentity()
	if err != nil || self.Elevated {
		fmt.Fprintf(os.Stderr, "non-admin helper token required: elevated=%t error=%v", self.Elevated, err)
		os.Exit(4)
	}
	switch os.Args[i+1] {
	case "child":
		time.Sleep(time.Minute)
	case "retain", "held", "block":
		exe, _ := os.Executable()
		c := exec.Command(exe, "-test.run=^TestSessionHelper$", "--", "--session-helper", "child")
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if os.Args[i+1] != "retain" {
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
		}
		if err := c.Start(); err != nil {
			fmt.Fprint(os.Stderr, err)
			os.Exit(2)
		}
		if err := os.WriteFile("child.pid", []byte(fmt.Sprintf("%d\n", c.Process.Pid)), 0600); err != nil {
			fmt.Fprint(os.Stderr, err)
			os.Exit(2)
		}
		if os.Args[i+1] == "held" {
			fmt.Print(strings.Repeat("o", 100000) + "parent-out-tail")
			fmt.Fprint(os.Stderr, strings.Repeat("e", 100000)+"parent-err-tail")
		}
		if os.Args[i+1] == "block" {
			fmt.Print("started")
			time.Sleep(time.Minute)
		}
	case "query":
		b, err := os.ReadFile("child.pid")
		if err != nil {
			os.Exit(2)
		}
		pid, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
		if err != nil {
			os.Exit(2)
		}
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
		if err != nil {
			os.Exit(2)
		}
		state, err := windows.WaitForSingleObject(h, 0)
		windows.CloseHandle(h)
		if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
			os.Exit(2)
		}
		fmt.Print("alive")
	case "gated":
		fmt.Print("started")
		for {
			if _, err := os.Stat("release"); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		fmt.Print("completed")
	default:
		os.Exit(3)
	}
	os.Exit(0)
}
