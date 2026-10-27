package windows

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/model"
)

func TestInvocationPreservesUnicodeAndSpaceArguments(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "argv-job")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	exe, _ := os.Executable()
	want := []string{"日本語 with spaces", "", `literal"quote`, `C:\space dir\`, "& | %PATH% $(no shell)"}
	args := append([]string{"-test.run=^TestPlatformHelper$", "--", "--w1-helper", "argv"}, want...)
	result, err := NewRunner().Run(context.Background(), Invocation{Executable: exe, Arguments: args, Workspace: w, JobID: "argv-job", OperationID: "argv-op", Cancellation: CancelTerminateTree}, nil)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, result.Stderr)
	}
	var got []string
	if err := json.Unmarshal([]byte(result.Stdout), &got); err != nil {
		t.Fatalf("%v output=%q", err, result.Stdout)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv %#v, want %#v", got, want)
	}
}

func TestCancellationTouchesOnlyOwnedProcessTree(t *testing.T) {
	exe, _ := os.Executable()
	unrelated := exec.Command(exe, "-test.run=^TestPlatformHelper$", "--", "--w1-helper", "sleep")
	unrelated.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { unrelated.Process.Kill(); unrelated.Wait() }()
	w, err := CreateWorkspace(t.TempDir(), "cancel-job")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan processTestResult, 1)
	go func() {
		result, e := NewRunner().Run(ctx, Invocation{Executable: exe, Arguments: []string{"-test.run=^TestPlatformHelper$", "--", "--w1-helper", "tree"}, Workspace: w, JobID: "cancel-job", OperationID: "tree-op", Cancellation: CancelTerminateTree}, nil)
		done <- processTestResult{result: result, err: e}
	}()
	pidPath := filepath.Join(w.Path(), "child.pid")
	readyCtx, readyCancel := context.WithTimeout(ctx, 10*time.Second)
	defer readyCancel()
	childPID, err := awaitOwnedChildPID(readyCtx, func() ([]byte, error) { return os.ReadFile(pidPath) }, done)
	if err != nil {
		t.Fatal(err)
	}
	child, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, childPID)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(child)
	cancel()
	select {
	case completed := <-done:
		if !errors.Is(completed.err, context.Canceled) {
			t.Fatalf("cancel error %v", completed.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runner did not cancel")
	}
	if state, err := windows.WaitForSingleObject(child, 3000); err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatalf("owned child survived: %d %v", state, err)
	}
	other, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(unrelated.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(other)
	if state, _ := windows.WaitForSingleObject(other, 0); state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatal("unrelated process terminated")
	}
}

type processTestResult struct {
	result RunResult
	err    error
}

// The helper commits a PID record with its final newline. An existing file or
// a parseable digit prefix alone does not mean its publication is complete.
func awaitOwnedChildPID(ctx context.Context, read func() ([]byte, error), done <-chan processTestResult) (uint32, error) {
	premature := func(completed processTestResult) (uint32, error) {
		message := fmt.Sprintf("runner exited before child readiness: exit=%d stderr=%q", completed.result.ExitCode, completed.result.Stderr)
		if completed.err != nil {
			return 0, fmt.Errorf("%s: %w", message, completed.err)
		}
		return 0, errors.New(message)
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	var lastObservation error
	for {
		select {
		case completed := <-done:
			return premature(completed)
		default:
		}
		if err := ctx.Err(); err != nil {
			return 0, fmt.Errorf("owned child readiness: %w (last observation: %v)", err, lastObservation)
		}
		b, err := read()
		if err == nil {
			if len(b) > 0 && b[len(b)-1] == '\n' {
				pid, parseErr := strconv.ParseUint(string(b[:len(b)-1]), 10, 32)
				if parseErr == nil && pid > 0 {
					return uint32(pid), nil
				}
			}
			lastObservation = fmt.Errorf("incomplete or invalid PID record %q", b)
		} else if !errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("read owned child readiness: %w", err)
		} else {
			lastObservation = err
		}
		select {
		case completed := <-done:
			return premature(completed)
		case <-ctx.Done():
			return 0, fmt.Errorf("owned child readiness: %w (last observation: %v)", ctx.Err(), lastObservation)
		case <-tick.C:
		}
	}
}

func TestOwnedChildReadinessWaitsForCompletePID(t *testing.T) {
	for _, tc := range []struct{ name, partial string }{
		{"empty created file", ""},
		{"partial digits", "43"},
		{"zero PID", "0\n"},
		{"malformed PID", "4321 trailing\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "child.pid")
			if err := os.WriteFile(path, []byte(tc.partial), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			observed := make(chan struct{})
			release := make(chan struct{})
			waiting := make(chan processTestResult, 1)
			first := true
			go func() {
				pid, err := awaitOwnedChildPID(ctx, func() ([]byte, error) {
					b, err := os.ReadFile(path)
					if first {
						first = false
						close(observed)
						select {
						case <-release:
						case <-ctx.Done():
						}
					}
					return b, err
				}, nil)
				waiting <- processTestResult{result: RunResult{ProcessID: pid}, err: err}
			}()
			select {
			case <-observed:
			case <-ctx.Done():
				t.Fatal("reader did not reach gated file read")
			}
			// The first read has captured incomplete content. Publish before releasing
			// that snapshot, forcing the create-before-write interleaving without sleeps.
			if err := os.WriteFile(path, []byte("8765\n"), 0600); err != nil {
				t.Fatal(err)
			}
			close(release)
			select {
			case got := <-waiting:
				if got.err != nil || got.result.ProcessID != 8765 {
					t.Fatalf("readiness accepted incomplete snapshot: PID=%d error=%v", got.result.ProcessID, got.err)
				}
			case <-ctx.Done():
				t.Fatal("readiness did not observe complete publication")
			}
		})
	}
}

func TestOwnedChildReadinessReportsPrematureRunnerExit(t *testing.T) {
	launchErr := errors.New("native launch failed")
	for _, tc := range []struct {
		name      string
		completed processTestResult
	}{
		{"failed runner", processTestResult{result: RunResult{ExitCode: 7, Stderr: "helper startup diagnostic"}, err: launchErr}},
		{"early successful exit", processTestResult{result: RunResult{ExitCode: 0}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan processTestResult, 1)
			done <- tc.completed
			_, err := awaitOwnedChildPID(ctx, func() ([]byte, error) { cancel(); return nil, os.ErrNotExist }, done)
			if err == nil || !strings.Contains(err.Error(), "runner exited before child readiness") || (tc.completed.err != nil && !errors.Is(err, tc.completed.err)) || (tc.completed.result.Stderr != "" && !strings.Contains(err.Error(), tc.completed.result.Stderr)) {
				t.Fatalf("premature runner diagnostics lost: %v", err)
			}
		})
	}
}

func TestInvocationRejectsUnownedAndShellPaths(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "job")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	exe, _ := os.Executable()
	for _, inv := range []Invocation{{Executable: "relative.exe", Workspace: w, JobID: "job", OperationID: "op", Cancellation: CancelTerminateTree}, {Executable: `C:\Windows\System32\cmd.bat`, Workspace: w, JobID: "job", OperationID: "op", Cancellation: CancelTerminateTree}, {Executable: exe, Workspace: w, JobID: "other", OperationID: "op", Cancellation: CancelTerminateTree}, {Executable: exe, Workspace: w, JobID: "job", OperationID: "op"}} {
		if _, err := NewRunner().Run(context.Background(), inv, nil); err == nil {
			t.Fatalf("accepted %#v", inv)
		}
	}
}

func TestRunnerPreservesFailureOutputAndBoundsCapture(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "job")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	exe, _ := os.Executable()
	inv := Invocation{Executable: exe, Workspace: w, JobID: "job", OperationID: "op", Cancellation: CancelTerminateTree, Arguments: []string{"-test.run=^TestPlatformHelper$", "--", "--w1-helper", "failure"}}
	r, err := NewRunner().Run(context.Background(), inv, nil)
	var exit *ProcessExitError
	if !errors.As(err, &exit) || exit.Code != 7 || r.Stderr != "failed" {
		t.Fatalf("failure result %#v error %v", r, err)
	}
	inv.Arguments[len(inv.Arguments)-1] = "large"
	r, err = NewRunner().Run(context.Background(), inv, nil)
	if err != nil || len(r.Stdout) != 65536 || r.Stdout != strings.Repeat("a", 65536) {
		t.Fatalf("capture length %d error %v", len(r.Stdout), err)
	}
}

func TestRunnerWaitPolicyFinishesMutationBeforeReturningCancellation(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "job")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	exe, _ := os.Executable()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := NewRunner().Run(ctx, Invocation{Executable: exe, Workspace: w, JobID: "job", OperationID: "op", Cancellation: CancelWait, Arguments: []string{"-test.run=^TestPlatformHelper$", "--", "--w1-helper", "mutation"}}, func(e model.Event) {
		if strings.Contains(e.Message, "started") {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) || !r.Cancelled || r.Stdout != "startedcompleted" || r.ExitCode != 0 {
		t.Fatalf("wait result %#v error %v", r, err)
	}
}

func TestPlatformHelper(t *testing.T) {
	i := -1
	for n, arg := range os.Args {
		if arg == "--w1-helper" {
			i = n
			break
		}
	}
	if i < 0 {
		return
	}
	mode := os.Args[i+1]
	switch mode {
	case "argv":
		json.NewEncoder(os.Stdout).Encode(os.Args[i+2:])
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	case "tree":
		exe, _ := os.Executable()
		c := exec.Command(exe, "-test.run=^TestPlatformHelper$", "--", "--w1-helper", "sleep")
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := c.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := os.WriteFile("child.pid", []byte(fmt.Sprintf("%d\n", c.Process.Pid)), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "publish owned child readiness: %v\n", err)
			os.Exit(2)
		}
		c.Wait()
		os.Exit(0)
	case "short":
		time.Sleep(150 * time.Millisecond)
		fmt.Print("completed")
		os.Exit(0)
	case "mutation":
		fmt.Print("started")
		time.Sleep(150 * time.Millisecond)
		fmt.Print("completed")
		os.Exit(0)
	case "failure":
		fmt.Fprint(os.Stderr, "failed")
		os.Exit(7)
	case "large":
		fmt.Print(strings.Repeat("a", 100000))
		os.Exit(0)
	case "window":
		h, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
		fmt.Print(h)
		os.Exit(0)
	case "pipe-client":
		var peer PeerIdentity
		b, err := base64.RawURLEncoding.DecodeString(os.Args[i+3])
		if err != nil || json.Unmarshal(b, &peer) != nil {
			os.Exit(4)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := DialWorkerPipe(ctx, os.Args[i+2], peer)
		if err != nil {
			os.Exit(5)
		}
		defer c.Close()
		if _, err := c.Write([]byte("hello")); err != nil {
			os.Exit(6)
		}
		reply := make([]byte, 5)
		if _, err := io.ReadFull(c, reply); err != nil || string(reply) != "world" {
			os.Exit(7)
		}
		os.Exit(0)
	}
	os.Exit(3)
}
