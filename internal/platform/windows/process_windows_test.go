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
	done := make(chan error, 1)
	go func() {
		_, e := NewRunner().Run(ctx, Invocation{Executable: exe, Arguments: []string{"-test.run=^TestPlatformHelper$", "--", "--w1-helper", "tree"}, Workspace: w, JobID: "cancel-job", OperationID: "tree-op", Cancellation: CancelTerminateTree}, nil)
		done <- e
	}()
	pidPath := filepath.Join(w.Path(), "child.pid")
	var childPID uint32
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		b, e := os.ReadFile(pidPath)
		if e == nil {
			fmt.Sscanf(string(b), "%d", &childPID)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID == 0 {
		cancel()
		t.Fatal("owned child did not start")
	}
	child, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, childPID)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(child)
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("cancel error %v", e)
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
		os.WriteFile("child.pid", []byte(fmt.Sprint(c.Process.Pid)), 0600)
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
