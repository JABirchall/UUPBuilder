//go:build windows && windowsintegration

package windows

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// Safe native integration: the only launched programs are this Go test binary.
func TestWindowsIntegrationConcurrentJobsAndHiddenConsole(t *testing.T) {
	runner := NewRunner()
	exe, _ := os.Executable()
	first, err := CreateWorkspace(t.TempDir(), "first")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := CreateWorkspace(t.TempDir(), "second")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	makeInvocation := func(w *Workspace, mode string) Invocation {
		return Invocation{Executable: exe, Arguments: []string{"-test.run=^TestPlatformHelper$", "--", "--w1-helper", mode}, Workspace: w, JobID: w.Identity().JobID, OperationID: "op", Cancellation: CancelTerminateTree}
	}
	result, err := runner.Run(context.Background(), makeInvocation(first, "window"), nil)
	if err != nil || result.Stdout != "0" {
		t.Fatalf("supporting console handle %q error %v", result.Stdout, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelled := make(chan error, 1)
	go func() { _, err := runner.Run(ctx, makeInvocation(first, "sleep"), nil); cancelled <- err }()
	time.AfterFunc(50*time.Millisecond, cancel)
	result, err = runner.Run(context.Background(), makeInvocation(second, "short"), nil)
	if err != nil || result.Stdout != "completed" {
		t.Fatalf("other owned job %#v %v", result, err)
	}
	if err := <-cancelled; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled job %v", err)
	}
}
