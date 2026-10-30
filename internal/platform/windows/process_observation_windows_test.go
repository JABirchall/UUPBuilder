package windows

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestRunnerExitObservationDistinguishesCompletedAndUnlaunchedProcesses(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "exit-observation")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	inv := Invocation{Executable: executable, Workspace: w, JobID: w.Identity().JobID, OperationID: "exit-observation", Cancellation: CancelWait,
		Arguments: []string{"-test.run=^TestPlatformHelper$", "--", "--w1-helper", "short"}}
	result, err := NewRunner().Run(context.Background(), inv, nil)
	if err != nil || !result.ExitObserved || result.ExitCode != 0 {
		t.Fatalf("natural successful exit not observed: %+v, %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = NewRunner().Run(ctx, inv, nil)
	if !errors.Is(err, context.Canceled) || result.ExitObserved {
		t.Fatalf("unlaunched process claimed an observed exit: %+v, %v", result, err)
	}
	inv.Arguments[len(inv.Arguments)-1] = "failure"
	result, err = NewRunner().Run(context.Background(), inv, nil)
	var failed *ProcessExitError
	if !errors.As(err, &failed) || !result.ExitObserved || result.ExitCode != 7 {
		t.Fatalf("natural failed exit not observed: %+v, %v", result, err)
	}
}
