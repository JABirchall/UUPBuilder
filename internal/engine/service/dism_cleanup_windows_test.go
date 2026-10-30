package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

func TestDISMDiscardAcceptsOnlySuccessfulNaturalExitAfterCancellation(t *testing.T) {
	for _, tc := range []struct {
		name              string
		code              int
		commit, wantError bool
	}{
		{"discard-zero", 0, false, false},
		{"discard-nonzero", 7, false, true},
		{"commit-zero", 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := platform.CreateWorkspace(t.TempDir(), "cleanup-exit")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			mount, err := w.ClaimMount("mount", "service-image")
			if err != nil {
				t.Fatal(err)
			}
			d, err := NewDISM(context.Background(), w)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Replace only the external DISM process with this bounded helper. The
			// actual session runner, cancellation and native exit observation run.
			d.runner = dismRunnerFunc(func(ctx context.Context, inv platform.Invocation, emit model.Emit) (platform.RunResult, error) {
				inv.Executable = self
				inv.Arguments = append([]string{"-test.run=^TestDISMDelayedExitHelper$", "--", "--dism-delayed-exit", strconv.Itoa(tc.code)}, inv.Arguments...)
				return d.session.Run(ctx, inv, func(e model.Event) {
					if strings.Contains(e.Message, "cleanup-started") {
						cancel()
					}
					if emit != nil {
						emit(e)
					}
				})
			})
			err = d.Unmount(ctx, mount, tc.commit, nil)
			if tc.wantError {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation or failed helper: %v", err)
				}
			} else if err != nil {
				t.Fatalf("successful completed discard reported failed cleanup: %v", err)
			}
		})
	}
}

func TestDISMDelayedExitHelper(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--dism-delayed-exit" {
			code, err := strconv.Atoi(os.Args[i+1])
			if err != nil {
				os.Exit(99)
			}
			fmt.Print("cleanup-started\n")
			time.Sleep(75 * time.Millisecond)
			os.Exit(code)
		}
	}
}

func TestDISMDiscardRetainsUnobservedExitAndOtherObservationFailures(t *testing.T) {
	observationError := errors.New("native wait observation failed")
	for _, tc := range []struct {
		name      string
		result    platform.RunResult
		err       error
		wantError bool
	}{
		{"deadline-only-observed-zero", platform.RunResult{ExitObserved: true, Cancelled: true}, context.DeadlineExceeded, false},
		{"unobserved-zero-default", platform.RunResult{Cancelled: true}, context.DeadlineExceeded, true},
		{"additional-observation-error", platform.RunResult{ExitObserved: true, Cancelled: true}, errors.Join(context.DeadlineExceeded, observationError), true},
		{"observed-nonzero", platform.RunResult{ExitCode: 7, ExitObserved: true, Cancelled: true}, context.DeadlineExceeded, true},
		{"unconfirmed-cancellation", platform.RunResult{ExitObserved: true}, context.DeadlineExceeded, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := platform.CreateWorkspace(t.TempDir(), "cleanup-observation")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			mount, err := w.ClaimMount("mount", "service-image")
			if err != nil {
				t.Fatal(err)
			}
			d, err := NewDISM(context.Background(), w)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			d.runner = dismRunnerFunc(func(context.Context, platform.Invocation, model.Emit) (platform.RunResult, error) {
				return tc.result, tc.err
			})
			err = d.Unmount(context.Background(), mount, false, nil)
			if tc.wantError && (!errors.Is(err, tc.err) || err == nil) {
				t.Fatalf("cleanup lost observation failure: %v", err)
			}
			if !tc.wantError && err != nil {
				t.Fatalf("successful cleanup rejected: %v", err)
			}
		})
	}
}
