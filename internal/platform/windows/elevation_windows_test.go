package windows

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestElevationBootstrapOnlyContainsTypedJobIdentity(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	self, err := CurrentPeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	d := WorkerDescriptor{Version: 1, JobID: "job-1", PlanDigest: strings.Repeat("a", 64), Workspace: w.Identity()}
	b := WorkerBootstrap{Descriptor: d, PipeName: `\\.\pipe\uupbuilder-0123456789abcdef0123456789abcdef`, Parent: self}
	args, err := workerArguments(b)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseWorkerArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Descriptor != d || decoded.Parent != self {
		t.Fatalf("bootstrap changed %#v", decoded)
	}
	for _, bad := range [][]string{{"--uup-worker", "e30="}, {"--uup-worker", "bad"}, {"cmd.exe", "/c", "anything"}, append(args, "extra")} {
		if _, err := ParseWorkerArguments(bad); err == nil {
			t.Fatal("accepted invalid worker arguments")
		}
	}
	d.JobID = "other"
	if _, err := StartElevated(context.Background(), d); err == nil {
		t.Fatal("accepted foreign workspace")
	}
}

func TestElevationCancellationDoesNotPrompt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StartElevated(ctx, WorkerDescriptor{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel %v", err)
	}
}

func TestElevationUsesSameExecutableAndPropagatesConsentFailure(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	self, err := CurrentPeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	d := WorkerDescriptor{Version: 1, JobID: "job-1", PlanDigest: strings.Repeat("b", 64), Workspace: w.Identity()}
	denied := errors.New("simulated consent denied")
	_, err = startElevated(context.Background(), d, func(executable string, args []string) (windows.Handle, error) {
		if !strings.EqualFold(executable, self.Executable) {
			t.Fatalf("elevates %q, want %q", executable, self.Executable)
		}
		b, e := ParseWorkerArguments(args)
		if e != nil || b.Descriptor != d || b.Parent != self {
			t.Fatalf("invalid launch envelope %#v %v", b, e)
		}
		return 0, denied
	})
	if !errors.Is(err, denied) {
		t.Fatalf("lost consent failure: %v", err)
	}
}
