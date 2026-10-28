package windows

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestSessionRejectsInvalidWorkspace(t *testing.T) {
	for _, w := range []*Workspace{nil, {}} {
		if s, err := NewSessionRunner(w); err == nil {
			s.Close()
			t.Fatal("accepted missing workspace capability")
		}
	}
	w, err := CreateWorkspace(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if s, err := NewSessionRunner(w); err == nil {
		s.Close()
		t.Fatal("accepted closed workspace")
	}
}

func TestSessionScopeAndClosure(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "scope")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	s, err := NewSessionRunner(w)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	exe, _ := os.Executable()
	inv := Invocation{Executable: exe, Arguments: []string{"-test.run=^TestPlatformHelper$", "--", "--w1-helper", "short"}, Workspace: w, JobID: "scope", OperationID: "op", Cancellation: CancelTerminateTree}
	other, err := OpenWorkspace(w.Identity())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	for _, tc := range []struct {
		name string
		edit func(*Invocation)
	}{
		{"another borrowed handle", func(i *Invocation) { i.Workspace = other }},
		{"another job", func(i *Invocation) { i.JobID = "another" }},
		{"unknown cancellation", func(i *Invocation) { i.Cancellation = "unknown" }},
		{"relative executable", func(i *Invocation) { i.Executable = "relative.exe" }},
		{"script executable", func(i *Invocation) { i.Executable = `C:\script.bat` }},
		{"NUL argument", func(i *Invocation) { i.Arguments = []string{"bad\x00arg"} }},
		{"escaping directory", func(i *Invocation) { i.Directory = "../outside" }},
		{"missing directory", func(i *Invocation) { i.Directory = "missing" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := inv
			tc.edit(&bad)
			if result, err := s.Run(context.Background(), bad, nil); err == nil || result.ProcessID != 0 {
				t.Fatalf("invalid invocation launched: %#v %v", result, err)
			}
		})
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
	if result, err := s.Run(context.Background(), inv, nil); err == nil || result.ProcessID != 0 {
		t.Fatalf("closed session launched: %#v %v", result, err)
	}
	if f, err := w.OpenFile("borrowed", os.O_CREATE|os.O_WRONLY, 0600); err != nil {
		t.Fatalf("session closed borrowed workspace: %v", err)
	} else {
		f.Close()
	}
	var nilSession *SessionRunner
	if result, err := nilSession.Run(context.Background(), inv, nil); err == nil || result.ProcessID != 0 {
		t.Fatalf("nil session launched: %#v %v", result, err)
	}
	if err := nilSession.Close(); err == nil {
		t.Fatal("nil session Close accepted")
	}
	var zero SessionRunner
	if result, err := zero.Run(context.Background(), inv, nil); err == nil || result.ProcessID != 0 {
		t.Fatalf("zero session launched: %#v %v", result, err)
	}
	if err := zero.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRejectsClosedBorrowedWorkspace(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "closed-borrow")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSessionRunner(w)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	inv := Invocation{Executable: exe, Workspace: w, JobID: "closed-borrow", OperationID: "op", Cancellation: CancelTerminateTree}
	if result, err := s.Run(context.Background(), inv, nil); err == nil || result.ProcessID != 0 {
		t.Fatalf("closed workspace launched: %#v %v", result, err)
	}
}

func TestSessionPipeDrainsCompletedBytesWithoutWriterEOF(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, err := w.Write([]byte("completed parent tail")); err != nil {
		t.Fatal(err)
	}
	parentDone := make(chan struct{})
	close(parentDone)
	done := make(chan string, 1)
	go func() { done <- captureOutput(&sessionPipeReader{file: r, parentDone: parentDone}, Invocation{}, nil) }()
	select {
	case got := <-done:
		if got != "completed parent tail" {
			t.Fatalf("completed output lost: %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("completed-pipe snapshot waited for retained writer EOF")
	}
}
