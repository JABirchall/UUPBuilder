//go:build windows

package jobstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestAtomicJournalFinalPromotionFailure(t *testing.T) {
	for _, point := range []string{"journal-before-write", "journal-after-write", "journal-before-replace", "journal-after-replace"} {
		t.Run(point, func(t *testing.T) {
			s, inspector := newStore(t)
			base := commitStage(t, s, intent("base"), "pristine")
			tx, err := s.Begin(testContext, intent("next"))
			if err != nil {
				t.Fatal(err)
			}
			out := writeOutput(t, tx, "image.wim", "validated")
			final := false
			triggered := false
			before := ""
			s.fail = func(p string) error {
				if p == "promotion-before-journal" {
					final = true
					before = readOwned(t, s, journalPath)
				}
				if final && p == point {
					triggered = true
					return errors.New("interrupted final journal")
				}
				return nil
			}
			if err := tx.Commit(testContext, []OutputIdentity{out}); err == nil || !triggered {
				t.Fatal("final journal interruption ignored")
			}
			if point != "journal-after-replace" && readOwned(t, s, journalPath) != before {
				t.Fatal("failed final journal replaced the previous record")
			}
			id := s.Identity()
			s.Close()
			reopened, err := Open(id, inspector)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			r, err := reopened.InspectRecovery(testContext, "job")
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if point == "journal-after-replace" {
				want = 2
			}
			if len(r.Checkpoints) != want {
				t.Fatalf("got %d checkpoints, want %d", len(r.Checkpoints), want)
			}
			for _, cp := range r.Checkpoints {
				if !cp.Valid {
					t.Fatal("journal advertised an invalid checkpoint")
				}
			}
			if readOwned(t, reopened, base.Outputs[0].Path) != "pristine" {
				t.Fatal("final journal failure changed prior checkpoint")
			}
		})
	}
}

func TestRecoveryPreservesCorruptJournal(t *testing.T) {
	s, inspector := newStore(t)
	base := commitStage(t, s, intent("base"), "pristine")
	id := s.Identity()
	s.Close()
	path := filepath.Join(id.Path, journalPath)
	bad := []byte(`{"sha256":"truncated`)
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(id, inspector); err == nil {
		reopened.Close()
		t.Fatal("truncated record accepted")
	}
	b, err := os.ReadFile(filepath.Join(id.Path, filepath.FromSlash(base.Outputs[0].Path)))
	if err != nil || string(b) != "pristine" {
		t.Fatal("corrupt journal recovery modified output")
	}
	b, err = os.ReadFile(path)
	if err != nil || string(b) != string(bad) {
		t.Fatal("corrupt journal overwritten")
	}
}

func TestRecoveryRejectsJournalOwnershipDrift(t *testing.T) {
	for _, kind := range []string{"candidate-path", "checkpoint-intent", "missing-checkpoint"} {
		t.Run(kind, func(t *testing.T) {
			s, inspector := newStore(t)
			commitStage(t, s, intent("base"), "pristine")
			next := clone(s.state)
			switch kind {
			case "candidate-path":
				candidate := next.Stages[0].Candidates[0]
				candidate.Path = next.Stages[0].Promotion + "/unowned.txt"
				next.Stages[0].Candidates = append(next.Stages[0].Candidates, candidate)
			case "checkpoint-intent":
				cp := &next.Checkpoints[0]
				cp.Checkpoint.Intent.Tools[0].Digest = digest("different tool")
				var err error
				cp.Checkpoint.Digest, err = checkpointDigest(cp.Checkpoint.Intent, cp.Checkpoint.Outputs, cp.Directory)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-checkpoint":
				next.Checkpoints = nil
			}
			if err := s.writeJournal(next); err != nil {
				t.Fatal(err)
			}
			id := s.Identity()
			s.Close()
			if reopened, err := Open(id, inspector); err == nil {
				reopened.Close()
				t.Fatal("inconsistent durable ownership record accepted")
			}
		})
	}
}

func TestAtomicJournalPublicationBarrierFailure(t *testing.T) {
	for _, kind := range []string{"intent", "promotion-intent", "checkpoint", "discard"} {
		t.Run(kind, func(t *testing.T) {
			s, inspector := newStore(t)
			base := commitStage(t, s, intent("base"), "pristine")
			var tx *Transaction
			var out OutputIdentity
			if kind != "intent" {
				var err error
				tx, err = s.Begin(testContext, intent("next"))
				if err != nil {
					t.Fatal(err)
				}
				out = writeOutput(t, tx, "image.wim", "validated")
			}
			beforeGeneration := s.state.Generation
			barrierErr := errors.New("published journal flush failed")
			calls := 0
			var published *os.File
			s.flushPublished = func(file *os.File) error {
				calls++
				// Candidate preparation precedes final checkpoint publication. Its
				// real flush must succeed so the latter barrier is the failed one.
				if kind == "checkpoint" && calls == 1 {
					return file.Sync()
				}
				published = file
				actual, err := s.w.OpenFile(journalPath, os.O_RDONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				actualInfo, err := actual.Stat()
				if err != nil {
					actual.Close()
					t.Fatal(err)
				}
				actual.Close()
				fileInfo, err := file.Stat()
				if err != nil {
					t.Fatal(err)
				}
				if !os.SameFile(fileInfo, actualInfo) {
					t.Fatal("barrier did not retain the exact renamed file object")
				}
				var e envelope
				if err := strictDecode([]byte(readOwned(t, s, journalPath)), &e); err != nil {
					t.Fatal(err)
				}
				var current journal
				if err := strictDecode(e.Record, &current); err != nil {
					t.Fatal(err)
				}
				if current.Generation != s.state.Generation || s.state.Generation <= beforeGeneration {
					t.Fatal("published generation was not retained before its failed barrier")
				}
				if kind == "intent" {
					scratch := s.state.Stages[len(s.state.Stages)-1].Scratch
					if f, err := s.w.OpenFile(scratch, os.O_RDONLY, 0); !errors.Is(err, os.ErrNotExist) {
						if f != nil {
							f.Close()
						}
						t.Fatalf("scratch mutated before publication barrier: %v", err)
					}
				}
				return barrierErr
			}
			var err error
			switch kind {
			case "intent":
				tx, err = s.Begin(testContext, intent("next"))
				if tx != nil {
					t.Fatal("Begin granted mutation before journal publication barrier succeeded")
				}
			case "promotion-intent", "checkpoint":
				err = tx.Commit(testContext, []OutputIdentity{out})
			case "discard":
				err = s.Discard(testContext, "job")
			}
			if !errors.Is(err, barrierErr) {
				t.Fatalf("publication barrier failure not returned: %v", err)
			}
			wantCalls := 1
			if kind == "checkpoint" {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("barrier calls: got %d, want %d", calls, wantCalls)
			}
			if published == nil {
				t.Fatal("publication barrier was not invoked")
			}
			// Windows File.Stat can surface the native invalid-handle result
			// rather than wrapping os.ErrClosed after Close has invalidated it.
			if _, err := published.Stat(); !errors.Is(err, os.ErrClosed) && !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
				t.Fatalf("publication failure leaked the writable journal handle: %v", err)
			}
			if readOwned(t, s, base.Outputs[0].Path) != "pristine" {
				t.Fatal("failed publication changed the prior checkpoint")
			}
			if kind == "discard" {
				if _, err := tx.ScratchPath("image.wim"); err == nil {
					t.Fatal("published discard still grants mutation")
				}
			}
			if kind == "promotion-intent" {
				candidate := s.state.Stages[len(s.state.Stages)-1].Candidates[0].Path
				if f, err := s.w.OpenFile(candidate, os.O_RDONLY, 0); !errors.Is(err, os.ErrNotExist) {
					if f != nil {
						f.Close()
					}
					t.Fatal("promotion copied bytes before promotion intent was durable")
				}
			}
			generation := s.state.Generation
			id := s.Identity()
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(id, inspector)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if reopened.state.Generation != generation {
				t.Fatal("reopen lost the actually published old/new journal generation")
			}
			r, err := reopened.InspectRecovery(testContext, "job")
			if err != nil {
				t.Fatal(err)
			}
			wantCheckpoints := 1
			if kind == "checkpoint" {
				wantCheckpoints = 2
			}
			if len(r.Checkpoints) != wantCheckpoints {
				t.Fatalf("recovery checkpoints: got %d, want %d", len(r.Checkpoints), wantCheckpoints)
			}
			for _, cp := range r.Checkpoints {
				if !cp.Valid {
					t.Fatalf("published checkpoint was not independently valid: %s", cp.Reason)
				}
			}
			if kind == "discard" {
				if !r.Discarded || r.CanResume {
					t.Fatal("reopen did not retain published discard")
				}
			} else {
				next, err := reopened.Begin(testContext, intent("retry"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := next.ScratchPath("image.wim"); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestIntentJournalCloseFailurePreservesPublishedGeneration(t *testing.T) {
	s, inspector := newStore(t)
	generation := s.state.Generation
	called := false
	s.flushPublished = func(file *os.File) error {
		called = true
		if err := file.Sync(); err != nil {
			return err
		}
		return file.Close()
	}
	tx, err := s.Begin(testContext, intent("stage"))
	if err == nil || tx != nil {
		t.Fatal("Begin ignored a post-publication journal close failure")
	}
	if !called {
		t.Fatal("real publication flush was not reached")
	}
	if s.state.Generation != generation+1 {
		t.Fatal("post-publication close failure rolled back in-memory generation")
	}
	scratch := s.state.Stages[0].Scratch
	if f, err := s.w.OpenFile(scratch, os.O_RDONLY, 0); !errors.Is(err, os.ErrNotExist) {
		if f != nil {
			f.Close()
		}
		t.Fatal("close failure still allowed scratch creation")
	}
	id := s.Identity()
	s.Close()
	reopened, err := Open(id, inspector)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	r, err := reopened.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	if reopened.state.Generation != generation+1 || len(r.Interrupted) != 1 || len(r.Checkpoints) != 0 {
		t.Fatal("recovery lost the actually published intent after close failure")
	}
}
