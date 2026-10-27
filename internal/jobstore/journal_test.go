//go:build windows

package jobstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
