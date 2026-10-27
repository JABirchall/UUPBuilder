//go:build windows

package jobstore

import (
	"errors"
	"os"
	"testing"
)

func TestRecoveryUnrecordedMountCapabilityPreservesDirectory(t *testing.T) {
	s, inspector := newStore(t)
	tx, err := s.Begin(testContext, intent("stage"))
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	s.fail = func(point string) error {
		if point == "journal-before-write" {
			writes++
		}
		if writes == 2 && point == "journal-before-replace" {
			return errors.New("interrupted ownership record")
		}
		return nil
	}
	if claim, err := tx.ClaimMount("mount"); err == nil || claim.RelativePath != "" {
		t.Fatal("exposed mount capability before durable ownership record")
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
	if r.CanResume || len(r.Preserved) == 0 {
		t.Fatal("unrecorded mount directory claim inferred from journal intent")
	}
	if err := reopened.Discard(testContext, "job"); err == nil {
		t.Fatal("unresolved mount directory removed")
	}
}

func TestIntentTransactionPermissionEndsAtCommitOrClose(t *testing.T) {
	s, _ := newStore(t)
	in := intent("stage")
	tx, err := s.Begin(testContext, in)
	if err != nil {
		t.Fatal(err)
	}
	in.Tools[0].Digest = digest("caller changed input")
	out := writeOutput(t, tx, "image.wim", "complete")
	if err := tx.Commit(testContext, []OutputIdentity{out}); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.OpenFile("image.wim", os.O_WRONLY, 0600); err == nil {
		t.Fatal("committed transaction still grants mutable handles")
	}
	if _, err := tx.ScratchPath("image.wim"); err == nil {
		t.Fatal("committed transaction grants new provider paths")
	}
	r, err := s.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	if r.Checkpoints[0].Checkpoint.Intent.Tools[0].Digest != digest("tool") {
		t.Fatal("caller slice mutation changed durable intent")
	}
	tx, err = s.Begin(testContext, intent("next"))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := tx.ScratchPath("image.wim"); err == nil {
		t.Fatal("closed workspace grants provider path")
	}
}

func TestDiscardPublishedIntentRevokesPermissionOnReturnedError(t *testing.T) {
	s, _ := newStore(t)
	tx, err := s.Begin(testContext, intent("stage"))
	if err != nil {
		t.Fatal(err)
	}
	writeOutput(t, tx, "image.wim", "preserve before cleanup")
	s.fail = func(point string) error {
		if point == "journal-after-replace" {
			return errors.New("interrupted after discard publication")
		}
		return nil
	}
	if err := s.Discard(testContext, "job"); err == nil {
		t.Fatal("discard interruption ignored")
	}
	if _, err := tx.ScratchPath("image.wim"); err == nil {
		t.Fatal("durably discarded transaction still grants provider mutation paths")
	}
	if f, err := tx.OpenFile("image.wim", os.O_WRONLY, 0600); err == nil {
		f.Close()
		t.Fatal("durably discarded transaction still grants mutable handles")
	}
	s.fail = nil
	r, err := s.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Discarded || r.CanResume {
		t.Fatal("discard publication was not authoritative")
	}
	if err := s.Discard(testContext, "job"); err != nil {
		t.Fatal(err)
	}
}
