//go:build windows

package jobstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryMountAtVolumeRootIsNotUnrelated(t *testing.T) {
	s, inspector := newStore(t)
	base := commitStage(t, s, intent("base"), "pristine")
	inspector.snapshot.Mounts = []MountObservation{{Path: filepath.VolumeName(s.Identity().Path) + string(filepath.Separator), State: MountMounted}}
	r, err := s.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	if r.CanResume || len(r.Preserved) == 0 {
		t.Fatal("mount covering the workspace volume root was ignored")
	}
	if err := s.Discard(testContext, "job"); err == nil {
		t.Fatal("discard ignored ancestor volume mount")
	}
	if readOwned(t, s, base.Outputs[0].Path) != "pristine" {
		t.Fatal("ancestor mount discard modified checkpoint")
	}
}

func TestRecoveryMountClaimIsNotMountedStateAndRejectsSubstitution(t *testing.T) {
	s, inspector := newStore(t)
	tx, err := s.Begin(testContext, intent("stage"))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := tx.ClaimMount("mount")
	if err != nil {
		t.Fatal(err)
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
	if !r.CanResume {
		t.Fatalf("valid empty claim blocked by complete independent inventory: %#v", r)
	}
	inspector.err = os.ErrPermission
	r, err = reopened.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	if r.CanResume || len(r.Preserved) == 0 {
		t.Fatal("ownership claim substituted for unavailable OS evidence")
	}
	inspector.err = nil
	path := filepath.Join(id.Path, filepath.FromSlash(claim.RelativePath))
	if err := os.Rename(path, path+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	r, err = reopened.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	if r.CanResume || len(r.Preserved) == 0 {
		t.Fatal("substituted native directory identity accepted")
	}
	if err := reopened.Discard(testContext, "job"); err == nil {
		t.Fatal("substituted mount directory removed")
	}
}

func TestIntentMountClaimsCannotOverlap(t *testing.T) {
	for _, kind := range []struct{ first, next string }{{"mount", "MOUNT"}, {"mount", "mount/nested"}, {"mount/nested", "mount"}} {
		t.Run(kind.first+"-"+kind.next, func(t *testing.T) {
			s, _ := newStore(t)
			tx, err := s.Begin(testContext, intent("stage"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.ClaimMount(kind.first); err != nil {
				t.Fatal(err)
			}
			before := readOwned(t, s, journalPath)
			if _, err := tx.ClaimMount(kind.next); err == nil {
				t.Fatal("overlapping mount claim accepted")
			}
			if readOwned(t, s, journalPath) != before {
				t.Fatal("invalid overlapping mount claim changed durable intent")
			}
		})
	}
}
