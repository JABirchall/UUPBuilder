package jobstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnmountPersistsReplacementClaimAndKeepsNativeInventoryGate(t *testing.T) {
	for _, mounted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unmounted", true: "still-mounted"}[mounted], func(t *testing.T) {
			s, inspector := newStore(t)
			tx, err := s.Begin(testContext, intent("service-image"))
			if err != nil {
				t.Fatal(err)
			}
			mount, err := tx.ClaimMount("mount")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.Identity().Path, filepath.FromSlash(mount.RelativePath))
			output := writeOutput(t, tx, "image.wim", "serviced image")
			if err := tx.Unmount(testContext, mount, func() error {
				if err := os.Rename(path, path+"-old"); err != nil {
					return err
				}
				if err := os.Mkdir(path, 0700); err != nil {
					return err
				}
				return os.Remove(path + "-old")
			}); err != nil {
				t.Fatal(err)
			}
			if mounted {
				inspector.snapshot.Mounts = []MountObservation{{Path: path, State: MountMounted}}
			}
			err = tx.Commit(testContext, []OutputIdentity{output})
			if mounted {
				if err == nil || !strings.Contains(err.Error(), "actual OS mounted image") || !strings.Contains(err.Error(), path) {
					t.Fatalf("native resource gate or diagnostic lost: %v", err)
				}
				if err := s.Discard(testContext, "job"); err == nil {
					t.Fatal("still-mounted directory authorized discard")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			id := s.Identity()
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(id, inspector)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			claims, err := reopened.OwnedMounts(testContext, "job")
			if err != nil || len(claims) != 1 || claims[0].DirectoryID == mount.DirectoryID {
				t.Fatalf("replacement claim was not durably recorded: %+v, %v", claims, err)
			}
			r, err := reopened.InspectRecovery(testContext, "job")
			if err != nil || !r.CanResume || len(r.Checkpoints) != 1 || !r.Checkpoints[0].Valid {
				t.Fatalf("serviced checkpoint unusable after reopen: %+v, %v", r, err)
			}
			if err := reopened.Discard(testContext, "job"); err != nil {
				t.Fatalf("completed unmount blocked safe cleanup: %v", err)
			}
		})
	}
}
