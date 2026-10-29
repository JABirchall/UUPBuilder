package jobstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedMountsReturnsOnlyDurableIndependentClaims(t *testing.T) {
	s, _ := newStore(t)
	tx, err := s.Begin(testContext, intent("mount-stage"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := tx.ClaimMount("image")
	if err != nil {
		t.Fatal(err)
	}
	second, err := tx.ClaimMount("second-image")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.OwnedMounts(testContext, "job")
	if err != nil || len(got) != 2 || got[0] != m || got[1] != second {
		t.Fatal(got, err)
	}
	got[0].RelativePath = "foreign"
	id := s.Identity()
	s.Close()
	reopened, err := Open(id, &mountInventory{snapshot: MountSnapshot{Complete: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err = reopened.OwnedMounts(testContext, "job")
	if err != nil || len(got) != 2 || got[0] != m || got[1] != second {
		t.Fatal(got, err)
	}
	if _, err = reopened.OwnedMounts(testContext, "foreign"); err == nil {
		t.Fatal("wrong job accepted")
	}
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if _, err = reopened.OwnedMounts(ctx, "job"); err == nil {
		t.Fatal("cancelled context accepted")
	}
	path := filepath.Join(id.Path, filepath.FromSlash(second.RelativePath))
	if err = os.Rename(path, path+"-old"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if got, err = reopened.OwnedMounts(testContext, "job"); err == nil || len(got) != 0 {
		t.Fatal("changed directory adopted", got, err)
	}
	reopened.Close()
	if _, err = reopened.OwnedMounts(testContext, "job"); err == nil {
		t.Fatal("closed store accepted")
	}
}
