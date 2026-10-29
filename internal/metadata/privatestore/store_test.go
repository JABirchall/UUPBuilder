package privatestore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedStoreBoundsReadOnlyCustodyAndRevocation(t *testing.T) {
	s, e := New(Profile{MaxFiles: 1, MaxBytes: 2}, "content-test")
	if e != nil {
		t.Fatal(e)
	}
	f, name, e := s.Create(2)
	if e != nil {
		t.Fatal(e)
	}
	f.Write([]byte("xy"))
	f.Close()
	if _, _, e = s.Create(1); !errors.Is(e, ErrLimit) {
		t.Fatal("partial/current file not charged", e)
	}
	a, e := s.Retain(name, 2)
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 3)
	if n, e := a.ReadAt(b, 0); n != 2 || !errors.Is(e, io.EOF) {
		t.Fatal(n, e)
	}
	if e = s.Verify(context.Background()); e != nil {
		t.Fatal(e)
	}
	path := s.Path()
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("scope retained", e)
	}
	if _, e = a.ReadAt(b, 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("borrower survived owner", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestPublicationCustodyBlocksOrRejectsRenamedPrivateScope(t *testing.T) {
	s, e := New(Profile{MaxFiles: 1, MaxBytes: 2}, "content-scope-test")
	if e != nil {
		t.Fatal(e)
	}
	original := s.Path()
	moved := original + "-moved"
	if e = os.Rename(original, moved); e != nil {
		if e = s.Verify(context.Background()); e != nil {
			t.Fatal(e)
		}
		if e = s.Close(); e != nil {
			t.Fatal(e)
		}
		return
	}
	defer func() {
		s.Close()
		os.Remove(filepath.Join(moved, ".uupbuilder-owner.json"))
		os.Remove(moved)
		os.Remove(original)
	}()
	if e = os.Mkdir(original, 0700); e != nil {
		t.Fatal(e)
	}
	if e = s.Verify(context.Background()); !errors.Is(e, ErrIntegrity) {
		t.Fatal("scope path identity was not checked before publication", e)
	}
}
func TestPrivatePartialBatchCleanupAndLatchedUnknownEntry(t *testing.T) {
	s, e := New(Profile{MaxFiles: 2, MaxBytes: 10}, "content-cleanup-test")
	if e != nil {
		t.Fatal(e)
	}
	f, _, e := s.Create(8)
	if e != nil {
		t.Fatal(e)
	}
	f.Write([]byte("part"))
	f.Close()
	path := s.Path()
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("partial owned data leaked", e)
	}
	s, e = New(Profile{MaxFiles: 2, MaxBytes: 10}, "content-cleanup-test")
	if e != nil {
		t.Fatal(e)
	}
	path = s.Path()
	f, e = os.OpenFile(filepath.Join(path, "unexpected"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	first := s.Close()
	if !errors.Is(first, ErrIntegrity) || !errors.Is(s.Close(), ErrIntegrity) {
		t.Fatal("cleanup failure not latched", first)
	}
	for _, name := range []string{"unexpected", ".uupbuilder-owner.json"} {
		if e = os.Remove(filepath.Join(path, name)); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
}
