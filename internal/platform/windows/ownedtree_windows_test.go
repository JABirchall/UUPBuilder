package windows

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedTreeRejectsUnknownAndOutsideLinksBeforeCleanup(t *testing.T) {
	ctx := context.Background()
	w, e := CreateWorkspace(t.TempDir(), "fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	if failed, e := w.CreateOwnedTree("no-budget", "operation", "proof", TreeLimits{MaxResultBytes: 1}); failed != nil || !errors.Is(e, ErrTreeLimit) {
		if failed != nil {
			failed.Close()
		}
		t.Fatal("constructor allocated outside result budget", e)
	}
	tree, e := w.CreateOwnedTree("fresh", "operation", "proof", TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer tree.Close()
	if e = tree.CreateFile(ctx, "same", []byte("same bytes")); e != nil {
		t.Fatal(e)
	}
	if e = tree.CreateFile(ctx, "separate", []byte("same bytes")); e != nil {
		t.Fatal(e)
	}
	if e = tree.CreateDirectory(ctx, "directory"); e != nil {
		t.Fatal(e)
	}
	a, e := tree.Observe(ctx, "same", MetadataLimits{})
	if e != nil {
		t.Fatal(e)
	}
	b, e := tree.Observe(ctx, "separate", MetadataLimits{})
	if e != nil || a.Identity == b.Identity {
		t.Fatal("identical bytes confused with hardlinks", a, b, e)
	}
	if e = os.WriteFile(filepath.Join(w.Path(), "fresh", "foreign"), []byte("foreign"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = tree.Cleanup(ctx); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("foreign descendant deleted", e)
	}
	if _, e = os.Stat(filepath.Join(w.Path(), "fresh", "same")); e != nil {
		t.Fatal("cleanup mutated before complete proof", e)
	}
	if e = os.Remove(filepath.Join(w.Path(), "fresh", "foreign")); e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if e = os.Link(filepath.Join(w.Path(), "fresh", "same"), outside); e != nil {
		t.Fatal(e)
	}
	if e = tree.Cleanup(ctx); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("linked-outside cleanup", e)
	}
	if e = os.Remove(outside); e != nil {
		t.Fatal(e)
	}
	foreignADS, e := nativeTreeOpenShared(windows.Handle(tree.root.Fd()), "same:foreign:$DATA", windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE, windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer foreignADS.Close()
	if e = tree.Cleanup(ctx); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("unknown ADS deleted", e)
	}
	if e = deleteHeld(foreignADS); e != nil {
		t.Fatal(e)
	}
	if e = foreignADS.Close(); e != nil {
		t.Fatal(e)
	}
	if e = tree.Cleanup(ctx); e != nil {
		t.Fatal(e)
	}
	if e = tree.RemoveEmpty(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestOwnedTreeBoundsPathsAndCancellation(t *testing.T) {
	ctx := context.Background()
	w, e := CreateWorkspace(t.TempDir(), "fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	tree, e := w.CreateOwnedTree("fresh", "operation", "proof", TreeLimits{MaxEntries: 1, MaxLogicalBytes: 3})
	if e != nil {
		t.Fatal(e)
	}
	defer tree.Close()
	for _, p := range []string{"../escape", "a:b", "dir/../../escape"} {
		if e = tree.CreateFile(ctx, p, []byte("a")); e == nil {
			t.Fatal("unsafe name", p)
		}
	}
	if e = tree.CreateFile(ctx, "too-large", []byte("1234")); !errors.Is(e, ErrTreeLimit) {
		t.Fatal(e)
	}
	if e = tree.CreateFile(ctx, "one", []byte("123")); e != nil {
		t.Fatal(e)
	}
	if e = tree.CreateDirectory(ctx, "two"); !errors.Is(e, ErrTreeLimit) {
		t.Fatal(e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if e = tree.Cleanup(canceled); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e = tree.Cleanup(ctx); e != nil {
		t.Fatal(e)
	}
	if e = tree.RemoveEmpty(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestOwnedTreeConstructorRejectsReparseAncestorsAndExistingDirectory(t *testing.T) {
	w, e := CreateWorkspace(t.TempDir(), "fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	if e = w.MkdirAll("target"); e != nil {
		t.Fatal(e)
	}
	root, e := w.root.Open(".")
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	f, e := nativeTreeOpen(windows.Handle(root.Fd()), "junction", windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	setFixtureJunction(t, f, filepath.Join(w.Path(), "target"))
	defer deleteFixtureJunction(t, f)
	if tree, e := w.CreateOwnedTree("junction/forbidden", "op", "source", TreeLimits{}); tree != nil || e == nil {
		if tree != nil {
			tree.Close()
		}
		t.Fatal("constructor followed reparse ancestor", e)
	}
	if tree, e := w.CreateOwnedTree("target", "op", "source", TreeLimits{}); tree != nil || e == nil {
		t.Fatal("adopted existing directory", e)
	}
}

func TestOwnedTreeFinalReopenRejectsReplacementAndMissingRoot(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		w, e := CreateWorkspace(t.TempDir(), "fixture")
		if e != nil {
			t.Fatal(e)
		}
		tree, e := w.CreateOwnedTree("fresh", "op", "source", TreeLimits{})
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(w.Path(), "fresh")
		moved := path + "-moved"
		tree.reopenRemoval = func(parent windows.Handle, leaf string, dir bool) (*os.File, error) {
			if e := os.Rename(path, moved); e != nil {
				t.Fatal(e)
			}
			if replacement {
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			}
			return nativeTreeOpen(parent, leaf, windows.DELETE|windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
		}
		if e = tree.RemoveEmpty(context.Background()); !errors.Is(e, ErrTreePreserved) {
			t.Fatal("changed root deleted", replacement, e)
		}
		if replacement {
			if _, e = os.Stat(path); e != nil {
				t.Fatal("foreign replacement removed", e)
			}
			if e = os.Remove(path); e != nil {
				t.Fatal(e)
			}
		}
		if e = os.Remove(moved); e != nil {
			t.Fatal(e)
		}
		if e = tree.Close(); !errors.Is(e, ErrTreePreserved) {
			t.Fatal("partial custody error not latched", e)
		}
		w.Close()
	}
}

func TestOwnedTreeCloseLatchesAcquiredHandleFailures(t *testing.T) {
	w, e := CreateWorkspace(t.TempDir(), "fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	tree, e := w.CreateOwnedTree("fresh", "op", "source", TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	if e = tree.CreateFile(context.Background(), "file", []byte("owned")); e != nil {
		t.Fatal(e)
	}
	if e = tree.entries["file"].file.Close(); e != nil {
		t.Fatal(e)
	}
	e = tree.Close()
	if !errors.Is(e, os.ErrClosed) || !errors.Is(e, ErrTreePreserved) {
		t.Fatal("close failure lost", e)
	}
	if next := tree.Close(); next != e {
		t.Fatal("close error not latched", next, e)
	}
}

func TestOwnedTreeRefusesChangedWorkspaceOwnerBeforeDescendantMutation(t *testing.T) {
	w, e := CreateWorkspace(t.TempDir(), "fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	tree, e := w.CreateOwnedTree("fresh", "op", "source", TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer tree.Close()
	path := filepath.Join(w.Path(), ownerFile)
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte(`{"Path":"foreign"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e = tree.CreateFile(context.Background(), "forbidden", []byte("bytes")); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("foreign owner marker allowed mutation", e)
	}
	if e = os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	if e = tree.Cleanup(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = tree.RemoveEmpty(context.Background()); e != nil {
		t.Fatal(e)
	}
}
