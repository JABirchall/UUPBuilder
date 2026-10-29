package windows

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The review's retained overlay injected a rename in Err() call 5: the first
// cancellation boundary after a one-directory complete topology proof. Keep
// that proof-to-action regression permanent; these are fresh test files only.
type cleanupBoundaryContext struct {
	context.Context
	calls  int
	action func()
}

func (c *cleanupBoundaryContext) Err() error {
	c.calls++
	if c.calls == 5 {
		c.action()
	}
	return nil
}

func TestOwnedTreeCleanupPinsNamesAfterTopologyProof(t *testing.T) {
	for _, kind := range []string{"ordinary", "hardlink-primary", "hardlink-alias", "named-stream"} {
		t.Run(kind, func(t *testing.T) {
			w, e := CreateWorkspace(t.TempDir(), "fixture")
			if e != nil {
				t.Fatal(e)
			}
			defer w.Close()
			tree, e := w.CreateOwnedTree("fresh", "op", "proof", TreeLimits{})
			if e != nil {
				t.Fatal(e)
			}
			defer tree.Close()
			if e = tree.CreateFile(context.Background(), "owned", []byte("fixture bytes")); e != nil {
				t.Fatal(e)
			}
			if strings.HasPrefix(kind, "hardlink") {
				if e = tree.CreateHardlink(context.Background(), "owned", "alias"); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "named-stream" {
				if e = tree.CreateNamedStream(context.Background(), "owned", "ads", []byte("named bytes")); e != nil {
					t.Fatal(e)
				}
			}
			name := "owned"
			if kind == "hardlink-alias" {
				name = "alias"
			}
			original := filepath.Join(w.Path(), "fresh", name)
			outside := filepath.Join(w.Path(), "outside-owned-tree")
			attempted := false
			var renameErr error
			ctx := &cleanupBoundaryContext{Context: context.Background(), action: func() { attempted = true; renameErr = os.Rename(original, outside) }}
			e = tree.Cleanup(ctx)
			if !attempted {
				t.Fatal("post-proof cancellation boundary not reached", ctx.calls, e)
			}
			if !errors.Is(e, ErrTreePreserved) {
				t.Fatalf("file-containing cleanup must preserve exact custody: %v; rename=%v", e, renameErr)
			}
			id := tree.Identity()
			if !strings.Contains(e.Error(), id.RelativePath) || !strings.Contains(e.Error(), fmt.Sprintf("file=%d", id.Root.FileIndex)) {
				t.Fatal("preserved scope path/native ID missing", e, id.Root)
			}
			if renameErr == nil {
				if _, e = os.Stat(outside); e != nil {
					t.Fatal("escaped file deleted", e)
				}
			} else {
				if !errors.Is(renameErr, windows.ERROR_SHARING_VIOLATION) && !errors.Is(renameErr, windows.ERROR_ACCESS_DENIED) {
					t.Fatal("unexpected rename refusal", renameErr)
				}
				if _, e = os.Stat(original); e != nil {
					t.Fatal("pinned original missing", e)
				}
			}
			t.Logf("post-proof rename=%v; Cleanup preserved; Err calls=%d", renameErr, ctx.calls)
			var held []*os.File
			for _, entry := range tree.entries {
				held = append(held, entry.file)
				held = append(held, entry.streamFiles...)
			}
			for _, file := range held {
				if _, e = file.ReadAt(make([]byte, 1), 0); e != nil {
					t.Fatal("preserved handle lost before Close", e)
				}
			}
			closeErr := tree.Close()
			if !errors.Is(closeErr, ErrTreePreserved) {
				t.Fatal("preserved Close falsely clean", closeErr)
			}
			if tree.Close() != closeErr {
				t.Fatal("preserved Close error not latched")
			}
			for _, file := range held {
				if _, e = file.ReadAt(make([]byte, 1), 0); !errors.Is(e, os.ErrClosed) {
					t.Fatal("Close retained native handle", e)
				}
			}
			retainedPath := original
			if renameErr == nil {
				retainedPath = outside
			}
			if _, e = os.Stat(retainedPath); e != nil {
				t.Fatal("Close deleted preserved file", e)
			}
		})
	}
}

func TestOwnedTreeCleanupRejectsActualFileAndStreamGrowth(t *testing.T) {
	for _, ads := range []bool{false, true} {
		t.Run(fmt.Sprintf("ADS=%t", ads), func(t *testing.T) {
			w, e := CreateWorkspace(t.TempDir(), "fixture")
			if e != nil {
				t.Fatal(e)
			}
			defer w.Close()
			tree, e := w.CreateOwnedTree("fresh", "op", "proof", TreeLimits{MaxLogicalBytes: 3})
			if e != nil {
				t.Fatal(e)
			}
			defer tree.Close()
			if e = tree.CreateFile(context.Background(), "owned", []byte("x")); e != nil {
				t.Fatal(e)
			}
			leaf := "owned"
			if ads {
				if e = tree.CreateNamedStream(context.Background(), "owned", "ads", []byte("y")); e != nil {
					t.Fatal(e)
				}
				leaf += ":ads:$DATA"
			}
			writer, openErr := nativeTreeOpenShared(windows.Handle(tree.root.Fd()), leaf, windows.FILE_GENERIC_WRITE, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil)
			if openErr == nil {
				if _, e = writer.WriteAt([]byte("1234"), 0); e != nil {
					writer.Close()
					t.Fatal(e)
				}
				if e = writer.Close(); e != nil {
					t.Fatal(e)
				}
			} else if !errors.Is(openErr, windows.ERROR_SHARING_VIOLATION) {
				t.Fatal("unexpected write refusal", openErr)
			}
			e = tree.Cleanup(context.Background())
			if !errors.Is(e, ErrTreePreserved) {
				t.Fatal("actual over-budget or unstable file deleted", e)
			}
			if openErr == nil && !errors.Is(e, ErrTreeLimit) {
				t.Fatal("actual grown bytes not charged", e)
			}
			if _, e = os.Stat(filepath.Join(w.Path(), "fresh", "owned")); e != nil {
				t.Fatal("file removed", e)
			}
			t.Logf("compatible external growth open=%v; cleanup preserved", openErr)
		})
	}
}

func TestOwnedTreeCleanupChargesActualBytesInsteadOfStaleLedgerTotal(t *testing.T) {
	for _, ads := range []bool{false, true} {
		t.Run(fmt.Sprintf("ADS=%t", ads), func(t *testing.T) {
			w, e := CreateWorkspace(t.TempDir(), "fixture")
			if e != nil {
				t.Fatal(e)
			}
			defer w.Close()
			tree, e := w.CreateOwnedTree("fresh", "op", "proof", TreeLimits{})
			if e != nil {
				t.Fatal(e)
			}
			defer tree.Close()
			data := []byte("1234")
			if ads {
				data = []byte("x")
			}
			if e = tree.CreateFile(context.Background(), "owned", data); e != nil {
				t.Fatal(e)
			}
			if ads {
				if e = tree.CreateNamedStream(context.Background(), "owned", "ads", []byte("1234")); e != nil {
					t.Fatal(e)
				}
			}
			// Test-only already-created native state. Lower the limit and make only
			// the cached total stale; do not weaken the production native pins.
			tree.limits.MaxLogicalBytes = 3
			tree.logical = 1
			e = tree.Cleanup(context.Background())
			if !errors.Is(e, ErrTreePreserved) || !errors.Is(e, ErrTreeLimit) {
				t.Fatal("actual native bytes escaped limit proof", e)
			}
			if _, e = os.Stat(filepath.Join(w.Path(), "fresh", "owned")); e != nil {
				t.Fatal("over-budget file deleted", e)
			}
		})
	}
}

func TestOwnedTreeProofRejectsChangedRecordedLengthsWithinBudget(t *testing.T) {
	for _, ads := range []bool{false, true} {
		t.Run(fmt.Sprintf("ADS=%t", ads), func(t *testing.T) {
			w, e := CreateWorkspace(t.TempDir(), "fixture")
			if e != nil {
				t.Fatal(e)
			}
			defer w.Close()
			tree, e := w.CreateOwnedTree("fresh", "op", "proof", TreeLimits{})
			if e != nil {
				t.Fatal(e)
			}
			defer tree.Close()
			if e = tree.CreateFile(context.Background(), "owned", []byte("12")); e != nil {
				t.Fatal(e)
			}
			if ads {
				if e = tree.CreateNamedStream(context.Background(), "owned", "ads", []byte("34")); e != nil {
					t.Fatal(e)
				}
				tree.entries["owned"].streams["ads"] = 1
			} else {
				tree.entries["owned"].size = 1
			}
			// The actual native lengths and cached total are unchanged and below
			// the bound; this independently exercises the expected-size comparison.
			if e = tree.checkTopology(context.Background()); !errors.Is(e, ErrTreePreserved) {
				t.Fatal("changed recorded size accepted", e)
			}
		})
	}
}

func TestOwnedTreeHardlinkLogicalBudgetCountsNamedStreamsPerName(t *testing.T) {
	for _, limit := range []uint64{5, 6} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			w, e := CreateWorkspace(t.TempDir(), "fixture")
			if e != nil {
				t.Fatal(e)
			}
			defer w.Close()
			tree, e := w.CreateOwnedTree("fresh", "op", "proof", TreeLimits{MaxLogicalBytes: limit})
			if e != nil {
				t.Fatal(e)
			}
			defer tree.Close()
			if e = tree.CreateFile(context.Background(), "owned", []byte("x")); e != nil {
				t.Fatal(e)
			}
			if e = tree.CreateNamedStream(context.Background(), "owned", "ads", []byte("yz")); e != nil {
				t.Fatal(e)
			}
			e = tree.CreateHardlink(context.Background(), "owned", "alias")
			if limit == 5 {
				if !errors.Is(e, ErrTreeLimit) {
					t.Fatal("alias ADS bytes not reserved", e)
				}
				if _, e = os.Stat(filepath.Join(w.Path(), "fresh", "alias")); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("over-budget alias created", e)
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				if e = tree.checkTopology(context.Background()); e != nil {
					t.Fatal("exact six logical bytes refused", e)
				}
			}
		})
	}
}

func TestOwnedTreeDirectoryOnlyCleanupHoldsRemovalPinThroughDisposition(t *testing.T) {
	w, e := CreateWorkspace(t.TempDir(), "fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	tree, e := w.CreateOwnedTree("fresh", "op", "proof", TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer tree.Close()
	if e = tree.CreateDirectory(context.Background(), "directory"); e != nil {
		t.Fatal(e)
	}
	attempted := false
	var renameErr error
	var inject func(windows.Handle, string, bool) (*os.File, error)
	inject = func(parent windows.Handle, leaf string, dir bool) (*os.File, error) {
		tree.reopenRemoval = nil
		f, e := tree.openRemoval(parent, leaf, dir)
		tree.reopenRemoval = inject
		if e == nil && leaf == "directory" {
			attempted = true
			renameErr = os.Rename(filepath.Join(w.Path(), "fresh", "directory"), filepath.Join(w.Path(), "outside-directory"))
		}
		return f, e
	}
	tree.reopenRemoval = inject
	if e = tree.Cleanup(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !attempted || renameErr == nil {
		t.Fatal("removal did not hold namespace pin", attempted, renameErr)
	}
	if !errors.Is(renameErr, windows.ERROR_SHARING_VIOLATION) && !errors.Is(renameErr, windows.ERROR_ACCESS_DENIED) {
		t.Fatal(renameErr)
	}
	if e = tree.RemoveEmpty(context.Background()); e != nil {
		t.Fatal(e)
	}
}

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
	foreignADS, e := nativeTreeOpenShared(windows.Handle(tree.root.Fd()), "same:foreign:$DATA", windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE, windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer foreignADS.Close()
	if e = tree.Cleanup(ctx); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("unknown ADS deleted", e)
	}
	if e = foreignADS.Close(); e != nil {
		t.Fatal(e)
	}
	// TempDir's test-only teardown runs after preserved handles close. Production
	// cleanup never deletes this unrecorded stream or claims successful release.
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
	if e = tree.Cleanup(ctx); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("file cleanup falsely complete", e)
	}
	if e = tree.RemoveEmpty(ctx); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("nonempty scope falsely released", e)
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
