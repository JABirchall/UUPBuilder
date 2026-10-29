package windows

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	native "golang.org/x/sys/windows"
)

// A reader that consents to deletion can keep legacy delete disposition
// pending. Closing cleanup's own marker handle does not confirm unlinking.
func TestWorkspaceCleanupReportsPendingMarkerDeletionWithSharedReader(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "shared-marker-preflight")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	root, err := w.root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	rootInfo, err := nativeInfo(root)
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	reader, err := nativeTreeOpenShared(native.Handle(root.Fd()), ownerFile, native.FILE_GENERIC_READ, native.FILE_OPEN, native.FILE_NON_DIRECTORY_FILE, native.FILE_SHARE_READ|native.FILE_SHARE_DELETE, nil)
	closeErr := root.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	ownerInfo, err := nativeInfo(reader)
	if err != nil {
		t.Fatal(err)
	}
	err = w.RemoveEmpty()
	if !errors.Is(err, native.ERROR_DIR_NOT_EMPTY) {
		t.Fatalf("pending marker deletion lost actual native refusal: %v", err)
	}
	if _, statErr := os.Stat(w.Path()); statErr != nil {
		t.Fatalf("refused directory was not preserved: %v", statErr)
	}
	if strings.Contains(err.Error(), "marker-removed=true") {
		t.Fatalf("pending legacy disposition was reported as confirmed marker removal: %v", err)
	}
	rootID := uint64(rootInfo.FileIndexHigh)<<32 | uint64(rootInfo.FileIndexLow)
	ownerID := uint64(ownerInfo.FileIndexHigh)<<32 | uint64(ownerInfo.FileIndexLow)
	for _, fact := range []string{
		w.Path(),
		fmt.Sprintf("volume=%d file=%d owner-file=%d", rootInfo.VolumeSerialNumber, rootID, ownerID),
		"marker-deletion-requested=true",
		"marker-local-handle-closed=true",
		"marker-removal=unconfirmed",
		"root-deletion-requested=false",
	} {
		if !strings.Contains(err.Error(), fact) {
			t.Fatalf("cleanup diagnostic lost %q: %v", fact, err)
		}
	}
	var marker [1]byte
	if n, readErr := reader.ReadAt(marker[:], 0); n != 1 || readErr != nil {
		t.Fatalf("cleanup affected the independently owned reader: %d %v", n, readErr)
	}
}

// This rejects deleting a reopened, replaced, nonempty or stream-bearing root,
// and proves successful deletion rather than merely releasing its handles.
func TestFreshWorkspaceEmptyCleanupKeepsExactCustody(t *testing.T) {
	for _, name := range []string{"empty", "unknown-entry", "root-stream", "owner-stream", "owner-delete-denied", "replacement", "owner-replacement", "reopened"} {
		t.Run(name, func(t *testing.T) {
			w, err := CreateWorkspace(t.TempDir(), "read-only-preflight")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			id := w.Identity()
			cleanup, ok := any(w).(interface{ RemoveEmpty() error })
			if !ok {
				t.Fatal("fresh workspace cannot remove its exactly owned empty root")
			}
			var locked *os.File
			switch name {
			case "unknown-entry":
				err = os.WriteFile(filepath.Join(id.Path, "foreign"), []byte("retain"), 0600)
			case "root-stream":
				err = os.WriteFile(id.Path+":foreign", []byte("retain"), 0600)
			case "owner-stream":
				err = os.WriteFile(filepath.Join(id.Path, ownerFile)+":foreign", []byte("retain"), 0600)
			case "owner-delete-denied":
				root, e := w.root.Open(".")
				if e != nil {
					t.Fatal(e)
				}
				locked, err = nativeTreeOpenShared(native.Handle(root.Fd()), ownerFile, native.FILE_GENERIC_READ, native.FILE_OPEN, native.FILE_NON_DIRECTORY_FILE, native.FILE_SHARE_READ, nil)
				if e = root.Close(); e != nil {
					t.Fatal(e)
				}
				if locked != nil {
					defer locked.Close()
				}
			case "replacement":
				body, e := os.ReadFile(filepath.Join(id.Path, ownerFile))
				if e != nil {
					t.Fatal(e)
				}
				err = os.Rename(id.Path, id.Path+"-original")
				if err == nil {
					err = os.Mkdir(id.Path, 0700)
				}
				if err == nil {
					err = os.WriteFile(filepath.Join(id.Path, ownerFile), body, 0600)
				}
			case "owner-replacement":
				body, e := os.ReadFile(filepath.Join(id.Path, ownerFile))
				if e != nil {
					t.Fatal(e)
				}
				err = os.Rename(filepath.Join(id.Path, ownerFile), filepath.Join(id.Path, "original-owner"))
				if err == nil {
					err = os.WriteFile(filepath.Join(id.Path, ownerFile), body, 0600)
				}
				if err == nil {
					err = os.Remove(filepath.Join(id.Path, "original-owner"))
				}
			case "reopened":
				if err = w.Close(); err != nil {
					t.Fatal(err)
				}
				w, err = OpenWorkspace(id)
				if err == nil {
					defer w.Close()
					cleanup = any(w).(interface{ RemoveEmpty() error })
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			err = cleanup.RemoveEmpty()
			if name == "empty" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(id.Path); !os.IsNotExist(err) {
					t.Fatalf("empty root retained: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "preserved") {
					t.Fatalf("unsafe cleanup: %v", err)
				}
				if _, e := os.Stat(filepath.Join(id.Path, ownerFile)); e != nil {
					t.Fatalf("refusal lost ownership marker: %v", e)
				}
			}
		})
	}
}

func TestWorkspacePartialConstructorRetainsScopeAndClosesEveryHandle(t *testing.T) {
	parent := t.TempDir()
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}
	token, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	// Native creation still uses a valid held parent, while opening the owned
	// root fails. This exercises the real post-creation constructor failure.
	w, err := createWorkspace(root, handle, parent, "partial-preflight", token)
	if w == nil || err == nil || !strings.Contains(err.Error(), "preserved at "+w.Path()) {
		t.Fatalf("fresh scope lost: %v %v", w, err)
	}
	if w.fresh.rootID.FileIndex == 0 {
		t.Fatal("original native identity lost")
	}
	if _, err := os.Stat(w.Path()); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeInfo(handle); err == nil {
		t.Fatal("constructor leaked parent handle")
	}
	if err := w.RemoveEmpty(); err == nil || !strings.Contains(err.Error(), "initialization incomplete") {
		t.Fatalf("partial initialization granted removal: %v", err)
	}
}

func TestWorkspaceCloseLatchesFailureAndAttemptsOtherHandles(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "close-preflight")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.fresh.parent.Close(); err != nil {
		t.Fatal(err)
	}
	first := w.Close()
	if first == nil {
		t.Fatal("close ignored owned handle failure")
	}
	if again := w.Close(); again == nil || again.Error() != first.Error() {
		t.Fatalf("close failure not retained: %v", again)
	}
	if _, err := w.root.Open("."); err == nil {
		t.Fatal("close skipped workspace root after failure")
	}
}
