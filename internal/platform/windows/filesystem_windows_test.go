package windows

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWorkspaceRejectsEscapingReparsePoint(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	createJunction(t, filepath.Join(w.Path(), "escape"), outside)
	if _, err := w.OpenFile("escape/keep.txt", os.O_WRONLY|os.O_TRUNC, 0600); err == nil {
		t.Fatal("write escaped through junction")
	}
	if err := w.MkdirAll("escape/new"); err == nil {
		t.Fatal("mkdir escaped through junction")
	}
	if err := w.Remove("escape/keep.txt"); err == nil {
		t.Fatal("remove escaped through junction")
	}
	got, _ := os.ReadFile(sentinel)
	if string(got) != "unchanged" {
		t.Fatalf("outside file changed: %q", got)
	}
}

func TestWorkspaceOwnershipAndAtomicReplacement(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	identity := w.Identity()
	if err := w.MkdirAll("stage/日本語"); err != nil {
		t.Fatal(err)
	}
	f, err := w.OpenFile("stage/日本語/new.tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("complete")
	f.Close()
	if err := w.Replace("stage/日本語/new.tmp", "stage/日本語/output.txt", false); err != nil {
		t.Fatal(err)
	}
	f, err = w.OpenFile("stage/日本語/output.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := w.OpenFile("../outside", os.O_CREATE|os.O_WRONLY, 0600); err == nil {
		t.Fatal("accepted traversal")
	}
	w.Close()
	identity.JobID = "another"
	if _, err := OpenWorkspace(identity); err == nil {
		t.Fatal("accepted another job ownership")
	}
	identity.JobID = "job-1"
	w, err = OpenWorkspace(identity)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	m, err := w.ClaimMount("stage/mount", "op-1")
	if err != nil {
		t.Fatal(err)
	}
	if m.JobID != "job-1" || m.OperationID != "op-1" {
		t.Fatalf("mount %#v", m)
	}
	if err := w.ValidateMount(m); err != nil {
		t.Fatal(err)
	}
	m.OperationID = "foreign"
	if err := w.ValidateMount(m); err == nil {
		t.Fatal("accepted foreign mount")
	}
}

func TestMountOwnershipRejectsDirectorySubstitution(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "job")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	m, err := w.ClaimMount("mount", "op")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(w.Path(), "mount"), filepath.Join(w.Path(), "old-mount")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(w.Path(), "mount"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := w.ValidateMount(m); err == nil {
		t.Fatal("accepted a substituted mount directory")
	}
}

func TestWorkspaceRejectsMutationThroughHardLink(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "job")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	outside := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(w.Path(), "linked.txt")); err != nil {
		t.Fatal(err)
	}
	if f, err := w.OpenFile("linked.txt", os.O_WRONLY|os.O_TRUNC, 0600); err == nil {
		f.Close()
		t.Fatal("accepted write through shared hard link")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "unchanged" {
		t.Fatalf("outside hard link changed: %q %v", got, err)
	}
}

func TestWorkspaceUsesProtectedOwnerACL(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "job")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	f, err := w.root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivateDACL(t, sd)
}

func TestMountRecoveryRequiresPersistedDirectoryIdentity(t *testing.T) {
	w, err := CreateWorkspace(t.TempDir(), "job")
	if err != nil {
		t.Fatal(err)
	}
	identity := w.Identity()
	m, err := w.ClaimMount("mount", "op")
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	w, err = OpenWorkspace(identity)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.RestoreMount(m); err != nil {
		t.Fatal(err)
	}
	if err := w.ValidateMount(m); err != nil {
		t.Fatal(err)
	}
	m.DirectoryID.FileIndex++
	if err := w.RestoreMount(m); err == nil {
		t.Fatal("accepted a forged persisted directory identity")
	}
}

func TestAtomicReplaceCollisionPreservesBothFiles(t *testing.T) {
	d := t.TempDir()
	a, b := filepath.Join(d, "new.tmp"), filepath.Join(d, "old.txt")
	os.WriteFile(a, []byte("new"), 0600)
	os.WriteFile(b, []byte("old"), 0600)
	if err := AtomicReplace(a, b, false); err == nil {
		t.Fatal("replaced collision")
	}
	got, _ := os.ReadFile(b)
	if string(got) != "old" {
		t.Fatal("collision changed original")
	}
	got, _ = os.ReadFile(a)
	if string(got) != "new" {
		t.Fatal("collision lost source")
	}
}
