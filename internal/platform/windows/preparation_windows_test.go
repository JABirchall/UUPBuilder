package windows

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Dropping nonfollowing ancestor custody, or accepting a reopened descriptor,
// would let another path stand in for the freshly prepared parent.
func TestFreshPreparationParentPinsAncestorsOwnerAndTemp(t *testing.T) {
	base := t.TempDir()
	w, e := CreateWorkspace(base, "fixed-preparation-unit")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	p, e := PinFreshWorkspace(w)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	id := p.Identity()
	if id.Root.FileIndex == 0 || id.Owner.FileIndex == 0 || id.Parent.FileIndex == 0 || id.VolumeID == "" {
		t.Fatalf("incomplete custody: %+v", id)
	}
	if e = p.Check(w.Path()); e != nil {
		t.Fatal(e)
	}
	if e = p.Check(base); e == nil {
		t.Fatal("different process temp parent accepted")
	}
	if e = os.Rename(base, base+"-swapped"); e == nil {
		t.Fatal("held ancestor renamed")
	}
	if e = os.WriteFile(filepath.Join(w.Path(), ownerFile), []byte("{}"), 0600); e == nil {
		t.Fatal("owner marker overwritten")
	}
	f, e := p.CreateEvidenceFile("attempt.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.WriteString("early\n"); e != nil {
		t.Fatal(e)
	}
	if e = f.Sync(); e != nil {
		t.Fatal(e)
	}
	if _, e = p.CreateEvidenceFile("attempt.jsonl"); e == nil {
		t.Fatal("failed evidence overwritten")
	}
	if e = os.WriteFile(filepath.Join(w.Path(), "attempt.jsonl"), []byte("replacement"), 0600); e == nil {
		t.Fatal("held evidence overwritten")
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenWorkspace(w.Identity())
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if adopted, e := PinFreshWorkspace(reopened); e == nil {
		adopted.Close()
		t.Fatal("historical descriptor minted fresh custody")
	}
}

func TestPreparationParentRejectsJunctionAncestor(t *testing.T) {
	base, target := t.TempDir(), t.TempDir()
	link := filepath.Join(base, "junction")
	createJunction(t, link, target)
	w, e := CreateWorkspace(link, "fixed-preparation-unit")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	// The workspace stores its actual physical path; verify the selected path
	// independently, before its lexical spelling is lost by resolution.
	if p, e := PinFreshWorkspace(w); e == nil {
		p.Close()
		t.Fatal("junction ancestor followed")
	}
}

// Dropping deny-write/delete sharing or the final rehash would allow approved
// executable bytes to change between preparation and launch.
func TestPreparationExecutablePinsBytesAndRejectsAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixed.test.exe")
	if e := os.WriteFile(path, []byte("reviewed bytes"), 0600); e != nil {
		t.Fatal(e)
	}
	p, e := OpenPinnedExecutable(context.Background(), path)
	if e != nil {
		t.Fatal(e)
	}
	id := p.Identity()
	if id.Size != 14 || id.SHA256 != "2f70b28379ec7304447e353e98395457080ae10bc139b695de16828b63efc54a" || id.File.FileIndex == 0 {
		t.Fatalf("measurement: %+v", id)
	}
	if e = os.WriteFile(path, []byte("substitute"), 0600); e == nil {
		t.Fatal("pinned executable overwritten")
	}
	if e = os.Rename(path, path+".old"); e == nil {
		t.Fatal("pinned executable renamed")
	}
	if e = p.Verify(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	if e = p.Verify(context.Background()); e == nil {
		t.Fatal("closed pin accepted")
	}
	alias := filepath.Join(filepath.Dir(path), "alias.exe")
	if e = os.Link(path, alias); e != nil {
		t.Fatal(e)
	}
	if pin, e := OpenPinnedExecutable(context.Background(), path); e == nil {
		pin.Close()
		t.Fatal("multiply linked executable accepted")
	}
	if pin, e := OpenPinnedExecutable(context.Background(), strings.TrimSuffix(path, ".exe")); e == nil {
		pin.Close()
		t.Fatal("non-executable path accepted")
	}
}

// A token identity from an earlier process or log must not describe this token.
// This test opens QUERY only, never an adjustment or elevation handle.
func TestPreparationTokenIdentityRequeriesCurrentProcess(t *testing.T) {
	id, e := CurrentProcessTokenIdentity()
	if e != nil {
		t.Fatal(e)
	}
	if id.TokenID == 0 || id.AuthenticationID == 0 || id.UserSID == "" {
		t.Fatalf("missing facts: %+v", id)
	}
	if e = CheckProcessTokenIdentity(id); e != nil {
		t.Fatal(e)
	}
	id.TokenID++
	if e = CheckProcessTokenIdentity(id); e == nil {
		t.Fatal("different token identity accepted")
	}
}

func TestFixedProbeBootstrapHasOnlyFixedTestDispatch(t *testing.T) {
	self, e := CurrentPeerIdentity()
	if e != nil {
		t.Fatal(e)
	}
	b := FixedPreservationBootstrap{Version: 1, PipeName: `\\.\pipe\uupbuilder-0123456789abcdef0123456789abcdef`, Parent: self, Executable: ExecutableIdentity{Path: self.Executable, SHA256: strings.Repeat("a", 64), Size: 14, File: FileIdentity{1, 2}}}
	args, e := fixedPreservationArguments(b)
	if e != nil {
		t.Fatal(e)
	}
	if len(args) != 5 || args[0] != "-test.run=^TestConfiguredFixedSelectedSourceApply$" || args[1] != "-test.count=1" || args[2] != "-test.v=true" || args[3] != "-test.timeout=0" {
		t.Fatalf("not exact fixed dispatch: %q", args)
	}
	parsed, e := ParseFixedPreservationBootstrap(strings.TrimPrefix(args[4], "-fixed-selected-bootstrap="))
	if e != nil || parsed != b {
		t.Fatalf("round trip %+v %v", parsed, e)
	}
	b.Executable.Path = `C:\Windows\System32\cmd.exe`
	if _, e = fixedPreservationArguments(b); e == nil {
		t.Fatal("different executable accepted")
	}
	b.Executable.Path = `\\?\` + self.Executable
	if _, e = fixedPreservationArguments(b); e != nil {
		t.Fatal("native final-path spelling rejected", e)
	}
	if _, e = ParseFixedPreservationBootstrap(strings.Repeat("a", 17000)); e == nil {
		t.Fatal("unbounded bootstrap accepted")
	}
}

func TestPreparationPeerParentRechecksHeldNativeIdentities(t *testing.T) {
	w, e := CreateWorkspace(t.TempDir(), "fixed-parent-unit")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	p, e := PinFreshWorkspace(w)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	id := p.Identity()
	borrow, e := OpenPreparationParent(id)
	if e != nil {
		t.Fatal(e)
	}
	if e = borrow.Check(w.Path()); e != nil {
		t.Fatal(e)
	}
	if e = borrow.Close(); e != nil {
		t.Fatal(e)
	}
	id.Root.FileIndex++
	if borrowed, e := OpenPreparationParent(id); e == nil {
		borrowed.Close()
		t.Fatal("changed root accepted")
	}
}
