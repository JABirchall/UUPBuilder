package probes

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
	"uupbuilder/internal/jobstore"

	platform "uupbuilder/internal/platform/windows"
)

func controlFixture() (controlRequest, controlFacts) {
	r := controlRequest{Version: 1, Profile: controlProfile, Plan: `C:\p\2026-10-28-uup-builder-remaining-work-plan`, Facts: controlFacts{Build: 19045, Native: "amd64", Process: "amd64", SID: "S-1-5-21-test", Source: controlPin{Size: 4164077935, SHA256: controlSourceSHA, SHA1: controlSourceSHA1}, Tool: controlPin{Size: 289136, SHA256: controlToolSHA, Versions: controlVersionFields{NumericFileVersion: "10.0.19041.3636", DisplayFileVersion: "10.0.19041.1 (WinBuild.160101.0800)", NumericProductVersion: "10.0.19041.3636", DisplayProductVersion: "10.0.19041.1"}, Machine: 0x8664}, Runner: controlPin{Size: 10, SHA256: strings.Repeat("c", 64), Machine: 0x8664}}}
	for i, p := range []*platform.WorkspaceIdentity{&r.Bundle, &r.Store, &r.Provider, &r.Apply} {
		*p = platform.WorkspaceIdentity{Path: r.Plan + `\r3a2b\uupbuilder-` + strings.Repeat(string(rune('a'+i)), 32), JobID: "desktop-control", Token: strings.Repeat(string(rune('a'+i)), 32)}
		r.ScopeIDs[i] = platform.FileIdentity{FileIndex: uint64(i + 1)}
	}
	r.Source = r.Plan + `\native-control\source\desktop-control.esd`
	r.Tool = `C:\Windows\System32\dism.exe`
	r.Runner = r.Bundle.Path + `\runner.exe`
	a := r.Facts
	a.Elevated = true
	a.Free = 101 << 30
	return r, a
}

func TestNativeControlSealAndPreflightRejectTamperingBeforeLaunch(t *testing.T) {
	r, a := controlFixture()
	b, _ := json.Marshal(r)
	sha := controlHash(b)
	if _, err := decodeControl(b, sha); err != nil {
		t.Fatal(err)
	}
	if err := validateControl(r, a, true); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*controlRequest){
		func(r *controlRequest) { r.Profile = "other" }, func(r *controlRequest) { r.Facts.Source.SHA256 = strings.Repeat("0", 64) }, func(r *controlRequest) { r.Facts.Tool.SHA256 = strings.Repeat("0", 64) }, func(r *controlRequest) { r.Facts.SID = "other" }, func(r *controlRequest) { r.Tool = `C:\foreign.exe` }, func(r *controlRequest) { r.Store.Path = `C:\foreign` }, func(r *controlRequest) { r.Store.Token = "bad" }, func(r *controlRequest) { r.Source = `C:\foreign.esd` },
	} {
		c := r
		change(&c)
		raw, _ := json.Marshal(c)
		if _, err := decodeControl(raw, sha); err == nil {
			t.Fatal("changed request bytes accepted")
		}
		if err := validateControl(c, a, true); err == nil {
			t.Fatal("changed request contract accepted")
		}
	}
	for _, change := range []func(*controlFacts){func(a *controlFacts) { a.Elevated = false }, func(a *controlFacts) { a.SID = "other" }, func(a *controlFacts) { a.Build++ }, func(a *controlFacts) { a.Process = "x86" }, func(a *controlFacts) { a.Runner.SHA256 = "bad" }, func(a *controlFacts) { a.Free = 1 }} {
		c := a
		change(&c)
		if err := validateControl(r, c, true); err == nil {
			t.Fatal("wrong actual boundary accepted")
		}
	}
	for _, bad := range [][]byte{append(b, ' '), append(b, []byte(`{}`)...), []byte(strings.Replace(string(b), `"version":1`, `"version":1,"argv":[]`, 1))} {
		if _, err := decodeControl(bad, sha); err == nil {
			t.Fatal("unsealed request accepted")
		}
	}
}

func TestNativeControlFixedCommandGraphAndCancellation(t *testing.T) {
	p := controlPaths{Source: `C:\source.esd`, Before: `C:\owned\before.wim`, Working: `C:\owned\working.wim`, After: `C:\owned\after.wim`, Mount: `C:\owned\mount`, Apply: `C:\apply\image`, Provider: `C:\provider`}
	var got []string
	for _, op := range controlOperations {
		args, err := controlArguments(op, p)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, op)
		if len(args) < 4 || args[0] != "/English" || args[1] != "/NoRestart" {
			t.Fatal(args)
		}
		if strings.Contains(strings.Join(args, " "), "/Online") || strings.Contains(strings.Join(args, " "), "Cleanup-Mountpoints") {
			t.Fatal(args)
		}
	}
	if !reflect.DeepEqual(got, []string{"i0", "s0", "e0", "b0", "m0", "d0", "q0", "x0", "q1", "u0", "e1", "a0", "p0", "i1"}) {
		t.Fatal(got)
	}
	args, _ := controlArguments("x0", p)
	if args[2] != `/Image:C:\owned\mount` || args[3] != "/Set-InputLocale:0809:00000809" {
		t.Fatal(args)
	}
	args, _ = controlArguments("r0", p)
	if args[2] != "/Unmount-Image" || args[3] != `/MountDir:C:\owned\mount` || args[4] != "/Discard" {
		t.Fatal(args)
	}
	if _, err := controlArguments("arbitrary", p); err == nil {
		t.Fatal("arbitrary dispatch accepted")
	}
}

func TestNativeControlIndependentAssertionsRejectNoopAndWrongDurableState(t *testing.T) {
	b := controlBaselineObservation()
	a := b
	a.UserPreload = "00000809"
	if err := assertControlChange(b, a, controlPin{SHA256: strings.Repeat("a", 64)}, controlPin{SHA256: strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*controlObservation){func(a *controlObservation) { a.UserPreload = "00000409" }, func(a *controlObservation) { a.UserLocale = "en-GB" }, func(a *controlObservation) { a.Edition = "Enterprise" }, func(a *controlObservation) { a.SystemDefault = "0809" }, func(a *controlObservation) { a.UserSubstitutes = map[string]string{"00000809": "00000409"} }} {
		c := a
		change(&c)
		if err := assertControlChange(b, c, controlPin{SHA256: "a"}, controlPin{SHA256: "b"}); err == nil {
			t.Fatal("conflicting durable state accepted")
		}
	}
	if err := assertControlChange(b, a, controlPin{SHA256: "same"}, controlPin{SHA256: "same"}); err == nil {
		t.Fatal("unchanged image accepted")
	}
}

const mountedControlText = "Mounted images:\r\n\r\nMount Dir : C:\\owned\\mount\r\nImage File : C:\\owned\\working.wim\r\nImage Index : 1\r\nMounted Read/Write : Yes\r\nStatus : Ok\r\n\r\nThe operation completed successfully.\r\n"

func TestNativeControlRecoveryRequiresExactOwnedInventory(t *testing.T) {
	m, err := parseControlMounts(mountedControlText)
	if err != nil {
		t.Fatal(err)
	}
	p := controlPaths{Mount: `C:\owned\mount`, Working: `C:\owned\working.wim`}
	if err := controlOwnedMount(m, p); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(mountedControlText, "working.wim", "foreign.wim", 1), strings.Replace(mountedControlText, "Image Index : 1", "Image Index : 2", 1), strings.Replace(mountedControlText, "Status : Ok", "Status : Invalid", 1)} {
		m, e := parseControlMounts(bad)
		if e == nil && controlOwnedMount(m, p) == nil {
			t.Fatal("foreign/invalid recovery accepted")
		}
	}
	for _, bad := range []string{"", "The operation completed successfully.", strings.Replace(mountedControlText, "Mounted images:", "", 1), mountedControlText + mountedControlText} {
		if _, err := parseControlMounts(bad); err == nil {
			t.Fatal("ambiguous inventory accepted")
		}
	}
}

func TestNativeControlInventoryEncodingTruncationAndPathRepresentations(t *testing.T) {
	u := utf16.Encode([]rune(mountedControlText))
	b := []byte{0xff, 0xfe}
	for _, v := range u {
		b = append(b, byte(v), byte(v>>8))
	}
	if m, err := parseControlMounts(string(b)); err != nil || len(m) != 1 {
		t.Fatal(m, err)
	}
	for _, bad := range []string{mountedControlText[strings.Index(mountedControlText, "Mount Dir"):], mountedControlText[:len(mountedControlText)-45], strings.Replace(mountedControlText, "Image Index : 1", "Image Index :", 1), "\xff" + mountedControlText, "\x00" + mountedControlText, string(append(b, 1))} {
		if _, err := parseControlMounts(bad); err == nil {
			t.Fatal("partial/malformed inventory accepted")
		}
	}
	p := controlPaths{Mount: `\\?\C:\owned\mount`, Working: `\\?\C:\owned\working.wim`}
	m, err := parseControlMounts(mountedControlText)
	if err != nil || controlOwnedMount(m, p) != nil {
		t.Fatal(m, err)
	}
	m[0].Path += `-foreign`
	if controlOwnedMount(m, p) == nil {
		t.Fatal("prefix overlap adopted")
	}
}

func TestNativeControlExecutionStopsAndPreservesOnFailure(t *testing.T) {
	// A boundary fake returns synthetic command observations only. The real
	// sequencer decides whether more commands or a passing receipt are allowed.
	for _, fail := range []string{"q0", "x0", "u0", "a0", "p0"} {
		t.Run(fail, func(t *testing.T) {
			var steps []string
			err := sequenceControl(context.Background(), func(ctx context.Context, op string) error {
				steps = append(steps, op)
				if op == fail {
					return errors.New("synthetic interruption")
				}
				return nil
			})
			if err == nil || steps[len(steps)-1] != fail {
				t.Fatalf("%v %v", steps, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	var steps []string
	err := sequenceControl(ctx, func(ctx context.Context, op string) error {
		steps = append(steps, op)
		if op == "x0" {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || steps[len(steps)-1] != "x0" {
		t.Fatal(steps, err)
	}
}

type controlTestInventory struct{}

func (controlTestInventory) Inspect(context.Context, string) (jobstore.MountSnapshot, error) {
	return jobstore.MountSnapshot{Complete: true}, nil
}

func TestNativeControlCrashRecoveryBindsDurableClaimAndExactIntent(t *testing.T) {
	r, _ := controlFixture()
	sha := strings.Repeat("d", 64)
	s, err := jobstore.Create(t.TempDir(), "desktop-control", controlTestInventory{})
	if err != nil {
		t.Fatal(err)
	}
	r.Store = s.Identity()
	tx, err := s.Begin(context.Background(), controlIntent(r, sha))
	if err != nil {
		t.Fatal(err)
	}
	m, err := tx.ClaimMount("mount")
	if err != nil {
		t.Fatal(err)
	}
	id := s.Identity()
	s.Close()
	s, err = jobstore.Open(id, controlTestInventory{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	recovery, err := s.InspectRecovery(context.Background(), id.JobID)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.OwnedMounts(context.Background(), id.JobID)
	if err != nil {
		t.Fatal(err)
	}
	path, claim, err := selectControlRecovery(recovery, claims, r, sha)
	if err != nil || claim != m || path == "" {
		t.Fatal(path, claim, err)
	}
	bad := recovery
	bad.Interrupted = append([]jobstore.InterruptedStage(nil), recovery.Interrupted...)
	bad.Interrupted[0].Intent = controlIntent(r, sha)
	bad.Interrupted[0].Intent.Tools = nil
	if _, _, err = selectControlRecovery(bad, claims, r, sha); err == nil {
		t.Fatal("altered tool intent recovered")
	}
	claims[0].RelativePath = "foreign"
	if _, _, err = selectControlRecovery(recovery, claims, r, sha); err == nil {
		t.Fatal("unrelated claim recovered")
	}
	// Reopening did not grant the interrupted transaction mutation permission.
	if _, err = tx.OpenFile("working.wim", os.O_CREATE|os.O_WRONLY, 0600); err == nil {
		t.Fatal("interrupted mutation resumed")
	}
	if _, err = os.Stat(filepath.Join(id.Path, filepath.FromSlash(m.RelativePath))); err != nil {
		t.Fatal("owned crash resource removed", err)
	}
}

func TestNativeControlScopePinsRejectReplacedDirectories(t *testing.T) {
	w, err := platform.CreateWorkspace(t.TempDir(), "desktop-control")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	f, err := controlReadLock(w.Path(), true)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := controlDirectoryID(f)
	child, writeErr := w.OpenFile("owned.txt", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if writeErr != nil {
		t.Fatal("pinned directory forbids owned child creation", writeErr)
	}
	child.Close()
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyControlDirectory(w.Path(), pin); err != nil {
		t.Fatal(err)
	}
	pin.FileIndex++
	if err = verifyControlDirectory(w.Path(), pin); err == nil {
		t.Fatal("changed directory identity accepted")
	}
	id := w.Identity()
	id.Token = strings.Repeat("f", 32)
	if other, err := platform.OpenWorkspace(id); err == nil {
		other.Close()
		t.Fatal("wrong capability accepted")
	}
}

func TestNativeControlObservationFiltersOnlyOwnedDescendants(t *testing.T) {
	got := controlDescendants(10, []controlProcessParent{{PID: 11, Parent: 10}, {PID: 12, Parent: 11}, {PID: 20, Parent: 2}, {PID: 21, Parent: 20}})
	if !reflect.DeepEqual(got, map[uint32]bool{10: true, 11: true, 12: true}) {
		t.Fatal(got)
	}
	// PID 30 is separately confirmed against an already observed creation
	// time. Its direct parent has exited, but its session lifetime continues.
	got = controlDescendants(10, []controlProcessParent{{PID: 30, Parent: 99}, {PID: 31, Parent: 30}, {PID: 40, Parent: 2}}, 30)
	if !reflect.DeepEqual(got, map[uint32]bool{10: true, 30: true, 31: true}) {
		t.Fatal(got)
	}
}

func TestNativeControlRejectsOverlappingInitialMountScope(t *testing.T) {
	for _, path := range []string{`C:\owned`, `C:\owned\child`, `C:\`} {
		if err := controlScopesUnmounted([]controlMount{{Path: path}}, []string{`\\?\C:\owned`}); err == nil {
			t.Fatal("overlapping mounted scope accepted", path)
		}
	}
	if err := controlScopesUnmounted([]controlMount{{Path: `C:\owned-foreign`}}, []string{`C:\owned`}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeControlReadOnlyTokenObservation(t *testing.T) {
	o, err := observeControlToken()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := platform.CurrentPeerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if o.SID != peer.UserSID || o.ElevationType < 1 || o.ElevationType > 3 || (o.LinkedAvailable && o.LinkedSID == "") {
		t.Fatal(o)
	}
}

func TestNativeControlPreparesMeasuredPathTemplatesWithoutImageOutputs(t *testing.T) {
	r, _ := controlFixture()
	proposal, err := controlProposal(r)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.MaxNativePath >= 260 || proposal.StageTokenWidth != 32 || len(proposal.Commands) != 14 {
		t.Fatal(proposal)
	}
	r.Provider.Path += strings.Repeat("x", 260)
	if _, err := controlProposal(r); err == nil {
		t.Fatal("overlong native path accepted")
	}
}

func TestNativeControlNativeQueriesRejectNoopAndConflictingIdentity(t *testing.T) {
	s := "Default system UI language : en-US\r\nSystem locale : en-US\r\nUser locale for default user : en-US\r\nActive keyboard(s) : 0409:00000409\r\n"
	if err := assertControlIntl(s, false); err != nil {
		t.Fatal(err)
	}
	if err := assertControlIntl(s, true); err == nil {
		t.Fatal("unchanged native query accepted")
	}
	if err := assertControlIntl(strings.Replace(s, "0409:00000409", "0809:00000809", 1), true); err != nil {
		t.Fatal(err)
	}
	info := "Index : 9\nName : Windows 10 Pro\nArchitecture : x64\nVersion : 10.0.19041\nServicePack Build : 3803\nEdition : Professional\nInstallation : Client\nen-US (Default)\n"
	if err := assertControlImageInfo(info, 9); err != nil {
		t.Fatal(err)
	}
	if err := assertControlImageInfo(strings.Replace(info, "Professional", "Enterprise", 1), 9); err == nil {
		t.Fatal("conflicting actual identity accepted")
	}
}

func TestNativeControlChildEnvironmentIsScopedAndRestored(t *testing.T) {
	before, existed := os.LookupEnv("TMP")
	provider := t.TempDir()
	restore, err := controlTemp(provider)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("TMP") != filepath.Join(provider, "tmp") || os.Getenv("TEMP") != filepath.Join(provider, "tmp") {
		t.Fatal("provider scratch environment not scoped")
	}
	if err = restore(); err != nil {
		t.Fatal(err)
	}
	after, exists := os.LookupEnv("TMP")
	if after != before || exists != existed {
		t.Fatal("process environment not restored")
	}
}

func TestNativeControlSharedComponentCustodyKeepsAliasesReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "component.bin")
	alias := filepath.Join(dir, "alias.bin")
	if err := os.WriteFile(path, []byte("locked"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if f, err := controlReadLock(path, false); err == nil {
		f.Close()
		t.Fatal("source/output strict custody accepted shared file")
	}
	f, err := controlComponentReadLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pin, err := controlPinFile(f, false, false)
	if err != nil || pin.Links != 2 || pin.Identity.FileIndex == 0 {
		t.Fatal(pin, err)
	}
	if writer, err := os.OpenFile(alias, os.O_WRONLY, 0); err == nil {
		writer.Close()
		t.Fatal("shared alias acquired mutation while component locked")
	}
	copyPin := pin
	copyPin.Identity.FileIndex++
	copyPin.Links = 1
	if !controlSameBytes(pin, copyPin) {
		t.Fatal("verified copy requires identical file ID")
	}
	copyPin.SHA256 = "changed"
	if controlSameBytes(pin, copyPin) {
		t.Fatal("changed copy accepted")
	}
}
