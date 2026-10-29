package engine

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	native "golang.org/x/sys/windows"
	platform "uupbuilder/internal/platform/windows"
)

const fixedSelectedLocatorSHA256 = "e9529aa610b1a25df0dad6fa8f33b759b65a74a2d00cf460f7b7b59527de986e"

var fixedAwaitConsent = flag.Bool("fixed-selected-await-consent", false, "fixed preparation parent: await separately approved tool-owned control command")
var fixedBootstrapValue = flag.String("fixed-selected-bootstrap", "", "private fixed selected probe peer bootstrap; no operation authority")

type fixedApprovedScope struct {
	Version                                                         uint32
	SourceHead, SourceRoot, LocatorSHA256, Policy, PrivilegeProfile string
	SourceBytes                                                     uint64
	Flags, Image                                                    uint32
	Parent                                                          platform.PreparationParentIdentity
	Executable                                                      platform.ExecutableIdentity
	Footprint                                                       fixedDiskFootprint
	TokenUser                                                       string
	TokenSession                                                    uint32
	Deadline                                                        time.Time
	AncillaryVolume                                                 platform.StorageVolume
	AncillaryDisclosure                                             string
	SourceContract, TokenPolicy                                     string
}

func (s fixedApprovedScope) validate() error {
	f, e := fixedPreparationFootprint(s.SourceBytes)
	if e != nil || s.Version != 1 || len(s.SourceHead) != 40 || s.SourceRoot != fixedPreparationSource || s.LocatorSHA256 != fixedSelectedLocatorSHA256 || s.SourceBytes != 2288011348 || s.Policy != fixedApplyPolicyDigest() || s.Flags != 0x182 || s.Image != 1 || s.PrivilegeProfile != platform.ImagePreservationPrivilegeProfile || s.Footprint != f || s.TokenUser == "" || s.Deadline.IsZero() {
		return ErrInput
	}
	if !strings.EqualFold(filepath.Clean(strings.TrimPrefix(filepath.Dir(s.Parent.Workspace.Path), `\\?\`)), filepath.Clean(fixedPreparationPlan)) || s.Parent.Workspace.JobID != "fixed-selected-preparation" || filepath.Base(s.Parent.Workspace.Path) != "uupbuilder-"+s.Parent.Workspace.Token || len(s.Parent.Workspace.Token) != 32 || s.Parent.Root.FileIndex == 0 || s.Parent.Owner.FileIndex == 0 || s.Parent.Parent.FileIndex == 0 || s.Parent.VolumeID == "" || s.Executable.File.FileIndex == 0 || s.Executable.Size <= 0 || len(s.Executable.SHA256) != 64 {
		return ErrInput
	}
	return nil
}
func newFixedApprovedScope(p *fixedSelectedPreparation, locator string) (fixedApprovedScope, error) {
	s := fixedApprovedScope{Version: 1, SourceHead: fixedPreparationSourceHead, SourceRoot: fixedPreparationSource, LocatorSHA256: locator, Policy: fixedApplyPolicyDigest(), PrivilegeProfile: platform.ImagePreservationPrivilegeProfile, SourceBytes: 2288011348, Flags: 0x182, Image: 1, Parent: p.parent.Identity(), Executable: p.executable.Identity(), Footprint: p.footprint, TokenUser: p.token.UserSID, TokenSession: p.token.SessionID}
	s.Deadline, _ = p.ctx.Deadline()
	system, e := native.GetSystemDirectory()
	if e != nil {
		return s, e
	}
	s.AncillaryVolume, e = platform.InspectStorage(system)
	if e != nil {
		return s, e
	}
	s.AncillaryDisclosure = "DISM null log/scratch remain OS-selected on system volume; 8 GiB conservative reserve, no enforced native/OS/NTFS allocation quota; output/cache/evidence retained; no cleanup acceptance; future elevated token ID and live WIM/proof unprepared"
	s.SourceContract = "manifest 675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9; 3d12aa3e-806a-46c9-900e-bf7613959273 / 19045.7811 / x86 / en-us; exact 13 ESD + 22 CAB; exclude ssu- and windows10.0- CAB servicing; Professional/Client/10.0.19041.1 original image 3 to output image 1; 39472 resources; all live hashes/oracles/closure recreated; original inputs read only; no source executable; one installed wimgapi apply 0x182; all native output/cache retained"
	s.TokenPolicy = "future elevated same user/session process token, no impersonation; SeBackupPrivilege, SeRestorePrivilege, SeSecurityPrivilege must already exist; fixed profile only; exact baseline restore/rollback or explicit quarantine; no fallback or account-policy changes; sufficiency unproved"
	if s.AncillaryVolume.AvailableBytes < 8<<30 {
		return s, ErrLimit
	}
	return s, s.validate()
}

type fixedLiveApproval struct {
	scope      fixedApprovedScope
	digest     string
	connection platform.WorkerConnection
}
type fixedControlFrame struct {
	Kind   string
	Scope  *fixedApprovedScope `json:",omitempty"`
	Digest string              `json:",omitempty"`
	Result *fixedChildResult   `json:",omitempty"`
}
type fixedChildResult struct {
	Failed, NativeInvoked, Preserved bool
	EvidenceRoot, Failure            string
}
type fixedControlWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *fixedControlWriter) send(v fixedControlFrame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if len(b) > 64<<10 {
		return ErrLimit
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(b)))
	if e = writeFixedFull(w.w, prefix[:]); e != nil {
		return e
	}
	return writeFixedFull(w.w, b)
}
func writeFixedFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n <= 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func readFixedControl(r io.Reader) (fixedControlFrame, error) {
	var v fixedControlFrame
	var prefix [4]byte
	if _, e := io.ReadFull(r, prefix[:]); e != nil {
		return v, e
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > 64<<10 {
		return v, ErrLimit
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return v, e
	}
	if e := json.Unmarshal(b, &v); e != nil {
		return v, e
	}
	return v, nil
}

// Only the live tool-owned pipe control command can release this gate. The
// controller supplies it after an explicit human response to this exact digest.
// Files, environment values, bootstrap JSON and an approval from another run do
// not release it. This is intentionally not a product command interface.
func readFixedOperatorApproval(ctx context.Context, r *os.File, digest string) error {
	if r == nil || ctx == nil {
		return ErrInput
	}
	typeID, e := native.GetFileType(native.Handle(r.Fd()))
	if e != nil || typeID != native.FILE_TYPE_PIPE {
		return ErrInput
	}
	type result struct {
		line string
		e    error
	}
	done := make(chan result, 1)
	go func() {
		var line []byte
		var b [1]byte
		for len(line) <= 128 {
			n, e := r.Read(b[:])
			if n > 0 {
				line = append(line, b[0])
				if b[0] == '\n' {
					done <- result{string(line), nil}
					return
				}
			}
			if e != nil {
				done <- result{"", e}
				return
			}
		}
		done <- result{"", ErrLimit}
	}()
	select {
	case v := <-done:
		if v.e != nil {
			return v.e
		}
		if v.line != "approve:"+digest+"\n" {
			return ErrInput
		}
		return nil
	case <-ctx.Done():
		r.Close()
		<-done
		return ctx.Err()
	}
}
func runFixedApprovedParent(p *fixedSelectedPreparation, s fixedApprovedScope) error {
	digest := preservationDigest(s)
	fmt.Printf("FIXED PREPARED SCOPE %s\nAwait explicit Codex human approval before tool-owned approve control; all WIM/token child measurements remain future.\n", digest)
	if e := readFixedOperatorApproval(p.ctx, os.Stdin, digest); e != nil {
		return e
	}
	if e := p.check(); e != nil {
		return e
	}
	p.record("operator-approval", struct {
		ScopeDigest     string
		BeforeElevation bool
	}{digest, true})
	if p.recordErr != nil {
		return p.recordErr
	}
	p.operatorApproved = true
	c, e := platform.StartFixedPreservationProbe(p.ctx, p.executable)
	if e != nil {
		return e
	}
	defer c.Close()
	w := &fixedControlWriter{w: c}
	if e = w.send(fixedControlFrame{Kind: "approved-fixed-scope", Scope: &s, Digest: digest}); e != nil {
		_, waitErr := platform.WaitFixedPreservationProbe(c)
		return errors.Join(e, waitErr)
	}
	stopControl := make(chan struct{})
	defer close(stopControl)
	// Parent deadline/interrupt/closed control is cooperative. The reader below
	// still waits for the child's final record; there is no forced timeout/kill.
	go func() {
		select {
		case <-p.ctx.Done():
			w.send(fixedControlFrame{Kind: "cancel", Digest: digest})
		case <-stopControl:
		}
	}()
	go func() {
		var b [128]byte
		n, e := os.Stdin.Read(b[:])
		if e != nil || string(b[:n]) != "cancel:"+digest+"\n" {
			w.send(fixedControlFrame{Kind: "cancel", Digest: digest})
			return
		}
		w.send(fixedControlFrame{Kind: "cancel", Digest: digest})
	}()
	v, readErr := readFixedControl(c)
	if readErr != nil || v.Kind != "final" || v.Result == nil || v.Digest != digest {
		w.send(fixedControlFrame{Kind: "cancel", Digest: digest})
	}
	// Even a failed IPC channel cannot be taken as synchronous native return.
	exit, waitErr := platform.WaitFixedPreservationProbe(c)
	p.record("child-final", struct {
		Frame      fixedControlFrame
		Read, Wait applyOperationOutcome
		Exit       uint32
	}{v, applyOutcome(readErr), applyOutcome(waitErr), exit})
	if readErr != nil || waitErr != nil {
		return errors.Join(readErr, waitErr)
	}
	if v.Kind != "final" || v.Digest != digest || v.Result == nil {
		return ErrInput
	}
	p.nativeStarted = v.Result.NativeInvoked
	// A preserved native trial deliberately exits nonzero. Neither this status
	// nor a successful component comparison counts as whole U07 acceptance.
	return fmt.Errorf("fixed component ended exit=%d failed=%t native=%t preserved=%t evidence=%s; production acceptance incomplete", exit, v.Result.Failed, v.Result.NativeInvoked, v.Result.Preserved, v.Result.EvidenceRoot)
}

func fixedSelectedChild(t *testing.T) {
	if flag.Lookup("test.run").Value.String() != "^TestConfiguredFixedSelectedSourceApply$" || flag.Lookup("test.count").Value.String() != "1" || flag.Lookup("test.timeout").Value.String() != "0s" {
		t.Fatal("fixed child must run alone without forced timeout")
	}
	b, e := platform.ParseFixedPreservationBootstrap(*fixedBootstrapValue)
	if e != nil {
		t.Fatal(e)
	}
	connectCtx, stopConnect := context.WithTimeout(context.Background(), 30*time.Second)
	c, exe, e := platform.ConnectFixedPreservationProbe(connectCtx, b)
	stopConnect()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := c.Close(); e != nil {
			t.Error(e)
		}
	})
	t.Cleanup(func() {
		if e := exe.Close(); e != nil {
			t.Error(e)
		}
	})
	writer := &fixedControlWriter{w: c}
	result := fixedChildResult{Failed: true, Preserved: true}
	var digest string
	t.Cleanup(func() {
		result.Failed = t.Failed()
		if e := writer.send(fixedControlFrame{Kind: "final", Digest: digest, Result: &result}); e != nil {
			t.Error("final peer delivery", e)
		}
	})
	v, e := readFixedControl(c)
	if e != nil || v.Kind != "approved-fixed-scope" || v.Scope == nil || v.Digest != preservationDigest(v.Scope) {
		t.Fatal("fixed authenticated scope missing", e)
	}
	s := *v.Scope
	digest = v.Digest
	if e = s.validate(); e != nil || s.Executable != exe.Identity() || s.SourceHead != fixedPreparationSourceHead || s.TokenUser != b.Parent.UserSID || s.TokenSession != b.Parent.SessionID {
		t.Fatal("approved scope changed", e)
	}
	ctx, cancel, e := fixedPreparationContext(context.Background(), s.Deadline, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(cancel)
	go func() {
		v, e := readFixedControl(c)
		if e != nil || v.Kind != "cancel" || v.Digest != digest {
			cancel()
			return
		}
		cancel()
	}()
	parent, e := platform.OpenPreparationParent(s.Parent)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := parent.Close(); e != nil {
			t.Error(e)
		}
	})
	if e = parent.Check(s.Parent.Workspace.Path); e != nil {
		t.Fatal(e)
	}
	actual, e := platform.InspectStorage(s.Parent.Workspace.Path)
	if e != nil {
		t.Fatal(e)
	}
	if actual.ID != s.Parent.VolumeID || s.Footprint.Check(actual) != nil {
		t.Fatal("approved output volume/space changed")
	}
	system, e := native.GetSystemDirectory()
	if e != nil {
		t.Fatal(e)
	}
	ancillary, e := platform.InspectStorage(system)
	if e != nil || ancillary.ID != s.AncillaryVolume.ID || ancillary.AvailableBytes < 8<<30 {
		t.Fatal("approved ancillary volume/space changed", e)
	}
	ctx, stopStorage := watchFixedPreparationStorage(ctx, []fixedStorageWatch{{s.Parent.Workspace.Path, s.Parent.VolumeID, 8 << 30}, {system, s.AncillaryVolume.ID, 8 << 30}})
	t.Cleanup(stopStorage)
	_, locator, e := fixedSelectedLocatorCost(s.SourceRoot)
	if e != nil || locator != s.LocatorSHA256 {
		t.Fatal("approved source locator changed", e)
	}
	w, e := platform.CreateWorkspace(s.Parent.Workspace.Path, "fixed-selected-native-child")
	if e != nil {
		t.Fatal(e)
	}
	pin, e := platform.PinFreshWorkspace(w)
	if e != nil {
		w.Close()
		t.Fatal(e)
	}
	sink, e := newFixedPreparationEvidence(pin, fixedEvidenceQuota)
	if e != nil {
		pin.Close()
		w.Close()
		t.Fatal(e)
	}
	p := &fixedSelectedPreparation{ctx: ctx, parent: pin, executable: exe, footprint: s.Footprint, volume: actual, evidence: sink, approved: &fixedLiveApproval{s, digest, c}}
	result.EvidenceRoot = w.Path()
	// t.Cleanup, rather than defers, lets producer cleanup records finish first.
	t.Cleanup(func() {
		result.Failed = t.Failed()
		result.NativeInvoked = p.nativeStarted
		p.record("cancel-context", struct{ Err, Cause string }{fmt.Sprint(p.ctx.Err()), fmt.Sprint(context.Cause(p.ctx))})
		p.record("child-owner-close", struct{ Parent, Workspace, Executable applyOperationOutcome }{applyOutcome(pin.Close()), applyOutcome(w.Close()), applyOutcome(errors.Join(exe.Verify(context.Background()), exe.Close()))})
		if e := sink.Final(struct {
			Result fixedChildResult
			Events applyOperationOutcome
		}{result, applyOutcome(p.recordErr)}); e != nil {
			t.Error("final durability", e)
		}
		if e := sink.Close(); e != nil {
			t.Error(e)
		}
		result.Failed = t.Failed()
	})
	p.record("approved-scope", s)
	p.token, e = platform.CurrentProcessTokenIdentity()
	if e != nil {
		t.Fatal(e)
	}
	p.record("child-token", p.token)
	if !p.token.Elevated || p.token.UserSID != s.TokenUser || p.token.SessionID != s.TokenSession {
		t.Fatal("approved token policy mismatch")
	}
	priv, e := platform.ObserveImagePreservationPrivileges(ctx)
	p.record("child-privilege-query", struct {
		Observation platform.PrivilegeObservation
		Outcome     applyOperationOutcome
	}{priv, applyOutcome(e)})
	if e != nil || len(priv.Required) != 3 {
		t.Fatal("fixed privileges unavailable", e)
	}
	for _, v := range priv.Required {
		if !v.Present || v.Attributes&native.SE_PRIVILEGE_REMOVED != 0 {
			t.Fatal("fixed existing privilege absent; no fallback", v.Name)
		}
	}
	t.Setenv("TEMP", w.Path())
	t.Setenv("TMP", w.Path())
	if e = p.check(); e != nil {
		t.Fatal(e)
	}
	fixedSelectedSourceApplyAfterLiveApproval(t, p)
}
