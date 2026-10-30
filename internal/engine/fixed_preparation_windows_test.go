package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	platform "uupbuilder/internal/platform/windows"
)

// Omitting a component/reserve or silently wrapping totals must prevent the
// small-volume fixture from reaching any producer or native claim mutation.
func TestFixedPreparationFootprintChecksCombinedVolumeAndOverflow(t *testing.T) {
	f, e := fixedPreparationFootprint(2288011348)
	if e != nil {
		t.Fatal(e)
	}
	if f.Total != 127110498388 {
		t.Fatalf("combined literal total %d", f.Total)
	}
	volume := platform.StorageVolume{ID: "fixed-volume", AvailableBytes: f.Total - 1}
	if e = f.Check(volume); e == nil {
		t.Fatal("insufficient combined space accepted")
	}
	volume.AvailableBytes = f.Total
	if e = f.Check(volume); e != nil {
		t.Fatal(e)
	}
	if e = f.CheckChanged(volume, platform.StorageVolume{ID: "other", AvailableBytes: f.Total}); e == nil {
		t.Fatal("changed volume accepted")
	}
	volume.AvailableBytes--
	if e = f.CheckChanged(platform.StorageVolume{ID: "fixed-volume", AvailableBytes: f.Total}, volume); e == nil {
		t.Fatal("space loss accepted")
	}
	if _, e = fixedPreparationFootprint(^uint64(0)); e == nil {
		t.Fatal("unknown/out-of-profile source size accepted")
	}
	if _, e = checkedPreparationSum(^uint64(0), 1); e == nil {
		t.Fatal("overflow accepted")
	}
}

// Lost early/final events, overwrite or quota reset would hide failed or
// partial preparation. All IO here is small ordinary private-file IO.
func TestFixedPreparationEvidenceRetainsEarlyFailureAndFinalOnQuota(t *testing.T) {
	w, e := platform.CreateWorkspace(t.TempDir(), "fixed-evidence-unit")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	p, e := platform.PinFreshWorkspace(w)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	s, e := newFixedPreparationEvidence(p, 64)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Record("early", struct{ Value string }{"source"}); e != nil {
		t.Fatal(e)
	}
	if e = s.Record("oversized", string(make([]byte, 80))); !errors.Is(e, ErrLimit) {
		t.Fatalf("quota %v", e)
	}
	if e = s.Record("retry", nil); !errors.Is(e, ErrLimit) {
		t.Fatalf("quota reset %v", e)
	}
	if e = s.Final(struct{ Failed bool }{true}); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	early, e := os.ReadFile(filepath.Join(w.Path(), "attempt.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	if string(early) != "{\"kind\":\"early\",\"value\":{\"Value\":\"source\"}}\n" {
		t.Fatalf("durable early record %q", early)
	}
	final, e := os.ReadFile(filepath.Join(w.Path(), "final.json"))
	if e != nil {
		t.Fatal(e)
	}
	var v struct{ Failed bool }
	if e = json.Unmarshal(final, &v); e != nil || !v.Failed {
		t.Fatalf("final %s %v", final, e)
	}
	if _, e = newFixedPreparationEvidence(p, 64); e == nil {
		t.Fatal("failed evidence replaced")
	}
	if e = s.Final(nil); e == nil {
		t.Fatal("final evidence overwritten")
	}
}

func TestFixedPreparationCancellationIsCooperativeAndDeadlineBounded(t *testing.T) {
	cancelSignal := make(chan struct{})
	ctx, stop, e := fixedPreparationContext(context.Background(), time.Now().Add(time.Minute), cancelSignal)
	if e != nil {
		t.Fatal(e)
	}
	defer stop()
	close(cancelSignal)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("cooperative request not observed")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal(ctx.Err())
	}
	if _, _, e = fixedPreparationContext(context.Background(), time.Time{}, nil); e == nil {
		t.Fatal("unbounded operation accepted")
	}
	if _, _, e = fixedPreparationContext(context.Background(), time.Now().Add(25*time.Hour), nil); e == nil {
		t.Fatal("excessive deadline accepted")
	}
}

func TestFixedPreparationNeverMintsNativeConsentFromConfiguration(t *testing.T) {
	t.Setenv("UUP_FIXED_SELECTED_APPLY", "reviewed-source-contract-0x182")
	p := &fixedSelectedPreparation{}
	if p.nativeAuthorized() {
		t.Fatal("configuration minted native approval")
	}
	if p.check() == nil {
		t.Fatal("missing live custody accepted")
	}
	if (*fixedSelectedPreparation)(nil).nativeAuthorized() {
		t.Fatal("nil preparation accepted")
	}
}

func TestFixedPreparationApprovalRequiresExactLivePipeDigest(t *testing.T) {
	for _, line := range []string{"approve:wrong\n", "approve:" + string(make([]byte, 300)) + "\n", "cancel\n"} {
		r, w, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		go func() { fmt.Fprint(w, line); w.Close() }()
		if e = readFixedOperatorApproval(context.Background(), r, "abc"); e == nil {
			t.Fatal("mismatched approval accepted")
		}
	}
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	go func() { fmt.Fprint(w, "approve:abc\n"); w.Close() }()
	if e = readFixedOperatorApproval(context.Background(), r, "abc"); e != nil {
		t.Fatal(e)
	}
	f, e := os.CreateTemp(t.TempDir(), "editable")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	f.WriteString("approve:abc\n")
	f.Seek(0, 0)
	if e = readFixedOperatorApproval(context.Background(), f, "abc"); e == nil {
		t.Fatal("editable file minted approval")
	}
}

func TestFixedPreparationScopeRejectsMutationBeforeLaunch(t *testing.T) {
	s := fixedApprovedScope{Version: 1, SourceHead: strings.Repeat("a", 40), SourceRoot: fixedPreparationSource, LocatorSHA256: fixedSelectedLocatorSHA256, SourceBytes: 2288011348, Policy: fixedApplyPolicyDigest(), Flags: 0x182, Image: 1, PrivilegeProfile: platform.ImagePreservationPrivilegeProfile, Deadline: time.Now().Add(time.Hour), TokenUser: "S-1-test", Parent: platform.PreparationParentIdentity{Workspace: platform.WorkspaceIdentity{Path: filepath.Join(fixedPreparationOutputParent, "uupbuilder-"+strings.Repeat("a", 32)), JobID: "fixed-selected-preparation", Token: strings.Repeat("a", 32)}, Root: platform.FileIdentity{VolumeSerial: 1, FileIndex: 2}, Owner: platform.FileIdentity{VolumeSerial: 1, FileIndex: 3}, Parent: platform.FileIdentity{VolumeSerial: 1, FileIndex: 4}, VolumeID: "volume"}, Executable: platform.ExecutableIdentity{Path: `C:\fixed.test.exe`, SHA256: strings.Repeat("b", 64), Size: 123, File: platform.FileIdentity{VolumeSerial: 1, FileIndex: 5}}}
	s.Footprint, _ = fixedPreparationFootprint(s.SourceBytes)
	if e := s.validate(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*fixedApprovedScope){func(v *fixedApprovedScope) { v.Flags = 0 }, func(v *fixedApprovedScope) { v.SourceBytes++ }, func(v *fixedApprovedScope) { v.Parent.Workspace.Path = `C:\other` }, func(v *fixedApprovedScope) { v.Footprint.Total-- }, func(v *fixedApprovedScope) { v.LocatorSHA256 = strings.Repeat("c", 64) }} {
		v := s
		change(&v)
		if e := v.validate(); e == nil {
			t.Fatal("mutated immutable scope accepted")
		}
	}
}

func TestFixedPreparationFinalSurvivesParentHandleClosure(t *testing.T) {
	w, e := platform.CreateWorkspace(t.TempDir(), "fixed-final-unit")
	if e != nil {
		t.Fatal(e)
	}
	p, e := platform.PinFreshWorkspace(w)
	if e != nil {
		t.Fatal(e)
	}
	s, e := newFixedPreparationEvidence(p, 64)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	if e = s.Final(struct{ Closed bool }{true}); e != nil {
		t.Fatal(e)
	}
}

func TestFixedPreparationStorageWatchCancelsOnActualVolumeReserve(t *testing.T) {
	path := t.TempDir()
	volume, e := platform.InspectStorage(path)
	if e != nil {
		t.Fatal(e)
	}
	ctx, stop := watchFixedPreparationStorage(context.Background(), []fixedStorageWatch{{Path: path, VolumeID: volume.ID, Reserve: ^uint64(0)}})
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("storage failure not cooperatively cancelled")
	}
	if !errors.Is(context.Cause(ctx), ErrLimit) {
		t.Fatal(context.Cause(ctx))
	}
}

func TestFixedPreparationNativeEstimateCountsPerNameStreamsAndLinks(t *testing.T) {
	p, close := expectationFixture(t)
	defer close()
	x, e := BindSourceExpectations(context.Background(), p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	v, e := fixedSourceDiskEstimate(x)
	if e != nil {
		t.Fatal(e)
	}
	if v.LogicalBytes != 106 || v.Entries != 11 || v.Total <= v.LogicalBytes {
		t.Fatalf("source-derived estimate %+v", v)
	}
	close()
	if _, e = fixedSourceDiskEstimate(x); e == nil {
		t.Fatal("closed historical proof reused for disk derivation")
	}
}

func TestFixedPreparationFramesUseBoundedExactBytes(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	go func() {
		defer w.Close()
		sender := fixedControlWriter{w: w}
		sender.send(fixedControlFrame{Kind: "cancel", Digest: strings.Repeat("a", 64)})
	}()
	v, e := readFixedControl(r)
	if e != nil || v.Kind != "cancel" || v.Digest != strings.Repeat("a", 64) {
		t.Fatalf("frame %+v %v", v, e)
	}
	if _, e = readFixedControl(strings.NewReader("\x00\x01\x00\x01")); !errors.Is(e, ErrLimit) {
		t.Fatalf("unbounded control accepted %v", e)
	}
}

type fixedPartialFrameWriter struct {
	w     io.Writer
	cause error
}

func (w fixedPartialFrameWriter) Write(b []byte) (int, error) {
	n, e := w.w.Write(b[:min(len(b), 2)])
	return n, errors.Join(e, w.cause)
}

// A partial write error deliberately leaves this real duplex pipe open. The
// initial handoff must disconnect before the peer can finish io.ReadFull.
func TestFixedPreparationPartialInitialFrameDisconnectsAndSettles(t *testing.T) {
	parent, child := net.Pipe()
	defer parent.Close()
	defer child.Close()
	childDone := make(chan error, 1)
	go func() {
		childDone <- fixedInitialControlIO(context.Background(), child.Close, func() error { _, e := readFixedControl(child); return e })
	}()
	cause := errors.New("partial initial frame refused")
	w := fixedControlWriter{w: fixedPartialFrameWriter{parent, cause}}
	e := fixedInitialControlIO(context.Background(), parent.Close, func() error { return w.send(fixedControlFrame{Kind: "approved-fixed-scope", Digest: "fixed"}) })
	if !errors.Is(e, cause) {
		t.Fatal(e)
	}
	select {
	case e = <-childDone:
		if e == nil {
			t.Fatal("truncated frame accepted")
		}
	case <-time.After(time.Second):
		parent.Close()
		<-childDone
		t.Fatal("peer frame-read did not settle after partial handoff")
	}
}

func TestFixedPreparationInitialReadCancellationClosesAndDrainsIPC(t *testing.T) {
	parent, child := net.Pipe()
	defer parent.Close()
	defer child.Close()
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- fixedInitialControlIO(ctx, child.Close, func() error { close(started); _, e := readFixedControl(child); return e })
	}()
	<-started
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		child.Close()
		<-done
		t.Fatal("cancelled initial IO was not drained")
	}
}

// A refusal before child sink construction must survive the authenticated
// result frame and the parent's real durable evidence writer, including cause.
func TestFixedPreparationPreSinkRefusalReachesDurableParent(t *testing.T) {
	w, e := platform.CreateWorkspace(t.TempDir(), "fixed-refusal-unit")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	pin, e := platform.PinFreshWorkspace(w)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	sink, e := newFixedPreparationEvidence(pin, fixedEvidenceQuota)
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	result := fixedChildResult{}
	if e = recordFixedChildFailure(&result, nil, "approved-parent", os.ErrNotExist); e != nil {
		t.Fatal(e)
	}
	r, writer, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	go func() {
		defer writer.Close()
		sender := fixedControlWriter{w: writer}
		sender.send(fixedControlFrame{Kind: "final", Digest: "same-live-scope", Result: &result})
	}()
	v, e := readFixedControl(r)
	if e != nil {
		t.Fatal(e)
	}
	if e = sink.Record("child-final", v); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(w.Path(), "attempt.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	var event struct {
		Value fixedControlFrame `json:"value"`
	}
	if e = json.Unmarshal(b, &event); e != nil {
		t.Fatal(e)
	}
	failure := event.Value.Result.Failure
	if failure == nil || failure.Phase != "approved-parent" || !failure.Outcome.Failed || !strings.Contains(failure.Reason, "exist") || !event.Value.Result.Failed {
		t.Fatalf("lost pre-sink refusal: %s", b)
	}
}

func TestFixedPreparationTokenRefusalIsBoundedAndRecorded(t *testing.T) {
	w, e := platform.CreateWorkspace(t.TempDir(), "fixed-token-refusal-unit")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	pin, e := platform.PinFreshWorkspace(w)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	sink, e := newFixedPreparationEvidence(pin, fixedEvidenceQuota)
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	token, e := platform.CurrentProcessTokenIdentity()
	if e != nil {
		t.Fatal(e)
	}
	cause := fixedChildTokenPolicy(token, fixedApprovedScope{TokenUser: "different-approved-user", TokenSession: token.SessionID})
	if cause == nil {
		t.Fatal("wrong token policy accepted")
	}
	result := fixedChildResult{}
	if e = recordFixedChildFailure(&result, sink, "token-policy", cause); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(w.Path(), "attempt.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), "token-policy") || !strings.Contains(string(b), "approved token policy mismatch") {
		t.Fatalf("missing durable token refusal: %s", b)
	}
	var bounded fixedChildResult
	recordFixedChildFailure(&bounded, nil, strings.Repeat("p", 80), errors.New(strings.Repeat("r", 8192)))
	if bounded.Failure == nil || len(bounded.Failure.Phase) != 64 || len(bounded.Failure.Reason) != 4096 || !bounded.Failed {
		t.Fatalf("unbounded refusal %+v", bounded.Failure)
	}
}
