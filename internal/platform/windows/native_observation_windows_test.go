package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func nativeObservationFixture(t *testing.T) (*OwnedTree, string) {
	t.Helper()
	w, e := CreateWorkspace(t.TempDir(), "fixture")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { w.Close() })
	r, e := w.CreateOwnedTree("native-result", "op", "proof", TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	path := filepath.Join(w.Path(), "native-result")
	if e = os.Mkdir(filepath.Join(path, "known"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(path, "known", "file"), []byte("independent bytes"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(path, "known", "file:ads"), []byte("ADS"), 0600); e != nil {
		t.Fatal(e)
	}
	return r, path
}

func TestNativeReadOnlyObservationEmptyShortNameDriftAndMissing(t *testing.T) {
	ctx := context.Background()
	root, _ := nativeObservationFixture(t)
	s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.ObserveInventory(ctx, TreeLimits{}); e != nil {
		t.Fatal(e)
	}
	s.queryDirectory = func(h windows.Handle, class uint32, b []byte) error {
		if e := windows.GetFileInformationByHandleEx(h, class, &b[0], uint32(len(b))); e != nil {
			return e
		}
		for off := 0; ; {
			v := b[off:]
			n := binary.LittleEndian.Uint32(v[60:])
			u := make([]uint16, n/2)
			for j := range u {
				u[j] = binary.LittleEndian.Uint16(v[104+j*2:])
			}
			if string(utf16.Decode(u)) == "file" {
				v[68] = 2
				binary.LittleEndian.PutUint16(v[70:], 'X')
			}
			next := binary.LittleEndian.Uint32(v)
			if next == 0 {
				break
			}
			off += int(next)
		}
		return nil
	}
	v, e := s.ObserveInventory(ctx, TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	if v.Complete {
		t.Fatal("empty-to-nonempty short name drift accepted", v)
	}
	for _, en := range v.Entries {
		if en.Path == "known/file" && en.Status != "changed-short-name" {
			t.Fatal("short-name drift not identified", en)
		}
	}
}

func TestNativeReadOnlyObservationExactHandleLimitAndPartialClose(t *testing.T) {
	ctx := context.Background()
	root, _ := nativeObservationFixture(t)
	l := NativeObservationLimits{MaxHandles: len(root.parents) + 6} // root, two leaves, ADS, two validation temporaries
	s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), l)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if _, e = s.ObserveInventory(ctx, TreeLimits{}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ReadOwnedAt(ctx, "known/file", "ads", make([]byte, 3), 0); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Observe(ctx, "known/file", MetadataLimits{}); e != nil {
		t.Fatal("exact handle ceiling refused settled temporary", e)
	}
	closed := 0
	s.closeFile = func(f *os.File) error { closed++; return errors.Join(f.Close(), windows.ERROR_ACCESS_DENIED) }
	if e = s.Close(); !errors.Is(e, ErrTreePreserved) || !errors.Is(e, windows.ERROR_ACCESS_DENIED) || closed != 3 {
		t.Fatal("close cause/lifetime", closed, e)
	}
	if e = s.Close(); !errors.Is(e, windows.ERROR_ACCESS_DENIED) || closed != 3 {
		t.Fatal("close not latched", e, closed)
	}
	if summary := s.FailureSummary(); summary.LatchedObservationFailed || !summary.HandleCloseFailed || !summary.CloseAttempted {
		t.Fatal("actual handle close confused with prior observation failure", summary)
	}
	v, e := s.Evidence(ctx, 1<<20)
	if e != nil || !v.Closed || len(v.Entries) != 3 || len(v.Failures) != 3 {
		t.Fatal("historical close evidence", v, e)
	}
	if _, e = s.Evidence(ctx, 0); !errors.Is(e, ErrTreeLimit) {
		t.Fatal("exhausted export", e)
	}
}

func TestNativeReadOnlyObservationRuntimeBudgetRefusesBeforeQueryOrRead(t *testing.T) {
	for _, kind := range []string{"read", "result", "handle"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			root, _ := nativeObservationFixture(t)
			s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{})
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if _, e = s.ObserveInventory(ctx, TreeLimits{}); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "read":
				s.limits.MaxReadBytes = s.read
			case "result":
				s.limits.MaxResultBytes = s.accounted
			case "handle":
				s.limits.MaxHandles = s.handles
			}
			if _, e = s.ReadOwnedAt(ctx, "known/file", "ads", make([]byte, 3), 0); !errors.Is(e, ErrTreeLimit) {
				t.Fatal(kind, e)
			}
			if len(s.entries["known/file"].streams) != 0 {
				t.Fatal("opened after exhausted budget")
			}
		})
	}
}

func nativeObservationPaths() []NativeObservationPath {
	return []NativeObservationPath{{Path: ".", Directory: true}, {Path: "known", Directory: true}, {Path: "known/file", DefaultSize: 17, Streams: []NativeObservationStream{{Name: "ads", Size: 3}}}}
}

func TestNativeObservationFirstBoundSurvivesFailedExportAndClose(t *testing.T) {
	for _, kind := range []string{"read", "scratch", "handles", "entries", "inventory-read", "metadata-buffer", "content-buffer", "export"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			root, _ := nativeObservationFixture(t)
			s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{})
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if _, e = s.ObserveInventory(ctx, TreeLimits{}); e != nil {
				t.Fatal(e)
			}
			before := s.read
			queries := 0
			original := s.queryDirectory
			s.queryDirectory = func(h windows.Handle, c uint32, b []byte) error { queries++; return original(h, c, b) }
			want := ""
			switch kind {
			case "read":
				s.limits.MaxReadBytes = s.read
				want = "read"
			case "scratch":
				s.limits.MaxResultBytes = s.accounted + nativeRootValidationScratch - 1
				want = "scratch"
			case "handles":
				s.limits.MaxHandles = s.handles
				want = "handles"
			case "entries":
				_, e = s.ObserveInventory(ctx, TreeLimits{MaxEntries: 1})
				want = "entries"
			case "inventory-read":
				_, e = s.ObserveInventory(ctx, TreeLimits{MaxReadBytes: 1})
				want = "read"
			case "metadata-buffer":
				_, e = s.Observe(ctx, "known/file", MetadataLimits{MaxBufferBytes: 128 << 10})
				want = "buffer"
			case "content-buffer":
				_, e = s.ReadOwnedAt(ctx, "known/file", "", make([]byte, 65537), 0)
				want = "buffer"
			case "export":
				_, e = s.Evidence(ctx, 0)
				want = "export"
			}
			if kind == "read" || kind == "scratch" || kind == "handles" {
				_, e = s.ReadOwnedAt(ctx, "known/file", "ads", make([]byte, 3), 0)
				if queries != 0 || s.read != before {
					t.Fatal("work after refusal", queries, s.read, before)
				}
			}
			if !errors.Is(e, ErrTreeLimit) {
				t.Fatal("missing refusal", e)
			}
			v := s.FailureSummary()
			if !v.FirstBound.Recorded || v.FirstBound.Dimension != want || v.FirstBound.Operation == "" || v.FirstBound.Site == "" || v.FirstBound.Requested <= v.FirstBound.Limit-min(v.FirstBound.Used, v.FirstBound.Limit) || v.LatchedObservationFailed != (kind != "export") || v.CloseAttempted {
				t.Fatal("missing precise first accounting refusal", v)
			}
			if _, e = s.Evidence(ctx, 0); !errors.Is(e, ErrTreeLimit) {
				t.Fatal(e)
			}
			s.Close()
			s.Close()
			closed := s.FailureSummary()
			if closed.FirstBound != v.FirstBound || !closed.CloseAttempted || closed.HandleCloseFailed || len(root.entries) != 0 {
				t.Fatal("history changed or handles/ledger misreported", v, closed, len(root.entries))
			}
		})
	}
}

// Catches fixture-ledger adoption, arbitrary/unknown reads, loss of held identity,
// and confusing handle Close with cleanup/release. These are ordinary fixtures,
// not WIMGAPI output or native invocation evidence.
func TestNativeReadOnlyObservationSeparatesEvidenceFromOwnership(t *testing.T) {
	ctx := context.Background()
	root, path := nativeObservationFixture(t)
	s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	v, e := s.ObserveInventory(ctx, TreeLimits{})
	if e != nil || !v.Complete || len(v.Entries) != 3 {
		t.Fatal(v, e)
	}
	if len(root.entries) != 0 {
		t.Fatal("observer adopted fixture ledger")
	}
	b := make([]byte, 32)
	n, e := s.ReadOwnedAt(ctx, "known/file", "", b, 0)
	if n != 17 || string(b[:n]) != "independent bytes" {
		t.Fatal(n, e, string(b[:n]))
	}
	n, e = s.ReadOwnedAt(ctx, "known/file", "ads", b, 0)
	if n != 3 || string(b[:n]) != "ADS" {
		t.Fatal(n, e, string(b[:n]))
	}
	for _, pair := range [][2]string{{"unknown", ""}, {"known/file", "foreign"}, {"../outside", ""}, {"known/file:ads", ""}} {
		if _, e = s.ReadOwnedAt(ctx, pair[0], pair[1], b, 0); e == nil {
			t.Fatal("arbitrary read", pair)
		}
	}
	o, e := s.Observe(ctx, "known/file", MetadataLimits{})
	if e != nil || o.Identity.FileIndex == 0 || o.ShortName.Status != "complete" {
		t.Fatal(o, e)
	}
	if e = s.Close(); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("Close claimed cleanup", e)
	}
	if e = s.Close(); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("unlatched Close", e)
	}
	if _, e = s.ReadOwnedAt(ctx, "known/file", "", b, 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(path, "known", "file")); e != nil {
		t.Fatal("observer deleted", e)
	}
}

func TestNativeReadOnlyObservationUnknownAndChangedNamesPreserve(t *testing.T) {
	ctx := context.Background()
	root, path := nativeObservationFixture(t)
	if e := os.Mkdir(filepath.Join(path, "foreign"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "foreign", "never-inspected"), []byte("foreign"), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	v, e := s.ObserveInventory(ctx, TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	if v.Complete {
		t.Fatal("unknown accepted")
	}
	for _, en := range v.Entries {
		if strings.Contains(en.Path, "never-inspected") {
			t.Fatal("unknown traversal", v)
		}
	}
	if e = os.Rename(filepath.Join(path, "known", "file"), filepath.Join(path, "known", "moved")); e == nil {
		if e = os.WriteFile(filepath.Join(path, "known", "file"), []byte("independent bytes"), 0600); e != nil {
			t.Fatal(e)
		}
		v, e = s.ObserveInventory(ctx, TreeLimits{})
		if e == nil && v.Complete {
			t.Fatal("replacement accepted", v)
		}
	}
}

func TestNativeReadOnlyObservationBoundsAndRevokedRoot(t *testing.T) {
	ctx := context.Background()
	root, _ := nativeObservationFixture(t)
	if s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{MaxHandles: len(root.parents) + 5}); s != nil || !errors.Is(e, ErrTreeLimit) {
		if s != nil {
			s.Close()
		}
		t.Fatal("root validation temporary handles omitted", e)
	}
	for _, l := range []NativeObservationLimits{{MaxEntries: 2}, {MaxDepth: 1}, {MaxHandles: 1}, {MaxStreams: 1}, {MaxReadBytes: 1}, {MaxResultBytes: 1}, {MaxExportBytes: 1}} {
		s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), l)
		if s != nil {
			s.Close()
		}
		if !errors.Is(e, ErrTreeLimit) {
			t.Fatal("preflight bound", l, e)
		}
	}
	for _, p := range [][]NativeObservationPath{{{Path: ".", Directory: true}, {Path: "../outside"}}, {{Path: ".", Directory: true}, {Path: "unknown/leaf"}}, {{Path: ".", Directory: true}, {Path: "same"}, {Path: "SAME"}}} {
		if s, e := BorrowNativeObservation(ctx, root, p, NativeObservationLimits{}); s != nil || e == nil {
			t.Fatal("unsafe descriptors", e)
		}
	}
	s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	root.Close()
	if e = s.CheckObservationLive(ctx); !errors.Is(e, os.ErrClosed) {
		t.Fatal("closed root usable", e)
	}
}

func TestNativeReadOnlyObservationSeparateProfileAndDescriptorCopies(t *testing.T) {
	paths := []NativeObservationPath{{Path: ".", Directory: true}}
	for j := 0; j < 5000; j++ {
		paths = append(paths, NativeObservationPath{Path: fmt.Sprintf("file-%05d", j)})
	}
	b, e := PreflightNativeObservation(paths, NativeObservationLimits{})
	if e != nil || b.Entries != 5001 {
		t.Fatal("separate read-only profile", b, e)
	}
	if _, e = treeBounds(TreeLimits{MaxEntries: 5001}); !errors.Is(e, ErrTreeLimit) {
		t.Fatal("fixture profile widened", e)
	}
	root, _ := nativeObservationFixture(t)
	paths = nativeObservationPaths()
	s, e := BorrowNativeObservation(context.Background(), root, paths, NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	paths[2].Path = "foreign"
	paths[2].Streams[0].Name = "foreign"
	v, e := s.ObserveInventory(context.Background(), TreeLimits{})
	if e != nil || !v.Complete {
		t.Fatal("caller mutation reached descriptors", v, e)
	}
	if _, e = s.ReadOwnedAt(context.Background(), "known/file", "ads", make([]byte, 3), 0); e != nil {
		t.Fatal(e)
	}
	v2, e := s.Evidence(context.Background(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	for j := range v2.Entries {
		if len(v2.Entries[j].Streams) > 0 {
			v2.Entries[j].Streams[0] = "mutated"
		}
	}
	v2, e = s.Evidence(context.Background(), 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	for _, en := range v2.Entries {
		for _, stream := range en.Streams {
			if stream == "mutated" {
				t.Fatal("mutable exported stream")
			}
		}
	}
}

func TestNativeReadOnlyObservationReusesReturnedMetadataScratch(t *testing.T) {
	ctx := context.Background()
	root, _ := nativeObservationFixture(t)
	s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{MaxResultBytes: 4 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.ObserveInventory(ctx, TreeLimits{}); e != nil {
		t.Fatal(e)
	}
	for j := 0; j < 400; j++ {
		if _, e = s.Observe(ctx, "known/file", MetadataLimits{}); e != nil {
			t.Fatalf("transient result reservation accumulated at %d: %v", j, e)
		}
	}
	if s.accounted > 1<<20 || s.scratch != 0 {
		t.Fatal("scratch retained", s.accounted, s.scratch)
	}
}

func TestNativeReadOnlyObservationReparseObjectNeverTraversesTarget(t *testing.T) {
	ctx := context.Background()
	root, rootPath := nativeObservationFixture(t)
	target := t.TempDir()
	if e := os.WriteFile(filepath.Join(target, "never-inspected"), []byte("outside"), 0600); e != nil {
		t.Fatal(e)
	}
	createJunction(t, filepath.Join(rootPath, "link"), target)
	paths := append(nativeObservationPaths(), NativeObservationPath{Path: "link", Directory: true, Reparse: true})
	s, e := BorrowNativeObservation(ctx, root, paths, NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	v, e := s.ObserveInventory(ctx, TreeLimits{})
	if e != nil || !v.Complete {
		t.Fatal(v, e)
	}
	for _, en := range v.Entries {
		if strings.Contains(en.Path, "never-inspected") {
			t.Fatal("followed reparse target", v)
		}
	}
	o, e := s.Observe(ctx, "link", MetadataLimits{})
	if e != nil || o.ReparseTag != windows.IO_REPARSE_TAG_MOUNT_POINT || len(o.Reparse.Raw) == 0 {
		t.Fatal("reparse object unavailable", o, e)
	}
	if _, e = s.ReadOwnedAt(ctx, "link", "", make([]byte, 1), 0); e == nil {
		t.Fatal("read reparse target")
	}
	if invalid, e := BorrowNativeObservation(ctx, root, append(paths, NativeObservationPath{Path: "link/never-inspected"}), NativeObservationLimits{}); invalid != nil || e == nil {
		t.Fatal("unsafe source ancestry", e)
	}
}

func TestNativeReadOnlyObservationRetainsKnownFailureIdentityAndCause(t *testing.T) {
	ctx := context.Background()
	root, _ := nativeObservationFixture(t)
	s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	v, e := s.ObserveInventory(ctx, TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	var expected FileIdentity
	for _, en := range v.Entries {
		if en.Path == "known/file" {
			expected = en.Identity
		}
	}
	if expected.FileIndex == 0 {
		t.Fatal(v)
	}
	s.info = func(f *os.File) (windows.ByHandleFileInformation, error) {
		if f == s.entries["known/file"].file {
			return windows.ByHandleFileInformation{}, windows.ERROR_ACCESS_DENIED
		}
		return nativeInfo(f)
	}
	v, e = s.ObserveInventory(ctx, TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	for _, en := range v.Entries {
		if en.Path == "known/file" {
			if en.RetainedIdentity != expected || en.NativeCode != uint32(windows.ERROR_ACCESS_DENIED) || en.Failure == "" || en.Status == "known" {
				t.Fatal("known failure lost", en)
			}
			return
		}
	}
	t.Fatal("known entry lost", v)
}

func TestNativeReadOnlyObservationPartialAcquisitionClosesAndRetainsCause(t *testing.T) {
	ctx := context.Background()
	root, _ := nativeObservationFixture(t)
	s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.info = func(f *os.File) (windows.ByHandleFileInformation, error) {
		if f.Name() == "file" {
			return windows.ByHandleFileInformation{}, windows.ERROR_ACCESS_DENIED
		}
		return nativeInfo(f)
	}
	v, e := s.ObserveInventory(ctx, TreeLimits{})
	if e != nil || v.Complete {
		t.Fatal(v, e)
	}
	f := s.entries["known/file"].file
	if e = s.Close(); !errors.Is(e, ErrTreePreserved) || !errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("partial acquisition cause lost", e)
	}
	if _, e = f.ReadAt(make([]byte, 1), 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("acquired handle leaked", e)
	}
	if s.handles != s.baseHandles {
		t.Fatal("unsettled session handles", s.handles, s.baseHandles)
	}
	if e = root.CheckObservationLive(ctx); e != nil {
		t.Fatal("borrowed root was closed", e)
	}
}

func TestNativeReadOnlyObservationExhaustedFailureEvidenceStillLatchesCloseCause(t *testing.T) {
	ctx := context.Background()
	root, _ := nativeObservationFixture(t)
	s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.ObserveInventory(ctx, TreeLimits{}); e != nil {
		t.Fatal(e)
	}
	s.limits.MaxResultBytes = s.accounted
	s.closeFile = func(f *os.File) error { return errors.Join(f.Close(), windows.ERROR_ACCESS_DENIED) }
	if e = s.Close(); !errors.Is(e, ErrTreeLimit) || !errors.Is(e, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("native close cause lost after budget exhaustion", e)
	}
	v, e := s.Evidence(ctx, 1<<20)
	if e != nil || !v.FailureEvidenceExhausted || v.TerminalFailure.Identity.FileIndex == 0 || v.TerminalFailure.NativeCode != 5 {
		t.Fatal(v, e)
	}
}

func TestNativeReadOnlyMetadataRejectsChangedReparseTypeBeforeVariableQueries(t *testing.T) {
	ctx := context.Background()
	root, _ := nativeObservationFixture(t)
	s, e := BorrowNativeObservation(ctx, root, nativeObservationPaths(), NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.ObserveInventory(ctx, TreeLimits{}); e != nil {
		t.Fatal(e)
	}
	entry := s.entries["known/file"]
	l, e := metadataBounds(MetadataLimits{})
	if e != nil {
		t.Fatal(e)
	}
	out, e := observeHeldMetadata(ctx, entry.file, entry.id, s.entries["known"].file, "file", l, true)
	if !errors.Is(e, ErrTreePreserved) || out.Identity != entry.id || out.ReadBytes != 0 {
		t.Fatal("unexpected type spent variable query capacity", out, e)
	}
}

// Catch accepting a profile that cannot fit the fixed metadata operation.
// The literal sufficient boundary is 18,444 retained bytes + 925,696 metadata
// scratch + 65,536 for the existing root recheck while metadata remains live.
func TestNativeReadOnlyObservationPreflightRequiresPlannedMetadataScratch(t *testing.T) {
	paths := []NativeObservationPath{{Path: ".", Directory: true}}
	for _, limit := range []uint64{160 << 10, 1_009_675} {
		if b, e := PreflightNativeObservation(paths, NativeObservationLimits{MaxResultBytes: limit}); !errors.Is(e, ErrTreeLimit) {
			t.Errorf("impossible fixed metadata profile accepted: limit=%d retained=%d error=%v", limit, b.AccountedBytes, e)
		}
	}
	const sufficient = uint64(1_009_676)
	if _, e := PreflightNativeObservation(paths, NativeObservationLimits{MaxResultBytes: sufficient}); e != nil {
		t.Fatal("just-sufficient profile refused", e)
	}
	ctx := context.Background()
	root, _ := nativeObservationFixture(t)
	s, e := BorrowNativeObservation(ctx, root, paths, NativeObservationLimits{MaxResultBytes: sufficient})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Observe(ctx, ".", MetadataLimits{}); e != nil {
		t.Fatal("just-sufficient profile cannot perform fixed metadata observation", e)
	}
	if s.scratch != 0 {
		t.Fatal("observation scratch retained", s.scratch)
	}
}

// Private-port stand-ins for already acquired root ADS handles isolate the
// close/accounting contract. This does not exercise the root ADS opener or
// authenticate an image result. The real read handles must all close once.
func TestNativeReadOnlyObservationRootStreamCloseExhaustionKeepsOnlyTerminalCause(t *testing.T) {
	ctx := context.Background()
	root, _ := nativeObservationFixture(t)
	paths := []NativeObservationPath{{Path: ".", Directory: true, Streams: []NativeObservationStream{{Name: "one", Size: 1}, {Name: "two", Size: 1}, {Name: "three", Size: 1}}}}
	s, e := BorrowNativeObservation(ctx, root, paths, NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	row := s.entries["."]
	names := map[*os.File]string{}
	causes := map[string]error{"one": windows.ERROR_INVALID_DATA, "two": windows.ERROR_SHARING_VIOLATION, "three": windows.ERROR_ACCESS_DENIED}
	for _, name := range []string{"one", "two", "three"} {
		filePath := filepath.Join(t.TempDir(), name)
		if e = os.WriteFile(filePath, []byte("x"), 0600); e != nil {
			t.Fatal(e)
		}
		f, e := os.Open(filePath)
		if e != nil {
			t.Fatal(e)
		}
		row.streams[name] = f
		row.streamOrder = append(row.streamOrder, name)
		s.handles++
		names[f] = name
	}
	accounted := s.accounted
	s.limits.MaxResultBytes = accounted
	var attempts []string
	s.closeFile = func(f *os.File) error {
		name := names[f]
		attempts = append(attempts, name)
		return errors.Join(f.Close(), causes[name])
	}
	closeErr := s.Close()
	if !errors.Is(closeErr, ErrTreePreserved) || !errors.Is(closeErr, ErrTreeLimit) || !errors.Is(closeErr, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("terminal close cause lost", closeErr)
	}
	if errors.Is(closeErr, windows.ERROR_SHARING_VIOLATION) || errors.Is(closeErr, windows.ERROR_INVALID_DATA) {
		t.Error("unreserved root close causes retained after exhaustion", closeErr)
	}
	if strings.Join(attempts, ",") != "three,two,one" || s.handles != s.baseHandles || s.accounted != accounted || len(s.failures) != 0 {
		t.Fatal("unbounded evidence or unsettled handles", attempts, s.handles, s.accounted, len(s.failures))
	}
	v, e := s.Evidence(ctx, 1<<20)
	if e != nil || !v.Closed || !v.Preserved || !v.Incomplete || !v.FailureEvidenceExhausted || v.TerminalFailure.Path != ".:three" || v.TerminalFailure.Identity != root.Identity().Root || v.TerminalFailure.NativeCode != 5 {
		t.Fatal("exact root terminal evidence lost", v, e)
	}
	if !strings.Contains(closeErr.Error(), root.Identity().RelativePath) || !strings.Contains(closeErr.Error(), fmt.Sprintf("volume=%d file=%d", row.id.VolumeSerial, row.id.FileIndex)) {
		t.Fatal("preserved root scope lost", closeErr)
	}
	for f := range names {
		if _, e = f.ReadAt(make([]byte, 1), 0); !errors.Is(e, os.ErrClosed) {
			t.Fatal("root stream handle leaked", e)
		}
	}
	if again := s.Close(); again != closeErr || len(attempts) != 3 {
		t.Fatal("Close was not idempotent", again, attempts)
	}
	if e = root.CheckObservationLive(ctx); e != nil {
		t.Fatal("borrowed root closed", e)
	}
}
