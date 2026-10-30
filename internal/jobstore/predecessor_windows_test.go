package jobstore

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func predecessorFixture(t *testing.T, ctx context.Context) (*Store, *Transaction, Checkpoint) {
	t.Helper()
	s, _ := newStore(t)
	cp := commitStage(t, s, intent("base"), "source bytes")
	in := intent("consume")
	in.Predecessors = []PredecessorIdentity{{StageID: "base", Digest: cp.Digest}}
	tx, err := s.Begin(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	return s, tx, cp
}

func TestPredecessorSharedAncestryChecksCachedRemainingHeight(t *testing.T) {
	s, _ := newStore(t)
	commit := func(stage string, predecessors ...PredecessorIdentity) Checkpoint {
		in := intent(stage)
		in.Predecessors = predecessors
		return commitStage(t, s, in, "x")
	}
	identity := func(c Checkpoint) PredecessorIdentity {
		return PredecessorIdentity{StageID: c.Intent.StageID, Digest: c.Digest}
	}
	// All nodes are actual committed, owned one-byte outputs. Sharing is first
	// visited shallowly because normalizeIntent orders predecessor digests.
	nodes := []Checkpoint{commit("shared-leaf")}
	for level := 1; level <= 63; level++ {
		threshold := ""
		if level == 62 {
			threshold = nodes[2].Digest
		} else if level == 63 {
			threshold = max(nodes[0].Digest, nodes[2].Digest)
		}
		var node Checkpoint
		for salt := 0; salt < 32; salt++ {
			node = commit(fmt.Sprintf("node-%d-%d", level, salt), identity(nodes[level-1]))
			if node.Digest > threshold {
				break
			}
		}
		if node.Digest <= threshold {
			t.Fatal("could not establish bounded shallow-first fixture ordering")
		}
		nodes = append(nodes, node)
	}
	leaf := commit("shared-leaf-overflow", identity(nodes[0]), identity(nodes[63]))
	tail := commit("shared-tail-overflow", identity(nodes[2]), identity(nodes[63]))
	valid := commit("shared-tail-boundary", identity(nodes[2]), identity(nodes[62]))
	for _, c := range []Checkpoint{leaf, tail, valid} {
		if c.Intent.Predecessors[0] != identity(nodes[0]) && c.Intent.Predecessors[0] != identity(nodes[2]) {
			t.Fatal("fixture did not visit shared tail first")
		}
	}
	in := intent("consume-shared")
	in.Predecessors = []PredecessorIdentity{identity(leaf), identity(tail), identity(valid)}
	tx, err := s.Begin(testContext, in)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		cp     Checkpoint
		refuse bool
	}{{"cached-leaf-at-depth64", leaf, true}, {"cached-nonleaf-tail-past64", tail, true}, {"shared-dag-exactly64", valid, false}} {
		t.Run(tc.name, func(t *testing.T) {
			verified := 0
			s.fail = func(point string) error {
				if point == "predecessor-before-verify" {
					verified++
				}
				return nil
			}
			r, err := tx.OpenPredecessor(testContext, identity(tc.cp), tc.cp.Outputs[0], 1024)
			s.fail = nil
			if tc.refuse {
				if r != nil {
					r.Close()
				}
				if !errors.Is(err, ErrPredecessorLimit) {
					t.Errorf("shared path past64 admitted: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 1)
				if n, e := r.ReadAt(b, 0); n != 1 || e != nil || string(b) != "x" {
					t.Fatal(n, e)
				}
				if verified != 64 {
					t.Errorf("shared DAG rewalked or omitted nodes: %d", verified)
				}
				if err = r.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if len(tx.readers) != 0 {
				t.Fatal("refusal/close retained borrower capacity")
			}
			// Every potentially acquired pin must unwind, including the shallow
			// cached subtree. Opening for write does not alter committed bytes.
			for _, c := range s.state.Checkpoints {
				for _, o := range c.Checkpoint.Outputs {
					f, e := s.w.OpenFile(o.Path, os.O_WRONLY, 0)
					if e != nil {
						t.Fatal("ancestry pin leaked after refusal/close", e)
					}
					if e = f.Close(); e != nil {
						t.Fatal(e)
					}
				}
			}
		})
	}
}

func TestPredecessorLiveBorrowerBoundReleasesCapacity(t *testing.T) {
	_, tx, cp := predecessorFixture(t, testContext)
	p := PredecessorIdentity{StageID: "base", Digest: cp.Digest}
	var readers []*PredecessorReader
	defer func() {
		for _, r := range readers {
			r.Close()
		}
	}()
	// Current canonical input producers allow64 simultaneous container files.
	for j := 0; j < 64; j++ {
		r, e := tx.OpenPredecessor(testContext, p, cp.Outputs[0], 4096)
		if e != nil {
			t.Fatalf("borrower %d refused within producer bound: %v", j, e)
		}
		readers = append(readers, r)
	}
	if r, e := tx.OpenPredecessor(testContext, p, cp.Outputs[0], 4096); e == nil {
		r.Close()
		t.Fatal("unbounded live borrower collection")
	}
	if e := readers[0].Close(); e != nil {
		t.Fatal(e)
	}
	r, e := tx.OpenPredecessor(testContext, p, cp.Outputs[0], 4096)
	if e != nil {
		t.Fatal("close did not release borrower capacity", e)
	}
	readers = append(readers, r)
}

func TestPredecessorCurrentSemanticBytesAndHeldAncestry(t *testing.T) {
	s, tx, cp := predecessorFixture(t, testContext)
	path := filepath.Join(s.Identity().Path, filepath.FromSlash(cp.Outputs[0].Path))
	name, _ := windows.UTF16PtrFromString(path)
	h, e := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		t.Fatal(e)
	}
	old := os.NewFile(uintptr(h), "old-semantic-fixture")
	defer old.Close()
	oldInfo, _ := old.Stat()
	if e = os.Rename(path, path+".before"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte("source bytes"), 0600); e != nil {
		t.Fatal(e)
	}
	newInfo, e := os.Stat(path)
	if e != nil || os.SameFile(oldInfo, newInfo) {
		t.Fatal("fixture did not replace file identity", e)
	}
	r, e := tx.OpenPredecessor(testContext, PredecessorIdentity{StageID: "base", Digest: cp.Digest}, cp.Outputs[0], 4096)
	if e != nil {
		t.Fatal("equal-byte pre-pin replacement must satisfy semantic checkpoint", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if e = old.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(path + ".before"); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(testContext, []OutputIdentity{writeOutput(t, tx, "image.wim", "child")}); e != nil {
		t.Fatal(e)
	}
	state, e := s.InspectRecovery(testContext, "job")
	if e != nil {
		t.Fatal(e)
	}
	child := state.Checkpoints[1].Checkpoint
	in := intent("next")
	in.Predecessors = []PredecessorIdentity{{StageID: "consume", Digest: child.Digest}}
	tx, e = s.Begin(testContext, in)
	if e != nil {
		t.Fatal(e)
	}
	r, e = tx.OpenPredecessor(testContext, in.Predecessors[0], child.Outputs[0], 4096)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte("changed"), 0600); e == nil {
		t.Fatal("borrowed ancestry remained mutable")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte("changed"), 0600); e != nil {
		t.Fatal(e)
	}
	if r, e = tx.OpenPredecessor(testContext, in.Predecessors[0], child.Outputs[0], 4096); e == nil {
		r.Close()
		t.Fatal("changed committed ancestry accepted")
	}
}

func TestPredecessorVerificationCancellationSettlesClose(t *testing.T) {
	s, tx, cp := predecessorFixture(t, testContext)
	ctx, cancel := context.WithCancel(testContext)
	defer cancel()
	entered, resume := make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(resume) })
	s.fail = func(point string) error {
		if point == "predecessor-before-verify" {
			close(entered)
			<-resume
		}
		return nil
	}
	opened := make(chan error, 1)
	go func() {
		r, e := tx.OpenPredecessor(ctx, PredecessorIdentity{StageID: "base", Digest: cp.Digest}, cp.Outputs[0], 4096)
		if r != nil {
			r.Close()
		}
		opened <- e
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("verification barrier not reached")
	}
	cancel()
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	release.Do(func() { close(resume) })
	if e := <-opened; !errors.Is(e, context.Canceled) {
		t.Fatal("verification cancellation lost", e)
	}
	if e := <-closed; e != nil {
		t.Fatal(e)
	}
}

func TestPredecessorReadSerializesWithOwnerEnd(t *testing.T) {
	for _, end := range []string{"commit", "discard", "store-close"} {
		t.Run(end, func(t *testing.T) {
			s, tx, cp := predecessorFixture(t, testContext)
			r, e := tx.OpenPredecessor(testContext, PredecessorIdentity{StageID: "base", Digest: cp.Digest}, cp.Outputs[0], 4096)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			var outputs []OutputIdentity
			if end == "commit" {
				outputs = []OutputIdentity{writeOutput(t, tx, "image.wim", "next")}
			}
			entered, resume := make(chan struct{}), make(chan struct{})
			var release sync.Once
			defer release.Do(func() { close(resume) })
			s.fail = func(point string) error {
				if point == "predecessor-after-read" {
					close(entered)
					<-resume
				}
				return nil
			}
			read := make(chan error, 1)
			go func() {
				b := make([]byte, 5)
				n, e := r.ReadAt(b, 0)
				if e == nil && (n != 5 || string(b) != "sourc") {
					e = errors.New("wrong pinned bytes")
				}
				read <- e
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("read barrier not reached")
			}
			finished := make(chan error, 1)
			go func() {
				switch end {
				case "commit":
					finished <- tx.Commit(testContext, outputs)
				case "discard":
					finished <- s.Discard(testContext, "job")
				default:
					finished <- s.Close()
				}
			}()
			select {
			case e := <-finished:
				t.Fatal("owner ended through active read", e)
			case <-time.After(10 * time.Millisecond):
			}
			release.Do(func() { close(resume) })
			if e := <-read; e != nil {
				t.Fatal(e)
			}
			if e := <-finished; e != nil {
				t.Fatal(e)
			}
			if n, e := r.ReadAt(make([]byte, 1), 0); e == nil || n != 0 {
				t.Fatal("read after owner end", n, e)
			}
		})
	}
}

func TestPredecessorIncrementalReadsUseOneExplicitByteAllowance(t *testing.T) {
	s, _ := newStore(t)
	body := strings.Repeat("x", 64<<10) + "tail"
	cp := commitStage(t, s, intent("base"), body)
	in := intent("consume")
	in.Predecessors = []PredecessorIdentity{{StageID: "base", Digest: cp.Digest}}
	tx, e := s.Begin(testContext, in)
	if e != nil {
		t.Fatal(e)
	}
	r, e := tx.OpenPredecessor(testContext, in.Predecessors[0], cp.Outputs[0], uint64(len(body)*2))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	b := make([]byte, len(body))
	if n, e := r.ReadAt(b, 0); n != len(b) || e != nil || string(b) != body {
		t.Fatal(n, e)
	}
	if _, e = r.ReadAt(b[:1], 0); !errors.Is(e, ErrPredecessorLimit) {
		t.Fatal("returned-byte allowance not enforced", e)
	}
}

func TestPredecessorReadsOnlyExactDeclaredCommittedOutput(t *testing.T) {
	for _, kind := range []string{"valid", "stage", "digest", "role", "size", "hash", "path", "traversal", "undeclared", "plan", "foreign-tx", "changed", "missing", "ancestry"} {
		t.Run(kind, func(t *testing.T) {
			s, tx, cp := predecessorFixture(t, testContext)
			p := PredecessorIdentity{StageID: "base", Digest: cp.Digest}
			out := cp.Outputs[0]
			switch kind {
			case "stage":
				p.StageID = "other"
			case "digest":
				p.Digest = digest("other")
			case "role":
				out.Role = "different"
			case "size":
				out.Size++
			case "hash":
				out.SHA256 = digest("other")
			case "path":
				out.Path = tx.scratch + "/image.wim"
			case "traversal":
				out.Path = "../image.wim"
			case "undeclared":
				tx.intent.Predecessors = nil
			case "plan":
				tx.intent.PlanDigest = digest("foreign plan")
			case "foreign-tx":
				copied := *tx
				tx = &copied
			case "changed":
				if err := os.WriteFile(filepath.Join(s.Identity().Path, filepath.FromSlash(out.Path)), []byte("changed bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(filepath.Join(s.Identity().Path, filepath.FromSlash(out.Path))); err != nil {
					t.Fatal(err)
				}
			case "ancestry":
				s.state.Checkpoints[0].Checkpoint.Intent.Predecessors = []PredecessorIdentity{{StageID: "absent", Digest: digest("absent")}}
			}
			r, err := tx.OpenPredecessor(testContext, p, out, 4096)
			if kind != "valid" {
				if err == nil {
					r.Close()
					t.Fatal("foreign, substituted or undeclared predecessor accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			b := make([]byte, 6)
			if n, err := r.ReadAt(b, 7); n != 5 || err != io.EOF || string(b[:n]) != "bytes" {
				t.Fatalf("bounded predecessor read %q %d %v", b, n, err)
			}
			if _, ok := any(r).(io.Writer); ok {
				t.Fatal("predecessor grants write authority")
			}
		})
	}
}

func TestPredecessorSubordinateLifetimeAndBudget(t *testing.T) {
	for _, kind := range []string{"reader-close", "store-close", "commit", "discard", "cancel-open", "cancel-owner", "budget", "zero-budget"} {
		t.Run(kind, func(t *testing.T) {
			owner, stopOwner := context.WithCancel(testContext)
			defer stopOwner()
			s, tx, cp := predecessorFixture(t, owner)
			ctx, cancel := context.WithCancel(testContext)
			defer cancel()
			allowance := uint64(4096)
			if kind == "budget" {
				allowance = 13
			}
			if kind == "zero-budget" {
				allowance = 0
			}
			r, err := tx.OpenPredecessor(ctx, PredecessorIdentity{StageID: "base", Digest: cp.Digest}, cp.Outputs[0], allowance)
			if kind == "zero-budget" {
				if err == nil {
					r.Close()
					t.Fatal("missing byte allowance accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			switch kind {
			case "reader-close":
				if err = r.Close(); err != nil {
					t.Fatal(err)
				}
			case "store-close":
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
			case "commit":
				if err = tx.Commit(testContext, []OutputIdentity{writeOutput(t, tx, "image.wim", "successor")}); err != nil {
					t.Fatal(err)
				}
			case "discard":
				if err = s.Discard(testContext, "job"); err != nil {
					t.Fatal(err)
				}
			case "cancel-open":
				cancel()
			case "cancel-owner":
				stopOwner()
			}
			b := make([]byte, 2)
			if n, err := r.ReadAt(b, 0); err == nil || n != 0 {
				t.Fatalf("read escaped lifetime/budget: %d %v", n, err)
			}
			if err := r.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}
