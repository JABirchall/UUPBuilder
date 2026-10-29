package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"uupbuilder/internal/jobstore"
	platform "uupbuilder/internal/platform/windows"
)

type applyTestPrivilege struct {
	active   bool
	closed   int
	closeErr error
}

func (p *applyTestPrivilege) CheckActive() error {
	if !p.active {
		return platform.ErrPrivilegeRequirement
	}
	return nil
}
func (p *applyTestPrivilege) Close() error { p.active = false; p.closed++; return p.closeErr }

func applyTestBinding(t *testing.T) (*fixedApplyBinding, *jobstore.Store) {
	t.Helper()
	ctx := context.Background()
	p, _ := expectationFixture(t, true)
	x, e := BindSourceExpectations(ctx, p, ComparisonLimits{})
	if e != nil {
		t.Fatal(e)
	}
	s, e := jobstore.Create(t.TempDir(), "fixture", preservationInventory{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	id := platform.DLLIdentity{Name: "wimgapi.dll", SHA256: strings.Repeat("a", 64), Size: 123}
	tx, e := s.Begin(ctx, fixedApplyIntent(p, id, "fixture"))
	if e != nil {
		t.Fatal(e)
	}
	d, c, e := tx.ClaimFixedSourceApplyDirectories(ctx, p.state.Digest)
	if e != nil {
		t.Fatal(e)
	}
	b, e := bindFixedApply(ctx, p, x, d, c, id, platform.NativeObservationLimits{})
	if e != nil {
		t.Fatal(e)
	}
	return b, s
}

func applyTestPorts(b *fixedApplyBinding, order *[]string) *fixedApplyPorts {
	add := func(s string) { *order = append(*order, s) }
	return &fixedApplyPorts{id: b.provider, check: func() error { return nil },
		open: func(path string) (uintptr, error) {
			add("open")
			if path != filepath.Join(b.proof.artifact.store.Path(), b.proof.artifact.name) {
				return 0, ErrInput
			}
			return 11, nil
		},
		temporary: func(h uintptr, path string) error {
			add("temporary")
			if h != 11 || path != claimApplyPath(b.cache) {
				return ErrInput
			}
			return nil
		},
		load: func(h uintptr, index uint32) (uintptr, error) {
			add("load")
			if h != 11 || index != 1 {
				return 0, ErrInput
			}
			return 22, nil
		},
		register: func(h, token uintptr) (uint32, error) {
			add("register")
			if h != 11 || token == 0 {
				return 0, ErrInput
			}
			return 0, nil
		},
		apply: func(request *fixedApplyBinding, h uintptr, flags uint32) (*nativeApplyCompletion, error) {
			add("apply")
			if request != b || h != 22 || flags != 0x182 {
				return nil, ErrInput
			}
			return nil, nil
		},
		unregister: func(h uintptr) error {
			add("unregister")
			if h != 11 {
				return ErrInput
			}
			return nil
		},
		closeHandle: func(h uintptr) error {
			if h == 22 {
				add("close-image")
			} else if h == 11 {
				add("close-wim")
			} else {
				return ErrInput
			}
			return nil
		},
		modules: func(context.Context) ([]ModuleIdentity, error) {
			add("modules")
			return []ModuleIdentity{{Name: "synthetic-operation-module"}}, nil
		},
		closeProvider: func() error { add("close-provider"); return nil },
	}
}

// A synthetic native return is diagnostic only. It must not manufacture a live
// observed result, even at progress100; the independent real comparison runs.
func TestFixedApplyRejectsSyntheticCompletionAndPreservesScopes(t *testing.T) {
	b, _ := applyTestBinding(t)
	var order []string
	n := applyTestPorts(b, &order)
	h := &applyCallbackHub{}
	priv := &applyTestPrivilege{active: true}
	n.apply = func(request *fixedApplyBinding, image uintptr, flags uint32) (*nativeApplyCompletion, error) {
		order = append(order, "apply")
		if request != b || image != 22 || flags != 0x182 {
			t.Fatal("fixed apply substituted", image, flags)
		}
		h.deliver(h.current.token, 0x9478, 100, 0)
		return &nativeApplyCompletion{}, nil // Unauthenticated caller completion.
	}
	r, e := executeFixedApply(context.Background(), b, n, priv, h)
	if e == nil || r == nil || r.result != nil || !r.evidence.Started || !r.evidence.Returned {
		t.Fatal("synthetic completion accepted", e)
	}
	if !slices.Equal(order[:6], []string{"open", "temporary", "load", "register", "apply", "modules"}) {
		t.Fatal(order)
	}
	if e = r.Close(); !errors.Is(e, platform.ErrTreePreserved) || priv.closed != 1 {
		t.Fatal("preservation omitted", e, priv.closed)
	}
	if !slices.Equal(order[len(order)-4:], []string{"unregister", "close-image", "close-wim", "close-provider"}) {
		t.Fatal(order)
	}
	if e = r.Close(); !errors.Is(e, platform.ErrTreePreserved) || priv.closed != 1 {
		t.Fatal("close not latched", e)
	}
	if e = b.destination.CheckLive(context.Background()); e != nil {
		t.Fatal("borrowed claim released", e)
	}
}

func TestFixedApplyCancellationWaitsForActualReturn(t *testing.T) {
	b, _ := applyTestBinding(t)
	var order []string
	n := applyTestPorts(b, &order)
	h := &applyCallbackHub{}
	ctx, cancel := context.WithCancel(context.Background())
	started, release := make(chan struct{}), make(chan struct{})
	priv := &applyTestPrivilege{active: true}
	n.apply = func(*fixedApplyBinding, uintptr, uint32) (*nativeApplyCompletion, error) {
		close(started)
		<-release
		if ret := h.deliver(h.current.token, 0x948e, 0, 0); ret != 0xffffffff {
			t.Error("cancel not delivered", ret)
		}
		return nil, errors.New("actual synthetic native return")
	}
	done := make(chan *fixedApplyRun, 1)
	go func() { r, _ := executeFixedApply(ctx, b, n, priv, h); done <- r }()
	<-started
	cancel()
	select {
	case <-done:
		t.Fatal("cancellation declared completion")
	case <-time.After(15 * time.Millisecond):
	}
	if priv.closed != 0 || slices.Contains(order, "close-image") {
		t.Fatal("lifetime released before actual return")
	}
	close(release)
	r := <-done
	if r.result != nil || !r.evidence.Returned || !r.evidence.Callback.AbortDelivered || !errors.Is(r.runErr, context.Canceled) {
		t.Fatal(r.evidence, r.runErr)
	}
	r.Close()
}

func TestFixedApplyRejectsChangedBindingsBeforeNativeCall(t *testing.T) {
	for _, kind := range []string{"zero", "proof", "foreign-expectation", "same-root", "closed-claim", "closed-source", "output", "provider", "profile", "intent", "preexisting", "privilege", "read-budget"} {
		t.Run(kind, func(t *testing.T) {
			b, s := applyTestBinding(t)
			var order []string
			n := applyTestPorts(b, &order)
			priv := &applyTestPrivilege{active: true}
			switch kind {
			case "zero":
				b = &fixedApplyBinding{}
			case "proof":
				b.proof = &PreservationProof{}
			case "foreign-expectation":
				p, _ := expectationFixture(t, true)
				b.expected, _ = BindSourceExpectations(context.Background(), p, ComparisonLimits{})
			case "same-root":
				b.cache = b.destination
			case "closed-claim":
				s.Close()
			case "closed-source":
				b.proof.artifact.Close()
			case "output":
				f, e := os.OpenFile(filepath.Join(b.proof.artifact.store.Path(), b.proof.artifact.name), os.O_WRONLY, 0)
				if e != nil {
					t.Log("native sharing prevented mutation", e)
					b.proof.artifact.Close()
				} else {
					f.WriteAt([]byte("X"), 0)
					f.Close()
				}
			case "provider":
				n.id.SHA256 = strings.Repeat("b", 64)
			case "profile":
				b.policy = "foreign"
			case "intent":
				b.intent = "foreign"
			case "preexisting":
				os.WriteFile(filepath.Join(claimApplyPath(b.destination), "unknown"), []byte("foreign"), 0600)
			case "privilege":
				priv.active = false
			case "read-budget":
				b.maxSourceRead = 1
			}
			r, e := executeFixedApply(context.Background(), b, n, priv, &applyCallbackHub{})
			if e == nil || slices.Contains(order, "open") || r != nil && r.evidence.Started {
				t.Fatal("invalid binding reached native", e, order)
			}
			if r != nil {
				r.Close()
			}
		})
	}
}

func TestFixedApplyNativeFailuresNeverBecomeObservation(t *testing.T) {
	for _, step := range []string{"open", "temporary", "load", "register", "apply", "modules", "unregister", "close-image", "close-wim", "privilege-close", "provider-close"} {
		t.Run(step, func(t *testing.T) {
			b, _ := applyTestBinding(t)
			var order []string
			n := applyTestPorts(b, &order)
			boom := errors.New(step)
			priv := &applyTestPrivilege{active: true}
			h := &applyCallbackHub{}
			switch step {
			case "open":
				n.open = func(string) (uintptr, error) { return 0, boom }
			case "temporary":
				n.temporary = func(uintptr, string) error { return boom }
			case "load":
				n.load = func(uintptr, uint32) (uintptr, error) { return 0, boom }
			case "register":
				n.register = func(uintptr, uintptr) (uint32, error) { return 0, boom }
			case "apply":
				n.apply = func(*fixedApplyBinding, uintptr, uint32) (*nativeApplyCompletion, error) {
					h.deliver(h.current.token, 0x9478, 100, 0)
					return nil, boom
				}
			case "modules":
				n.modules = func(context.Context) ([]ModuleIdentity, error) { return nil, boom }
			case "unregister":
				n.unregister = func(uintptr) error { return boom }
			case "close-image", "close-wim":
				base := n.closeHandle
				n.closeHandle = func(v uintptr) error {
					if step == "close-image" && v == 22 || step == "close-wim" && v == 11 {
						return boom
					}
					return base(v)
				}
			case "privilege-close":
				priv.closeErr = boom
			case "provider-close":
				n.closeProvider = func() error { return boom }
			}
			r, err := executeFixedApply(context.Background(), b, n, priv, h)
			if r == nil {
				t.Fatal("missing preserved owner", err)
			}
			closeErr := r.Close()
			if !errors.Is(errors.Join(err, closeErr), boom) || r.result != nil || !errors.Is(closeErr, platform.ErrTreePreserved) {
				t.Fatal("native failure lost", err, closeErr)
			}
			if step == "unregister" && (priv.closed != 0 || slices.Contains(order, "close-image") || slices.Contains(order, "close-provider")) {
				t.Fatal("unsettled registration released lifetimes", order)
			}
			outcomes := map[string]applyOperationOutcome{"apply": r.evidence.NativeReturn, "modules": r.evidence.ModuleObservation, "unregister": r.evidence.Unregister, "close-image": r.evidence.ImageClose, "close-wim": r.evidence.WIMClose, "privilege-close": r.evidence.PrivilegeClose, "provider-close": r.evidence.ProviderClose}
			if outcome, ok := outcomes[step]; ok && (!outcome.Attempted || !outcome.Failed) {
				t.Fatal("owning operation failure evidence lost", step, outcome)
			}
		})
	}
}

func TestFixedApplyPreflightReservesExecutorAndRejectsExhaustion(t *testing.T) {
	for _, kind := range []string{"result", "entry", "handle", "read", "export", "valid"} {
		t.Run(kind, func(t *testing.T) {
			b, _ := applyTestBinding(t)
			switch kind {
			case "result":
				b.profile.MaxResultBytes = 8 << 20
			case "entry":
				b.profile.MaxEntries = 1
			case "handle":
				b.profile.MaxHandles = 1
			case "read":
				b.profile.MaxReadBytes = 1
			case "export":
				b.profile.MaxExportBytes = 1
			}
			e := prepareFixedApplyObservation(context.Background(), b)
			if kind == "valid" {
				if e != nil || b.prepared == nil || b.preflight.Entries != 11 {
					t.Fatal(e, b.preflight)
				}
				b.prepared.Close()
				return
			}
			if e == nil || !errors.Is(e, platform.ErrTreeLimit) && !errors.Is(e, ErrLimit) {
				t.Fatal("preflight exhaustion accepted", kind, e)
			}
		})
	}
}

func TestObservedSourceContractRejectsCounterfeitCompletionAndComparison(t *testing.T) {
	if e := (&ObservedSourceContractResult{}).CheckLive(context.Background()); e == nil {
		t.Fatal("zero result accepted")
	}
	b, _ := applyTestBinding(t)
	var order []string
	n := applyTestPorts(b, &order)
	h := &applyCallbackHub{}
	r, e := invokeFixedApply(context.Background(), b, n, &applyTestPrivilege{active: true}, h)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	// Explicit synthetic negative: caller-declared complete comparison data
	// cannot replace the installed private native completion boundary.
	c := &PreservationComparison{expected: b.expected, port: r.observer, state: ComparisonEvidence{Source: b.expected.state, Destination: b.destinationID, Complete: true}}
	r.comparison = c
	r.evidence.NativeHandlesClosed = true
	r.evidence.Synthetic = false // More counterfeit caller assertions, still no native seal.
	if o, e := mintObservedSourceContract(r, c); e == nil || o != nil {
		t.Fatal("caller completion/comparison data minted authority", e)
	}
	if _, e = h.begin(context.Background(), claimApplyPath(b.destination), map[string]bool{".": true}, applyCallbackLimits{}); e == nil {
		t.Fatal("native lifetime slot reused during inspection")
	}
}

func TestFixedApplyPartialOutputPreservesBothClaims(t *testing.T) {
	b, _ := applyTestBinding(t)
	var order []string
	n := applyTestPorts(b, &order)
	boom := errors.New("partial synthetic apply")
	destName := filepath.Join(claimApplyPath(b.destination), "unexplained")
	cacheName := filepath.Join(claimApplyPath(b.cache), "native-cache")
	n.apply = func(*fixedApplyBinding, uintptr, uint32) (*nativeApplyCompletion, error) {
		if e := os.WriteFile(destName, []byte("partial result"), 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(cacheName, []byte("native cache"), 0600); e != nil {
			t.Fatal(e)
		}
		return nil, boom
	}
	r, e := executeFixedApply(context.Background(), b, n, &applyTestPrivilege{active: true}, &applyCallbackHub{})
	if !errors.Is(e, boom) || r.result != nil {
		t.Fatal(e)
	}
	if e = r.Close(); !errors.Is(e, boom) || !errors.Is(e, platform.ErrTreePreserved) {
		t.Fatal(e)
	}
	for _, name := range []string{destName, cacheName} {
		if _, e = os.Stat(name); e != nil {
			t.Fatal("partial native data removed", e)
		}
	}
	if len(r.evidence.Preserved) != 2 || len(r.evidence.CacheInventory.Entries) != 2 || r.evidence.CacheInventory.Complete {
		t.Fatal("native cache ownership invented", r.evidence)
	}
	if e = errors.Join(b.destination.CheckLive(context.Background()), b.cache.CheckLive(context.Background())); e != nil {
		t.Fatal("durable unresolved claim lost", e)
	}
	if _, e = serializeFixedTrialObserver(context.Background(), r.observer.session, 1); !errors.Is(e, ErrLimit) {
		t.Fatal("export exhaustion accepted", e)
	}
	if v, e := serializeFixedTrialObserver(context.Background(), r.observer.session, 1<<20); e != nil || len(v) == 0 {
		t.Fatal("bounded historical observer export missing", e)
	}
}

func TestFixedApplyDuplicateRunCannotTakeActiveNativeLifetimes(t *testing.T) {
	b, _ := applyTestBinding(t)
	var order []string
	n := applyTestPorts(b, &order)
	h := &applyCallbackHub{}
	priv := &applyTestPrivilege{active: true}
	started, finish := make(chan struct{}), make(chan struct{})
	defer close(finish)
	n.apply = func(*fixedApplyBinding, uintptr, uint32) (*nativeApplyCompletion, error) {
		close(started)
		<-finish
		return nil, errors.New("returned")
	}
	done := make(chan *fixedApplyRun, 1)
	go func() { r, _ := executeFixedApply(context.Background(), b, n, priv, h); done <- r }()
	<-started
	duplicate, e := executeFixedApply(context.Background(), b, n, priv, h)
	if e == nil || duplicate != nil {
		t.Errorf("duplicate invocation acquired live provider/privilege ownership: run=%v error=%v", duplicate != nil, e)
	}
	if priv.closed != 0 || slices.Contains(order, "close-provider") {
		t.Error("active native lifetime released")
	}
	// finish is closed by defer, then settle the original owner in a cleanup.
	t.Cleanup(func() { r := <-done; r.Close() })
}
