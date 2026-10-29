package cabindex

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"uupbuilder/internal/metadata/cabformat"
)

type faultyProvider struct {
	dataProvider
	mode   string
	calls  int
	scope  string
	cancel context.CancelFunc
}

func (p *faultyProvider) Extract(ctx context.Context, r io.ReaderAt, size uint64, table cabformat.Inventory, sink *memberSink, budget *runBudget) error {
	p.calls++
	p.scope = sink.store.store.Path()
	switch p.mode {
	case "no-op":
		return nil
	case "overrun":
		h, e := sink.begin(0)
		if e != nil {
			return e
		}
		_, e = sink.write(h, []byte("toolong"))
		return e
	case "short":
		h, e := sink.begin(0)
		if e != nil {
			return e
		}
		_, e = sink.write(h, []byte("x"))
		if e != nil {
			return e
		}
		return sink.end(h)
	case "wrong":
		h, e := sink.begin(0)
		if e != nil {
			return e
		}
		_, e = sink.write(h, []byte("zz"))
		if e != nil {
			return e
		}
		return sink.end(h)
	case "partial-batch":
		if p.calls == 2 {
			return errors.New("injected second-source failure")
		}
	case "cancel":
		h, e := sink.begin(0)
		if e != nil {
			return e
		}
		p.cancel()
		_, e = sink.write(h, []byte("xx"))
		return e
	case "changed-source":
		f := sink.source.resource
		if e := os.WriteFile(f.Path, bytes.Repeat([]byte("z"), int(f.Identity.Size)), 0600); e != nil {
			return e
		}
	case "conflict-size", "conflict-content":
		r := sink.state.References[0].Original
		sink.seen[r.SHA1] = fingerprint{sha256: "contradiction", size: 99}
		if p.mode == "conflict-content" {
			sink.seen[r.SHA1] = fingerprint{sha256: "contradiction", size: 2}
		}
	}
	e := p.dataProvider.Extract(ctx, r, size, table, sink, budget)
	if e == nil && p.mode == "extra-output" {
		f, err := os.OpenFile(filepath.Join(sink.store.store.Path(), "unexpected"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
	}
	if e == nil && p.mode == "changed-output" {
		a := (*sink.artifacts)[0]
		a.data.Close()
		if e := os.WriteFile(filepath.Join(sink.store.store.Path(), "member-00000001.data"), []byte("zz"), 0600); e != nil {
			return e
		}

	}
	return e
}
func (p *faultyProvider) Close() error {
	e := p.dataProvider.Close()
	if p.mode == "close-failure" {
		e = errors.Join(e, errors.New("injected provider close failure"))
	}
	return e
}
func TestFaultsNeverPublishAndRemovePartialOwnedOutputs(t *testing.T) {
	for _, mode := range []string{"no-op", "overrun", "short", "partial-batch", "cancel", "changed-source", "changed-output", "close-failure", "conflict-size", "conflict-content"} {
		t.Run(mode, func(t *testing.T) {
			b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
			m, fs, o := input(t, [][]byte{b, b}, [][]byte{[]byte("xx"), []byte("missing")})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var p *faultyProvider
			factory := func(ctx context.Context) (dataProvider, error) {
				base, e := openFDI(ctx)
				p = &faultyProvider{dataProvider: base, mode: mode, cancel: cancel}
				return p, e
			}
			r, e := build(ctx, m, fs, o, Limits{}, factory)
			if e == nil || r != nil {
				if r != nil {
					r.Close()
				}
				t.Fatal("fault published result", mode)
			}
			if p == nil || p.scope == "" {
				t.Fatal("failure path not reached")
			}
			if _, e := os.Stat(p.scope); !os.IsNotExist(e) {
				t.Fatalf("owned partial scope retained: %v", e)
			}
		})
	}
}
func TestWrongBytesCannotResolveOriginalHashAndNativeLimitsAreEnforced(t *testing.T) {
	b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, fs, o := input(t, [][]byte{b}, [][]byte{[]byte("xx")})
	factory := func(ctx context.Context) (dataProvider, error) {
		base, e := openFDI(ctx)
		return &faultyProvider{dataProvider: base, mode: "wrong"}, e
	}
	r, e := build(context.Background(), m, fs, o, Limits{}, factory)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	s := r.Catalog().Snapshot()
	if len(s.Witnesses) != 0 || len(s.Unresolved) != 1 || s.ReferenceClosure {
		t.Fatal("wrong output resolved a required hash")
	}
	for _, l := range []Limits{{MaxNativeBytes: 1}, {MaxNativeTotalBytes: 1}, {MaxProviderReadBytes: 1}, {MaxBufferBytes: 1}, {MaxDiskBytes: 1}} {
		r, e := Build(context.Background(), m, fs, o, l)
		if e == nil || r != nil {
			if r != nil {
				r.Close()
			}
			t.Fatalf("native/output lower limit bypassed %+v", l)
		}
	}
}
func TestSourceOrderAndClosureSkippedIdentityAreDeterministic(t *testing.T) {
	b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, fs, o := input(t, [][]byte{b, b}, [][]byte{[]byte("xx")})
	fs[0], fs[1] = fs[1], fs[0]
	for i, j := 0, len(m.Payloads)-1; i < j; i, j = i+1, j-1 {
		m.Payloads[i], m.Payloads[j] = m.Payloads[j], m.Payloads[i]
	}
	r, e := Build(context.Background(), m, fs, o, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	s := r.Catalog().Snapshot()
	if !s.ReferenceClosure || len(s.Witnesses) != 1 || s.Sources[0].Payload.Provenance.Name != "b.cab" || s.Sources[0].Status != "attempted" || s.Sources[1].Status != "closure-satisfied" {
		t.Fatalf("caller order changed canonical closure: %+v", s.Sources)
	}
}

func TestCopyBoundaryAndDiskBudgetPrecedeNativeCalls(t *testing.T) {
	b := cabinet([]string{"a"}, [][]byte{[]byte("xx")})
	m, fs, o := input(t, [][]byte{b}, [][]byte{[]byte("xx")})
	called := false
	factory := func(ctx context.Context) (dataProvider, error) { called = true; return openFDI(ctx) }
	if r, e := build(context.Background(), m, fs, o, Limits{MaxDiskBytes: 1}, factory); e == nil || r != nil || called {
		t.Fatal("disk refusal followed native construction", e, called)
	}
	original := fs[0].Identity
	factory = func(ctx context.Context) (dataProvider, error) {
		fs[0].Path = "caller mutation"
		fs[0].Identity.Provenance.Name = "mutated"
		m.Payloads[0].Identity.Provenance.Name = "mutated"
		return openFDI(ctx)
	}
	r, e := build(context.Background(), m, fs, o, Limits{}, factory)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	s := r.Catalog().Snapshot()
	if s.Witnesses[0].Payload != original {
		t.Fatal("caller aliases retained state")
	}
	s.References[0].Witnesses[0] = 999
	if r.Catalog().Snapshot().References[0].Witnesses[0] == 999 {
		t.Fatal("nested accessor alias")
	}
}

// The injected provider created this exact unexpected file. Production retains
// and reports it instead of recursively deleting an unowned directory tree.
func cleanTestRetainedScope(t *testing.T, path string) {
	t.Helper()
	root, e := os.OpenRoot(path)
	if os.IsNotExist(e) {
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"unexpected", ".uupbuilder-owner.json"} {
		if e := root.Remove(name); e != nil && !os.IsNotExist(e) {
			t.Error(e)
		}
	}
	root.Close()
	parent, e := os.OpenRoot(filepath.Dir(path))
	if e != nil {
		t.Fatal(e)
	}
	defer parent.Close()
	if e := parent.Remove(filepath.Base(path)); e != nil {
		t.Error(e)
	}
}
