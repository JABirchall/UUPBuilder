package engine

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	platform "uupbuilder/internal/platform/windows"
)

func TestNativeTempConstructorRetainsOpenerFailureCustody(t *testing.T) {
	for _, stage := range []struct {
		name   string
		failAt int
	}{{"root-open", 1}, {"parent-open", 2}} {
		for _, closeFails := range []bool{false, true} {
			name := stage.name + "/close-ok"
			if closeFails {
				name = stage.name + "/close-error"
			}
			t.Run(name, func(t *testing.T) {
				openErr := errors.New("injected constructor opener failure")
				rootCloseErr := errors.New("injected extra-root close failure")
				workspaceCloseErr := errors.New("injected workspace close failure")
				var root *os.Root
				var workspace *platform.Workspace
				var path string
				var initial os.FileInfo
				var owner []byte
				opens, rootCloses, workspaceCloses := 0, 0, 0
				ops := nativeTempConstructorOps{
					openRoot: func(p string) (*os.Root, error) {
						opens++
						if opens == 1 {
							path = p
							var e error
							initial, e = os.Stat(path)
							if e != nil {
								t.Fatal(e)
							}
							owner, e = os.ReadFile(filepath.Join(path, ".uupbuilder-owner.json"))
							if e != nil {
								t.Fatal(e)
							}
							t.Cleanup(func() { removeNativeTempTestScope(t, path, initial, owner) })
						}
						if opens == stage.failAt {
							return nil, openErr
						}
						var e error
						root, e = os.OpenRoot(p)
						return root, e
					},
					closeRoot: func(r *os.Root) error {
						rootCloses++
						e := r.Close()
						if closeFails {
							e = errors.Join(e, rootCloseErr)
						}
						return e
					},
					closeWorkspace: func(w *platform.Workspace) error {
						workspaceCloses++
						workspace = w
						e := w.Close()
						if closeFails {
							e = errors.Join(e, workspaceCloseErr)
						}
						return e
					},
				}
				cache, e := newNativeTempWith(ops)
				if cache != nil || !errors.Is(e, openErr) {
					t.Fatalf("constructor accepted failed opener: %v", e)
				}
				if !strings.Contains(e.Error(), "native cache preserved") || !strings.Contains(e.Error(), path) || !strings.Contains(e.Error(), "scope="+filepath.Base(path)) {
					t.Fatalf("constructor lost generated scope identity: %v", e)
				}
				if opens != stage.failAt || workspaceCloses != 1 || rootCloses != stage.failAt-1 || workspace == nil {
					t.Fatalf("constructor lost handle custody: opens=%d workspace-closes=%d root-closes=%d", opens, workspaceCloses, rootCloses)
				}
				if closeFails && (!errors.Is(e, workspaceCloseErr) || (root != nil && !errors.Is(e, rootCloseErr))) {
					t.Fatalf("constructor dropped close failure: %v", e)
				}
				if _, e = workspace.OpenFile("not-created", os.O_RDONLY, 0); !errors.Is(e, os.ErrClosed) {
					t.Fatalf("workspace handle survived failed constructor: %v", e)
				}
				if root != nil {
					if _, e = root.Stat("."); !errors.Is(e, os.ErrClosed) {
						t.Fatalf("extra root survived failed constructor: %v", e)
					}
				}
				now, e := os.Stat(path)
				if e != nil || !os.SameFile(initial, now) {
					t.Fatalf("preserved scope identity changed: %v", e)
				}
				got, e := os.ReadFile(filepath.Join(path, ".uupbuilder-owner.json"))
				if e != nil || !bytes.Equal(got, owner) {
					t.Fatalf("preserved owner changed: %v", e)
				}
			})
		}
	}
}

// Remove only the exact fresh test-created flat scope. Unknown/replaced entries
// remain preserved; no recursive deletion or adoption is used in the test.
func removeNativeTempTestScope(t *testing.T, path string, initial os.FileInfo, owner []byte) {
	t.Helper()
	r, e := os.OpenRoot(path)
	if e != nil {
		t.Error(e)
		return
	}
	defer r.Close()
	info, e := r.Stat(".")
	if e != nil || !os.SameFile(initial, info) {
		t.Errorf("test scope custody changed: %v", e)
		return
	}
	f, e := r.Open(".")
	if e != nil {
		t.Error(e)
		return
	}
	entries, re := f.ReadDir(2)
	re = errors.Join(re, f.Close())
	if re != nil && re != io.EOF || len(entries) != 1 || entries[0].Name() != ".uupbuilder-owner.json" {
		t.Errorf("unknown test scope entry preserved: %v", re)
		return
	}
	marker, e := r.ReadFile(".uupbuilder-owner.json")
	if e != nil || !bytes.Equal(marker, owner) {
		t.Errorf("test owner changed: %v", e)
		return
	}
	if e = r.Remove(".uupbuilder-owner.json"); e != nil {
		t.Error(e)
		return
	}
	if e = r.Close(); e != nil {
		t.Error(e)
		return
	}
	p, e := os.OpenRoot(filepath.Dir(path))
	if e != nil {
		t.Error(e)
		return
	}
	defer p.Close()
	info, e = p.Stat(filepath.Base(path))
	if e != nil || !os.SameFile(initial, info) {
		t.Errorf("named test scope changed: %v", e)
		return
	}
	if e = p.Remove(filepath.Base(path)); e != nil {
		t.Error(e)
	}
}
