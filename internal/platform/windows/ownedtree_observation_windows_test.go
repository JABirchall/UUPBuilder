package windows

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedTreeActualInventoryAndHeldContentRefuseUnknownOrRevoked(t *testing.T) {
	ctx := context.Background()
	w, e := CreateWorkspace(t.TempDir(), "observation-fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	tr, e := w.CreateOwnedTree("tree", "fixture", "proof", TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer tr.Close() // File-containing fixture is deliberately preserved.
	if e = tr.CreateFile(ctx, "known", []byte("original")); e != nil {
		t.Fatal(e)
	}
	if e = tr.CreateNamedStream(ctx, "known", "ads", []byte("named")); e != nil {
		t.Fatal(e)
	}
	inv, e := tr.ObserveInventory(ctx, TreeLimits{})
	if e != nil || !inv.Complete || len(inv.Entries) != 2 || inv.Entries[1].Path != "known" {
		t.Fatal(inv, e)
	}
	b := make([]byte, 8)
	if n, e := tr.ReadOwnedAt(ctx, "known", "", b, 0); e != nil || n != 8 || !bytes.Equal(b, []byte("original")) {
		t.Fatal(n, e, b)
	}
	if n, e := tr.ReadOwnedAt(ctx, "known", "ads", b[:5], 0); e != nil || n != 5 || string(b[:5]) != "named" {
		t.Fatal(n, e, b)
	}
	if _, e = tr.ReadOwnedAt(ctx, "known", "foreign", b, 0); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("foreign stream reader", e)
	}
	if partial, err := tr.ObserveInventory(ctx, TreeLimits{MaxReadBytes: 1}); !errors.Is(err, ErrTreeLimit) || partial.Complete {
		t.Fatal("read budget bypass or incomplete inventory accepted", err, partial.Complete)
	}
	if partial, err := tr.ObserveInventory(ctx, TreeLimits{MaxReadBytes: 80 << 10}); !errors.Is(err, ErrTreeLimit) || partial.Complete {
		t.Fatal("exhausted residual published complete inventory", err, partial.Complete)
	}
	if _, e = tr.ObserveInventory(ctx, TreeLimits{MaxResultBytes: 1}); !errors.Is(e, ErrTreeLimit) {
		t.Fatal("result budget bypass", e)
	}
	if e = os.WriteFile(filepath.Join(w.Path(), "tree", "extra"), []byte("foreign"), 0600); e != nil {
		t.Fatal(e)
	}
	inv, e = tr.ObserveInventory(ctx, TreeLimits{})
	if e != nil || inv.Complete {
		t.Fatal("unknown namespace accepted", inv, e)
	}
	found := false
	for _, v := range inv.Entries {
		if v.Path == "extra" && v.Status == "unknown" {
			found = true
		}
	}
	if !found {
		t.Fatal("exact unknown witness missing", inv)
	}
	if _, e = tr.ReadOwnedAt(ctx, "extra", "", b, 0); !errors.Is(e, ErrTreePreserved) {
		t.Fatal("unknown entry read", e)
	}
	if e = tr.Close(); !errors.Is(e, ErrTreePreserved) {
		t.Fatal(e)
	}
	if _, e = tr.ObserveInventory(ctx, TreeLimits{}); e == nil {
		t.Fatal("closed inventory")
	}
	if _, e = tr.ReadOwnedAt(ctx, "known", "", b, 0); e == nil {
		t.Fatal("closed content")
	}
}

func TestOwnedTreeActualInventoryDistinguishesMissingChangedAndUnknownAlias(t *testing.T) {
	ctx := context.Background()
	w, e := CreateWorkspace(t.TempDir(), "alias-observation")
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	tr, e := w.CreateOwnedTree("tree", "fixture", "proof", TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	defer tr.Close()
	if e = tr.CreateFile(ctx, "original", []byte("same bytes")); e != nil {
		t.Fatal(e)
	}
	if e = tr.CreateHardlink(ctx, "original", "alias"); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(w.Path(), "tree")
	if e = os.Rename(filepath.Join(root, "alias"), filepath.Join(root, "escaped")); e != nil {
		t.Fatal(e)
	}
	inv, e := tr.ObserveInventory(ctx, TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	statuses := map[string]string{}
	for _, v := range inv.Entries {
		statuses[v.Path] = v.Status
	}
	if inv.Complete || statuses["alias"] != "missing" || statuses["escaped"] != "unknown" {
		t.Fatal(inv)
	}
	if e = os.WriteFile(filepath.Join(root, "alias"), []byte("same bytes"), 0600); e != nil {
		t.Fatal(e)
	}
	inv, e = tr.ObserveInventory(ctx, TreeLimits{})
	if e != nil {
		t.Fatal(e)
	}
	statuses = map[string]string{}
	for _, v := range inv.Entries {
		statuses[v.Path] = v.Status
	}
	if inv.Complete || statuses["alias"] != "changed" {
		t.Fatal("same bytes adopted replacement identity", inv)
	}
	for _, v := range inv.Entries {
		if v.Path == "alias" && (v.LedgerIdentity.FileIndex == 0 || v.Identity == v.LedgerIdentity) {
			t.Fatal("changed identity witness lost", v)
		}
	}
	if _, e = tr.ObserveInventory(ctx, TreeLimits{MaxEntries: 1}); !errors.Is(e, ErrTreeLimit) {
		t.Fatal("entry exhaustion", e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = tr.ObserveInventory(ctx, TreeLimits{}); e == nil {
		t.Fatal("closed workspace allowed inventory")
	}
}
