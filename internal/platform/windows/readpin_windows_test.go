package windows

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceReadPinRetainsReadOnlyNonfollowCustody(t *testing.T) {
	for _, kind := range []string{"valid", "write", "delete", "rename-parent", "closed-owner", "junction", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			w, err := CreateWorkspace(t.TempDir(), "read-pin")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if err = w.MkdirAll("source"); err != nil {
				t.Fatal(err)
			}
			f, err := w.OpenFile("source/input", os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.WriteString("bytes")
			err2 := f.Close()
			if err != nil || err2 != nil {
				t.Fatal(err, err2)
			}
			name := "source/input"
			if kind == "junction" {
				createJunction(t, filepath.Join(w.Path(), "alias"), filepath.Join(w.Path(), "source"))
				name = "alias/input"
			}
			if kind == "hardlink" {
				if err = os.Link(filepath.Join(w.Path(), "source/input"), filepath.Join(w.Path(), "source/second")); err != nil {
					t.Fatal(err)
				}
			}
			p, err := w.OpenReadPin(name)
			if kind == "junction" || kind == "hardlink" {
				if err == nil {
					p.Close()
					t.Fatal("shared/reparse input admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			switch kind {
			case "write":
				f, err = os.OpenFile(filepath.Join(w.Path(), name), os.O_WRONLY, 0)
				if err == nil {
					f.Close()
					t.Fatal("pinned file permits writer")
				}
			case "delete":
				if err = os.Remove(filepath.Join(w.Path(), name)); err == nil {
					t.Fatal("pinned file permits delete")
				}
			case "rename-parent":
				if err = os.Rename(filepath.Join(w.Path(), "source"), filepath.Join(w.Path(), "moved")); err == nil {
					t.Fatal("pinned parent permits rename")
				}
			case "closed-owner":
				w.Close()
				if _, err = p.ReadAt(make([]byte, 1), 0); err == nil {
					t.Fatal("read through closed workspace")
				}
				return
			}
			b := make([]byte, 5)
			if n, err := p.ReadAt(b, 0); n != 5 || err != nil || string(b) != "bytes" {
				t.Fatal(n, err, string(b))
			}
		})
	}
}
