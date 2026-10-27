//go:build windows

package jobstore

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestRecoveryNativeMountInventory(t *testing.T) {
	// A real read-only call, with no image session, elevation, or mount action.
	snapshot, err := (nativeMountInspector{}).Inspect(context.Background(), t.TempDir())
	if err != nil {
		if snapshot.Complete {
			t.Fatal("failed native inventory claimed completion")
		}
		t.Logf("native inventory explicitly unavailable: %v", err)
		return
	}
	if !snapshot.Complete {
		t.Fatal("successful native inventory was incomplete")
	}
	t.Logf("native inventory completed: %d OS records", len(snapshot.Mounts))
}

func TestRecoveryDefaultInspectorIsConcreteAndFailClosed(t *testing.T) {
	s, err := Create(t.TempDir(), "job", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok := s.inspector.(nativeMountInspector); !ok {
		t.Fatal("default inspector is not the OS inventory")
	}
	r, err := s.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.Begin(testContext, intent("native"))
	if err != nil {
		t.Fatal(err)
	}
	out := writeOutput(t, tx, "image.wim", "plain owned test bytes")
	err = tx.Commit(testContext, []OutputIdentity{out})
	if !r.CanResume {
		if err == nil {
			t.Fatal("default unknown OS inventory authorized promotion")
		}
		if err := s.Discard(testContext, "job"); err == nil {
			t.Fatal("default unknown OS inventory authorized discard")
		}
		t.Logf("default inspector preserved unknown state: %s", r.Preserved[0].Reason)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryNativeMountABIBounds(t *testing.T) {
	want := uintptr(32)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		want = 20
	}
	if unsafe.Sizeof(dismMountedImageInfo{}) != want {
		t.Fatal("DISM mounted-image structure has the wrong process ABI size")
	}
	if _, err := nativeWideString(nil); err == nil {
		t.Fatal("nil native string accepted")
	}
	zero := uint16(0)
	if _, err := nativeWideString(&zero); err == nil {
		t.Fatal("empty native path accepted")
	}
	text, _ := windows.UTF16FromString(`C:\owned\日本語`)
	if got, err := nativeWideString(&text[0]); err != nil || got != `C:\owned\日本語` {
		t.Fatalf("native path decoding: %q %v", got, err)
	}
	long := make([]uint16, 32768)
	for i := range long {
		long[i] = 'x'
	}
	if _, err := nativeWideString(&long[0]); err == nil {
		t.Fatal("unbounded native path accepted")
	}
}

func TestRecoveryRejectsReparseAndUnknownEntries(t *testing.T) {
	for _, kind := range []string{"unknown-file", "junction", "shared-link"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := newStore(t)
			cp := commitStage(t, s, intent("base"), "pristine")
			outside := t.TempDir()
			sentinel := filepath.Join(outside, "keep.txt")
			if err := os.WriteFile(sentinel, []byte("external"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.Identity().Path, "unresolved")
			switch kind {
			case "unknown-file":
				if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "shared-link":
				if err := os.Link(sentinel, path); err != nil {
					t.Fatal(err)
				}
			case "junction":
				jobstoreJunction(t, path, outside)
			}
			r, err := s.InspectRecovery(testContext, "job")
			if err != nil {
				t.Fatal(err)
			}
			if r.CanResume || len(r.Preserved) == 0 {
				t.Fatal("unresolved real entry was hidden")
			}
			if err := s.Discard(testContext, "job"); err == nil {
				t.Fatal("discard removed unresolved entry")
			}
			if readOwned(t, s, cp.Outputs[0].Path) != "pristine" {
				t.Fatal("unsafe discard partly removed known output")
			}
			b, err := os.ReadFile(sentinel)
			if err != nil || string(b) != "external" {
				t.Fatalf("external source changed: %q %v", b, err)
			}
		})
	}
}

// An unprivileged junction fixture, never an image mount or security change.
func jobstoreJunction(t *testing.T, path, target string) {
	t.Helper()
	p, _ := windows.UTF16PtrFromString(path)
	if err := windows.CreateDirectory(p, nil); err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	sub := utf16.Encode([]rune(`\??\` + target))
	printName := utf16.Encode([]rune(target))
	data := make([]byte, 16+2*(len(sub)+1+len(printName)+1))
	binary.LittleEndian.PutUint32(data, windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(data[4:], uint16(len(data)-8))
	binary.LittleEndian.PutUint16(data[10:], uint16(2*len(sub)))
	binary.LittleEndian.PutUint16(data[12:], uint16(2*(len(sub)+1)))
	binary.LittleEndian.PutUint16(data[14:], uint16(2*len(printName)))
	buf := unsafe.Slice((*uint16)(unsafe.Pointer(&data[16])), (len(data)-16)/2)
	copy(buf, sub)
	copy(buf[len(sub)+1:], printName)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &data[0], uint32(len(data)), nil, 0, &n, nil); err != nil {
		t.Fatal(err)
	}
}
