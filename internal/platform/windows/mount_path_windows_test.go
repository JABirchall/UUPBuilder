package windows

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func nativeMountAlias(t *testing.T, path string) string {
	t.Helper()
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 32768)
	n, err := windows.GetShortPathName(wide, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || n >= uint32(len(buffer)) {
		t.Fatalf("native alias lookup: length=%d error=%v", n, err)
	}
	return windows.UTF16ToString(buffer[:n])
}

func TestShortMountPathRejectsUnshortenableNativePathAtWin32Boundary(t *testing.T) {
	for _, target := range []int{259, 260, 300} {
		t.Run(strconv.Itoa(target), func(t *testing.T) {
			w, err := CreateWorkspace(t.TempDir(), "mount-path-boundary")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			base := strings.TrimPrefix(nativeMountAlias(t, w.Path()), `\\?\`)
			remaining := target - len(utf16.Encode([]rune(base))) - 1
			if remaining < 3 {
				t.Fatalf("test's native parent is already too long: %s", base)
			}
			// These short component names have no shorter 8.3 spelling, even when
			// the volume shortens ancestors. No system 8.3 policy is modified.
			relative := strings.Repeat("d/", (remaining-1)/2) + strings.Repeat("d", 1+(remaining-1)%2)
			if err := w.MkdirAll(filepath.ToSlash(filepath.Dir(relative))); err != nil {
				t.Fatal(err)
			}
			mount, err := w.ClaimMount(relative, "service-image")
			if err != nil {
				t.Fatal(err)
			}
			original := filepath.Join(w.Path(), filepath.FromSlash(mount.RelativePath))
			alias := nativeMountAlias(t, original)
			if nativeMountAlias(t, alias) != alias {
				t.Fatal("fixture's native result could still be shortened")
			}
			ordinary := strings.TrimPrefix(alias, `\\?\`)
			if got := len(utf16.Encode([]rune(ordinary))); got != target {
				t.Fatalf("native fixture has %d units, want %d: %s", got, target, ordinary)
			}
			got, err := w.ShortMountPath(mount)
			if target >= 260 {
				if err == nil || got != "" || !strings.Contains(err.Error(), "shorter") {
					t.Fatalf("unsafe native mount alias accepted without remedy: path=%q error=%v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("safe native path rejected: %v", err)
			}
			originalInfo, err := os.Stat(original)
			if err != nil {
				t.Fatal(err)
			}
			gotInfo, err := os.Stat(got)
			if err != nil || !os.SameFile(originalInfo, gotInfo) {
				t.Fatalf("safe alias lost owned directory identity: %v", err)
			}
		})
	}
}
