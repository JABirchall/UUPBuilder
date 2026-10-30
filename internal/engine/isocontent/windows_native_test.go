package isocontent

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Optional real owned-file acceptance. The media here is an internal component
// only; absence of install/boot images cannot satisfy final output verification.
func TestNativeWindowsMediaContent(t *testing.T) {
	root, path := os.Getenv("UUP_OUTPUT_MEDIA"), os.Getenv("UUP_OUTPUT_ISO")
	if root == "" || path == "" {
		t.Skip("native media component paths not configured")
	}
	e := ISOExpectations{Volume: "U10_COMPONENT", TargetMachine: 0x8664, DirectLoaderPath: "efi/boot/bootx64.efi", BootImagePath: "efi/microsoft/boot/efisys.bin", BIOSBootImagePath: "boot/etfsboot.com"}
	file := func(path, name string) ISOExpectedFile {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			t.Fatal(err)
		}
		return ISOExpectedFile{name, n, hex.EncodeToString(h.Sum(nil))}
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		e.Files = append(e.Files, file(path, filepath.ToSlash(rel)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	boot, err := os.Open(filepath.Join(root, "efi/microsoft/boot/efisys.bin"))
	if err != nil {
		t.Fatal(err)
	}
	bs, _ := boot.Stat()
	e.EmbeddedLoader, err = ObserveEFILoader(boot, bs.Size(), 0x8664)
	boot.Close()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	got, err := InspectWindowsISO(f, s.Size(), e)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("independently inspected %d UDF files, ISO size=%d SHA256=%s", len(got.UDFFiles), got.Size, got.SHA256)
}
