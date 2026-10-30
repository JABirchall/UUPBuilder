package isocontent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// These are synthetic parser fixtures. Changing the machine without its EFI
// filename and optional-header kind must never establish a target binding.
func TestAdditionalISOKnownEFIArchitectureBindings(t *testing.T) {
	for _, tc := range []struct {
		name, path, fatName string
		machine, magic      uint16
	}{
		{"x86", "EFI/BOOT/BOOTIA32.EFI", "BOOTIA32EFI", 0x014c, 0x010b},
		{"amd64", "EFI/BOOT/BOOTX64.EFI", "BOOTX64 EFI", 0x8664, 0x020b},
		{"arm64", "EFI/BOOT/BOOTAA64.EFI", "BOOTAA64EFI", 0xaa64, 0x020b},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, e := syntheticBridge()
			fat := append([]byte(nil), b[341*2048:357*2048]...)
			copy(fat[2048:2059], tc.fatName)
			binary.LittleEndian.PutUint16(fat[2560+132:], tc.machine)
			binary.LittleEndian.PutUint16(fat[2560+152:], tc.magic)
			h := sha256.Sum256(fat[2560:3072])
			want := ISOExpectedFile{tc.path, 512, hex.EncodeToString(h[:])}
			if got, err := inspectEFIFAT(bytes.NewReader(fat), int64(len(fat)), want, tc.machine); err != nil || got != tc.machine {
				t.Fatalf("valid synthetic %s EFI data rejected: machine=%#x error=%v", tc.name, got, err)
			}
			e.TargetMachine, e.DirectLoaderPath, e.EmbeddedLoader = tc.machine, tc.path, want
			e.Files[1].Path = tc.path
			if _, err := validateISOExpectations(e); err != nil {
				t.Fatalf("known matching boot roles rejected: %v", err)
			}
			wrong := append([]byte(nil), fat[2560:3072]...)
			binary.LittleEndian.PutUint16(wrong[152:], tc.magic^0x0300)
			if _, err := inspectEFIPE(bytes.NewReader(wrong), int64(len(wrong)), tc.machine); err == nil {
				t.Fatal("wrong PE32/PE32+ optional-header kind accepted")
			}
			for _, other := range []string{"EFI/BOOT/BOOTIA32.EFI", "EFI/BOOT/BOOTX64.EFI", "EFI/BOOT/BOOTAA64.EFI", "EFI/BOOT/OTHER.EFI"} {
				if other == tc.path {
					continue
				}
				bad := e
				bad.DirectLoaderPath = other
				if _, err := validateISOExpectations(bad); err == nil {
					t.Fatalf("cross-paired direct path %s accepted", other)
				}
				bad = e
				bad.EmbeddedLoader.Path = other
				if _, err := validateISOExpectations(bad); err == nil {
					t.Fatalf("cross-paired embedded path %s accepted", other)
				}
				if _, err := inspectEFIFAT(bytes.NewReader(fat), int64(len(fat)), bad.EmbeddedLoader, tc.machine); err == nil {
					t.Fatalf("cross-paired FAT expectation %s accepted", other)
				}
			}
		})
	}
}

func TestAdditionalISORejectsUnknownEFIMachine(t *testing.T) {
	b, e := syntheticBridge()
	loader := append([]byte(nil), b[357*2048:357*2048+512]...)
	binary.LittleEndian.PutUint16(loader[132:], 0x01c4)
	if _, err := inspectEFIPE(bytes.NewReader(loader), 512, 0x01c4); err == nil {
		t.Fatal("unknown machine accepted through matching caller/PE values")
	}
	e.TargetMachine = 0x01c4
	if _, err := validateISOExpectations(e); err == nil {
		t.Fatal("unknown target expectations accepted")
	}
}
