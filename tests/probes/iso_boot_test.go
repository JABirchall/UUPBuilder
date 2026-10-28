package probes

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestISOBootSyntheticCorruptionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte, *ISOExpectations)
	}{
		{"catalog-checksum", func(b []byte, e *ISOExpectations) { b[30*2048+28] ^= 1 }},
		{"catalog-magic", func(b []byte, e *ISOExpectations) { b[30*2048+30] = 0 }},
		{"not-bootable", func(b []byte, e *ISOExpectations) { b[30*2048+32] = 0 }},
		{"floppy-emulation", func(b []byte, e *ISOExpectations) { b[30*2048+33] = 2 }},
		{"load-count-zero", func(b []byte, e *ISOExpectations) { binary.LittleEndian.PutUint16(b[30*2048+38:], 0) }},
		{"load-outside-image", func(b []byte, e *ISOExpectations) { binary.LittleEndian.PutUint16(b[30*2048+38:], 65535) }},
		{"image-outside-volume", func(b []byte, e *ISOExpectations) { binary.LittleEndian.PutUint32(b[30*2048+40:], 799) }},
		{"extra-section", func(b []byte, e *ISOExpectations) { b[30*2048+64] = 0x91 }},
		{"wrong-target-expectation", func(b []byte, e *ISOExpectations) { e.TargetMachine = 0x8664 }},
		{"wrong-embedded-loader-hash", func(b []byte, e *ISOExpectations) { e.EmbeddedLoader.SHA256 = e.Files[0].SHA256 }},
		{"wrong-embedded-boot-path", func(b []byte, e *ISOExpectations) { e.EmbeddedLoader.Path = "EFI/BOOT/BOOTX64.EFI" }},
		{"wrong-direct-loader-path", func(b []byte, e *ISOExpectations) { e.DirectLoaderPath = "UUP/P0000.CAB" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, e := syntheticBridge()
			tc.mutate(b, &e)
			if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), e); err == nil {
				t.Fatal("corrupt synthetic boot data accepted")
			}
		})
	}
}

func TestISOFATSyntheticCycleAndMachine(t *testing.T) {
	b, e := syntheticBridge()
	fat := b[341*2048 : 357*2048]
	if _, err := inspectEFIFAT(bytes.NewReader(fat), int64(len(fat)), e.EmbeddedLoader, 0xaa64); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{
		{"bad-bpb", func(b []byte) { b[13] = 3 }},
		{"cycle", func(b []byte) { b[512+6] = 4; b[512+7] &= 0xf0 }},
		{"directory-missing", func(b []byte) { b[1024] = 0 }},
		{"wrong-machine", func(b []byte) { binary.LittleEndian.PutUint16(b[2560+132:], 0x8664) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := append([]byte(nil), fat...)
			tc.change(p)
			if _, err := inspectEFIFAT(bytes.NewReader(p), int64(len(p)), e.EmbeddedLoader, 0xaa64); err == nil {
				t.Fatal("invalid FAT accepted")
			}
		})
	}
}
