package isocontent

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestWindowsMediaChecksUDFAndDualBootCatalog(t *testing.T) {
	b, e := syntheticBridge()
	p := b[30*2048 : 31*2048]
	efi := append([]byte(nil), p[32:64]...)
	p[1] = 0
	p[28], p[29] = 0, 0
	var sum uint16
	for i := 0; i < 32; i += 2 {
		sum += binary.LittleEndian.Uint16(p[i:])
	}
	binary.LittleEndian.PutUint16(p[28:], 0-sum)
	// Reuse this fixture's seven-byte payload for the BIOS content binding.
	p[38] = 1
	binary.LittleEndian.PutUint32(p[40:], 340)
	p[64], p[65], p[66] = 0x91, 0xef, 1
	copy(p[96:128], efi)
	e.BIOSBootImagePath = "UUP/P0000.CAB"
	if _, err := InspectWindowsISO(bytes.NewReader(b), int64(len(b)), e); err != nil {
		t.Fatal(err)
	}
	b[340*2048] ^= 1
	if _, err := InspectWindowsISO(bytes.NewReader(b), int64(len(b)), e); err == nil {
		t.Fatal("BIOS source bytes changed but accepted")
	}
}

func TestObserveSourceEFILoader(t *testing.T) {
	b, e := syntheticBridge()
	got, err := ObserveEFILoader(bytes.NewReader(b[341*2048:357*2048]), 32768, 0xaa64)
	if err != nil || got != e.EmbeddedLoader {
		t.Fatalf("source EFI observation: %+v %v", got, err)
	}
}

func TestWindowsMediaContentExpectationAllowsLargeFilesAndNormalNames(t *testing.T) {
	if !windowsPath("sources/en-GB/long resource name.dll.mui") {
		t.Fatal("normal Setup filename rejected")
	}
	for _, p := range []string{"../escape", "sources//bad", "sources/../bad", "/absolute", "sources/drive:bad"} {
		if windowsPath(p) {
			t.Fatalf("unsafe path accepted: %s", p)
		}
	}
	b, e := syntheticBridge()
	e.Files[0].Size = 5 << 30
	if _, err := windowsExpectations(e); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectWindowsISO(bytes.NewReader(b[:len(b)-2048]), int64(len(b)-2048), e); err == nil {
		t.Fatal("truncated media accepted")
	}
}

func TestUDFInternalImageAboveFourGiBUsesAllAllocations(t *testing.T) {
	b, _ := syntheticBridge()
	p := b[310*2048 : 311*2048]
	const length uint64 = (5 << 30) + 123
	binary.LittleEndian.PutUint64(p[56:], length)
	remaining := length
	block := uint32(1000)
	count := 0
	for remaining > 0 {
		n := min(remaining, (1<<30)-2048)
		at := 176 + count*8
		binary.LittleEndian.PutUint32(p[at:], uint32(n))
		binary.LittleEndian.PutUint32(p[at+4:], block)
		block += uint32((n + 2047) / 2048)
		remaining -= n
		count++
	}
	binary.LittleEndian.PutUint32(p[172:], uint32(count*8))
	syntheticUDFTag(p, 261, 10, 160+count*8)
	r := isoReader{ReaderAt: bytes.NewReader(b), size: 7 << 30, windowsMedia: true}
	f, dir, err := r.udfEntry(udfLayout{start: 300, blocks: 3 << 20}, 10, "sources/install.wim")
	if err != nil || dir || f.size != int64(length) || len(f.extents) != 6 {
		t.Fatalf("large WIM allocation truncated: %+v %v", f, err)
	}
	binary.LittleEndian.PutUint32(p[172:], uint32((count-1)*8))
	syntheticUDFTag(p, 261, 10, 160+count*8)
	r.claims = nil
	if _, _, err = r.udfEntry(udfLayout{start: 300, blocks: 3 << 20}, 10, "sources/install.wim"); err == nil {
		t.Fatal("missing final large-file allocation accepted")
	}
}
