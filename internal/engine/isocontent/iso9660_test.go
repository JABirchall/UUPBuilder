package isocontent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// syntheticBridge authors a small, explicitly synthetic ISO9660/UDF 1.02
// bridge. It is a parser fixture, never native-provider or Windows media proof.
// Metadata offsets and the three payload bindings are independent literals.
func syntheticBridge() ([]byte, ISOExpectations) {
	b := make([]byte, 800*2048)
	sector := func(n int) []byte { return b[n*2048 : (n+1)*2048] }
	both16 := func(p []byte, v uint16) { binary.LittleEndian.PutUint16(p, v); binary.BigEndian.PutUint16(p[2:], v) }
	both32 := func(p []byte, v uint32) { binary.LittleEndian.PutUint32(p, v); binary.BigEndian.PutUint32(p[4:], v) }
	record := func(name string, lba, size uint32, dir bool) []byte {
		n := 33 + len(name)
		if n%2 != 0 {
			n++
		}
		p := make([]byte, n)
		p[0] = byte(n)
		both32(p[2:], lba)
		both32(p[10:], size)
		if dir {
			p[25] = 2
		}
		both16(p[28:], 1)
		p[32] = byte(len(name))
		copy(p[33:], name)
		return p
	}
	for n, typ := range map[int]byte{16: 1, 17: 0, 18: 255} {
		p := sector(n)
		p[0] = typ
		copy(p[1:], "CD001")
		p[6] = 1
	}
	p := sector(16)
	copy(p[40:72], strings.Repeat(" ", 32))
	copy(p[40:], "P1ARM64")
	both32(p[80:], 800)
	both16(p[120:], 1)
	both16(p[124:], 1)
	both16(p[128:], 2048)
	copy(p[156:], record("\x00", 24, 2048, true))
	copy(sector(17)[7:], "EL TORITO SPECIFICATION")
	binary.LittleEndian.PutUint32(sector(17)[71:], 30)
	paths := []struct {
		name   string
		lba    uint32
		parent uint16
	}{{"\x00", 24, 1}, {"EFI", 25, 1}, {"UUP", 28, 1}, {"BOOT", 26, 2}, {"MICROSOFT", 27, 2}, {"BOOT", 29, 5}}
	for _, be := range []bool{false, true} {
		buf := sector(22)
		if be {
			buf = sector(23)
		}
		at := 0
		for _, x := range paths {
			q := buf[at:]
			q[0] = byte(len(x.name))
			if be {
				binary.BigEndian.PutUint32(q[2:], x.lba)
				binary.BigEndian.PutUint16(q[6:], x.parent)
			} else {
				binary.LittleEndian.PutUint32(q[2:], x.lba)
				binary.LittleEndian.PutUint16(q[6:], x.parent)
			}
			copy(q[8:], x.name)
			at += 8 + len(x.name) + (len(x.name) % 2)
		}
		both32(p[132:], uint32(at))
	}
	binary.LittleEndian.PutUint32(p[140:], 22)
	binary.BigEndian.PutUint32(p[148:], 23)
	dirs := map[int][][]byte{
		24: {record("\x00", 24, 2048, true), record("\x01", 24, 2048, true), record("EFI", 25, 2048, true), record("UUP", 28, 2048, true)},
		25: {record("\x00", 25, 2048, true), record("\x01", 24, 2048, true), record("BOOT", 26, 2048, true), record("MICROSOFT", 27, 2048, true)},
		26: {record("\x00", 26, 2048, true), record("\x01", 25, 2048, true), record("BOOTAA64.EFI;1", 357, 512, false)},
		27: {record("\x00", 27, 2048, true), record("\x01", 25, 2048, true), record("BOOT", 29, 2048, true)},
		28: {record("\x00", 28, 2048, true), record("\x01", 24, 2048, true), record("P0000.CAB;1", 340, 7, false)},
		29: {record("\x00", 29, 2048, true), record("\x01", 27, 2048, true), record("EFISYS.BIN;1", 341, 32768, false)},
	}
	for n, records := range dirs {
		at := 0
		for _, r := range records {
			copy(sector(n)[at:], r)
			at += len(r)
		}
	}
	copy(sector(340), "payload")
	loader := sector(357)[:512]
	copy(loader, "MZ")
	binary.LittleEndian.PutUint32(loader[60:], 128)
	copy(loader[128:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(loader[132:], 0xaa64)
	binary.LittleEndian.PutUint16(loader[134:], 1)
	binary.LittleEndian.PutUint16(loader[148:], 240)
	binary.LittleEndian.PutUint16(loader[152:], 0x20b)
	binary.LittleEndian.PutUint16(loader[220:], 10)
	fat := b[341*2048 : 357*2048]
	copy(fat, []byte{0xeb, 0x3c, 0x90})
	binary.LittleEndian.PutUint16(fat[11:], 512)
	fat[13] = 1
	binary.LittleEndian.PutUint16(fat[14:], 1)
	fat[16] = 1
	binary.LittleEndian.PutUint16(fat[17:], 16)
	binary.LittleEndian.PutUint16(fat[19:], 64)
	fat[21] = 0xf8
	binary.LittleEndian.PutUint16(fat[22:], 1)
	fat[510] = 0x55
	fat[511] = 0xaa
	copy(fat[512:], []byte{0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f}) // clusters 2,3,4 EOF
	entry := func(dst []byte, name string, attr byte, cluster uint16, size uint32) {
		copy(dst, name)
		dst[11] = attr
		binary.LittleEndian.PutUint16(dst[26:], cluster)
		binary.LittleEndian.PutUint32(dst[28:], size)
	}
	entry(fat[1024:], "EFI        ", 0x10, 2, 0)
	entry(fat[1536:], "BOOT       ", 0x10, 3, 0)
	entry(fat[2048:], "BOOTAA64EFI", 0x20, 4, 512)
	copy(fat[2560:], loader)
	cat := sector(30)
	cat[0] = 1
	cat[1] = 0xef
	cat[30] = 0x55
	cat[31] = 0xaa
	var sum uint16
	for i := 0; i < 32; i += 2 {
		sum += binary.LittleEndian.Uint16(cat[i:])
	}
	binary.LittleEndian.PutUint16(cat[28:], 0-sum)
	cat[32] = 0x88
	binary.LittleEndian.PutUint16(cat[38:], 64)
	binary.LittleEndian.PutUint32(cat[40:], 341)
	for n, name := range map[int]string{19: "BEA01", 20: "NSR02", 21: "TEA01"} {
		copy(sector(n)[1:], name)
		sector(n)[6] = 1
	}
	put32 := func(p []byte, off int, v uint32) { binary.LittleEndian.PutUint32(p[off:], v) }
	longAD := func(p []byte, lba, size uint32) { put32(p, 0, size); put32(p, 4, lba) }
	for _, n := range []int{256, 543, 799} {
		p = sector(n)
		put32(p, 16, 6*2048)
		put32(p, 20, 257)
		put32(p, 24, 6*2048)
		put32(p, 28, 263)
		syntheticUDFTag(p, 2, uint32(n), 496)
	}
	for _, start := range []int{257, 263} {
		p = sector(start)
		syntheticUDFTag(p, 1, uint32(start), 496)
		p = sector(start + 1)
		syntheticUDFTag(p, 4, uint32(start+1), 496)
		p = sector(start + 2)
		binary.LittleEndian.PutUint16(p[20:], 1)
		copy(p[25:], "+NSR02")
		put32(p, 184, 1)
		put32(p, 188, 300)
		put32(p, 192, 200)
		syntheticUDFTag(p, 5, uint32(start+2), 496)
		p = sector(start + 3)
		p[84] = 8
		copy(p[85:], "P1ARM64")
		p[211] = 8
		put32(p, 212, 2048)
		copy(p[217:], "*OSTA UDF Compliant")
		binary.LittleEndian.PutUint16(p[240:], 0x102)
		longAD(p[248:], 0, 4096)
		put32(p, 264, 6)
		put32(p, 268, 1)
		put32(p, 432, 2048)
		put32(p, 436, 269)
		p[440] = 1
		p[441] = 6
		binary.LittleEndian.PutUint16(p[442:], 1)
		syntheticUDFTag(p, 6, uint32(start+3), 430)
		p = sector(start + 4)
		syntheticUDFTag(p, 7, uint32(start+4), 8)
		p = sector(start + 5)
		syntheticUDFTag(p, 8, uint32(start+5), 496)
	}
	p = sector(269)
	put32(p, 28, 1)
	put32(p, 72, 1)
	put32(p, 76, 46)
	put32(p, 84, 200)
	put32(p, 120, 3)
	put32(p, 124, 6)
	binary.LittleEndian.PutUint16(p[128:], 0x102)
	binary.LittleEndian.PutUint16(p[130:], 0x102)
	binary.LittleEndian.PutUint16(p[132:], 0x102)
	syntheticUDFTag(p, 9, 269, 118)
	p = sector(300)
	p[112] = 8
	copy(p[113:], "P1ARM64")
	p[239] = 8
	longAD(p[400:], 2, 2048)
	copy(p[417:], "*OSTA UDF Compliant")
	binary.LittleEndian.PutUint16(p[440:], 0x102)
	syntheticUDFTag(p, 256, 0, 496)
	syntheticUDFTag(sector(301), 8, 1, 496)
	fid := func(name string, lba uint32, dir bool, loc uint32) []byte {
		n := 38
		if name != "" {
			n += 1 + len(name)
		}
		n = (n + 3) &^ 3
		p := make([]byte, n)
		binary.LittleEndian.PutUint16(p[16:], 1)
		if dir {
			p[18] = 2
		}
		if name == "" {
			p[18] |= 8
		} else {
			p[19] = byte(1 + len(name))
			p[38] = 8
			copy(p[39:], name)
		}
		longAD(p[20:], lba, 2048)
		syntheticUDFTag(p, 257, loc, n-16)
		return p
	}
	udirs := map[int][][]byte{303: {fid("", 2, true, 3), fid("EFI", 4, true, 3), fid("UUP", 12, true, 3)}, 305: {fid("", 2, true, 5), fid("BOOT", 6, true, 5), fid("MICROSOFT", 14, true, 5)}, 307: {fid("", 4, true, 7), fid("BOOTAA64.EFI", 8, false, 7)}, 313: {fid("", 2, true, 13), fid("P0000.CAB", 10, false, 13)}, 315: {fid("", 4, true, 15), fid("BOOT", 16, true, 15)}, 317: {fid("", 14, true, 17), fid("EFISYS.BIN", 9, false, 17)}}
	for n, entries := range udirs {
		at := 0
		for _, e := range entries {
			copy(sector(n)[at:], e)
			at += len(e)
		}
		fe := sector(n - 1)
		binary.LittleEndian.PutUint16(fe[20:], 4)
		fe[27] = 4
		binary.LittleEndian.PutUint16(fe[48:], 1)
		binary.LittleEndian.PutUint64(fe[56:], uint64(at))
		put32(fe, 172, 8)
		put32(fe, 176, uint32(at))
		put32(fe, 180, uint32(n-300))
		syntheticUDFTag(fe, 261, uint32(n-301), 168)
	}
	for _, x := range []struct{ fe, lba, size int }{{308, 357, 512}, {309, 341, 32768}, {310, 340, 7}} {
		fe := sector(x.fe)
		binary.LittleEndian.PutUint16(fe[20:], 4)
		fe[27] = 5
		binary.LittleEndian.PutUint16(fe[48:], 1)
		binary.LittleEndian.PutUint64(fe[56:], uint64(x.size))
		put32(fe, 172, 8)
		put32(fe, 176, uint32(x.size))
		put32(fe, 180, uint32(x.lba-300))
		syntheticUDFTag(fe, 261, uint32(x.fe-300), 168)
	}
	hash := func(p []byte) string { s := sha256.Sum256(p); return hex.EncodeToString(s[:]) }
	ex := ISOExpectations{Volume: "P1ARM64", TargetMachine: 0xaa64, DirectLoaderPath: "EFI/BOOT/BOOTAA64.EFI", BootImagePath: "EFI/MICROSOFT/BOOT/EFISYS.BIN", EmbeddedLoader: ISOExpectedFile{Path: "EFI/BOOT/BOOTAA64.EFI", Size: 512, SHA256: hash(loader)}}
	ex.Files = []ISOExpectedFile{{"UUP/P0000.CAB", 7, hash([]byte("payload"))}, {"EFI/BOOT/BOOTAA64.EFI", 512, hash(loader)}, {"EFI/MICROSOFT/BOOT/EFISYS.BIN", 32768, hash(fat)}}
	return b, ex
}

// Fixture CRC implementation is independent of production tag verification.
func syntheticUDFTag(p []byte, id uint16, loc uint32, n int) {
	binary.LittleEndian.PutUint16(p, id)
	binary.LittleEndian.PutUint16(p[2:], 2)
	binary.LittleEndian.PutUint16(p[6:], 1)
	binary.LittleEndian.PutUint16(p[10:], uint16(n))
	binary.LittleEndian.PutUint32(p[12:], loc)
	var crc uint16
	for _, v := range p[16 : 16+n] {
		crc ^= uint16(v) << 8
		for k := 0; k < 8; k++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	binary.LittleEndian.PutUint16(p[8:], crc)
	p[4] = 0
	for i, v := range p[:16] {
		if i != 4 {
			p[4] += v
		}
	}
}

func TestISOSyntheticBridgePreservesBothNamespacesAndBootBytes(t *testing.T) {
	b, e := syntheticBridge()
	got, err := InspectISO(bytes.NewReader(b), int64(len(b)), e)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ISOFiles) != 3 || len(got.UDFFiles) != 3 || got.EmbeddedMachine != 0xaa64 || got.DirectMachine != 0xaa64 || got.Size != int64(len(b)) || len(got.SHA256) != 64 {
		t.Fatalf("incomplete raw inspection: %+v", got)
	}
}

func TestISOSyntheticCorruptionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte, *ISOExpectations)
	}{
		{"descriptor-endian", func(b []byte, e *ISOExpectations) { b[16*2048+84] ^= 1 }},
		{"volume-size", func(b []byte, e *ISOExpectations) {
			binary.LittleEndian.PutUint32(b[16*2048+80:], 799)
			binary.BigEndian.PutUint32(b[16*2048+84:], 799)
		}},
		{"block-size", func(b []byte, e *ISOExpectations) { b[16*2048+129] = 0 }},
		{"missing-terminator", func(b []byte, e *ISOExpectations) { b[18*2048] = 1 }},
		{"path-table-parent", func(b []byte, e *ISOExpectations) { binary.LittleEndian.PutUint16(b[22*2048+10+6:], 55) }},
		{"path-table-disagrees", func(b []byte, e *ISOExpectations) { b[23*2048+10+5] ^= 1 }},
		{"path-table-padding", func(b []byte, e *ISOExpectations) { b[22*2048+9] = 1 }},
		{"self-directory-size", func(b []byte, e *ISOExpectations) {
			p := b[24*2048+10:]
			binary.LittleEndian.PutUint32(p, 4096)
			binary.BigEndian.PutUint32(p[4:], 4096)
		}},
		{"parent-directory-size", func(b []byte, e *ISOExpectations) {
			p := b[25*2048+34+10:]
			binary.LittleEndian.PutUint32(p, 4096)
			binary.BigEndian.PutUint32(p[4:], 4096)
		}},
		{"changed-payload", func(b []byte, e *ISOExpectations) { b[340*2048] ^= 1 }},
		{"missing-file", func(b []byte, e *ISOExpectations) { b[28*2048+68] = 0 }},
		{"misbound-file", func(b []byte, e *ISOExpectations) { b[28*2048+68+33] = 'Q' }},
		{"extent-outside", func(b []byte, e *ISOExpectations) {
			p := b[28*2048+68:]
			binary.LittleEndian.PutUint32(p[2:], 900)
			binary.BigEndian.PutUint32(p[6:], 900)
		}},
		{"extent-overlaps-metadata", func(b []byte, e *ISOExpectations) {
			p := b[28*2048+68:]
			binary.LittleEndian.PutUint32(p[2:], 24)
			binary.BigEndian.PutUint32(p[6:], 24)
		}},
		{"directory-cycle", func(b []byte, e *ISOExpectations) {
			p := b[24*2048+68:]
			binary.LittleEndian.PutUint32(p[2:], 24)
			binary.BigEndian.PutUint32(p[6:], 24)
		}},
		{"extra-file-expectation", func(b []byte, e *ISOExpectations) {
			e.Files = append(e.Files, ISOExpectedFile{"UUP/P0001.CAB", 7, e.Files[0].SHA256})
		}},
		{"wrong-expectation-hash", func(b []byte, e *ISOExpectations) { e.Files[0].SHA256 = strings.Repeat("0", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, e := syntheticBridge()
			tc.mutate(b, &e)
			if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), e); err == nil {
				t.Fatal("corrupt synthetic bridge accepted")
			}
		})
	}
}

func TestISOReadBounds(t *testing.T) {
	b, e := syntheticBridge()
	for _, size := range []int64{-1, 0, 2048, int64(len(b) - 1), 6 << 30} {
		if _, err := InspectISO(bytes.NewReader(b), size, e); err == nil {
			t.Fatalf("invalid length %d accepted", size)
		}
	}
}

func TestISORejectsMetadataAliasEvenWhenItsContentHashMatches(t *testing.T) {
	b, e := syntheticBridge()
	p := b[28*2048+68:]
	binary.LittleEndian.PutUint32(p[2:], 24)
	binary.BigEndian.PutUint32(p[6:], 24)
	sum := sha256.Sum256(b[24*2048 : 24*2048+7])
	e.Files[0].SHA256 = hex.EncodeToString(sum[:])
	if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), e); err == nil || !strings.Contains(err.Error(), "overlapping ISO allocations") {
		t.Fatalf("metadata alias was not rejected structurally: %v", err)
	}
}

func TestISODirectPETargetIsInspectedAsBytes(t *testing.T) {
	b, _ := syntheticBridge()
	loader := append([]byte(nil), b[357*2048:357*2048+512]...)
	binary.LittleEndian.PutUint16(loader[132:], 0x8664)
	if _, err := inspectEFIPE(bytes.NewReader(loader), 512, 0xaa64); err == nil {
		t.Fatal("x64 PE accepted as ARM64")
	}
	if machine, err := inspectEFIPE(bytes.NewReader(loader), 512, 0x8664); err != nil || machine != 0x8664 {
		t.Fatalf("PE fixture malformed: %#x %v", machine, err)
	}
}

// IMAPI keeps its UDF reserve sequence and two terminal anchors outside the
// ISO9660-declared volume. The payload/partition still ends at that boundary.
func syntheticBridgeWithUDFTail() ([]byte, ISOExpectations) {
	b, e := syntheticBridge()
	binary.LittleEndian.PutUint32(b[16*2048+80:], 500)
	binary.BigEndian.PutUint32(b[16*2048+84:], 500)
	for i := 0; i < 6; i++ {
		copy(b[(500+i)*2048:(501+i)*2048], b[(263+i)*2048:(264+i)*2048])
		p := b[(500+i)*2048 : (501+i)*2048]
		syntheticUDFTag(p, le16(p), uint32(500+i), int(le16(p[10:])))
		clear(b[(263+i)*2048 : (264+i)*2048])
	}
	clear(b[543*2048 : 544*2048])
	for _, n := range []int{256, 511, 767} {
		p := b[n*2048 : (n+1)*2048]
		if n != 256 {
			copy(p, b[256*2048:257*2048])
		}
		binary.LittleEndian.PutUint32(p[28:], 500)
		syntheticUDFTag(p, 2, uint32(n), 496)
	}
	return b[:768*2048], e
}

func TestISOBridgeAllowsOnlyValidatedUDFReserveTail(t *testing.T) {
	b, e := syntheticBridgeWithUDFTail()
	if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), e); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{{"unknown-tail-bytes", func(b []byte) { b[520*2048] = 1 }}, {"missing-end-anchor", func(b []byte) { clear(b[767*2048 : 768*2048]) }}, {"bad-backup-anchor-CRC", func(b []byte) { b[511*2048+8] ^= 1 }}, {"bad-reserve-CRC", func(b []byte) { b[502*2048+8] ^= 1 }}, {"ISO-catalog-beyond-declared-volume", func(b []byte) { binary.LittleEndian.PutUint32(b[17*2048+71:], 520) }}, {"ISO-file-beyond-declared-volume", func(b []byte) {
		p := b[28*2048+68:]
		binary.LittleEndian.PutUint32(p[2:], 520)
		binary.BigEndian.PutUint32(p[6:], 520)
	}}} {
		t.Run(tc.name, func(t *testing.T) {
			p := append([]byte(nil), b...)
			tc.mutate(p)
			if _, err := InspectISO(bytes.NewReader(p), int64(len(p)), e); err == nil {
				t.Fatal("unvalidated UDF tail/ISO extent accepted")
			}
		})
	}
}

func TestISODirectoryUsesDeclaredBytesAndChecksAllocationPadding(t *testing.T) {
	b, e := syntheticBridge()
	set := func(p []byte, v uint32) { binary.LittleEndian.PutUint32(p, v); binary.BigEndian.PutUint32(p[4:], v) }
	set(b[24*2048+104+10:], 112)
	set(b[28*2048+10:], 112)
	if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), e); err != nil {
		t.Fatal(err)
	}
	p := append([]byte(nil), b...)
	p[28*2048+112] = 1
	if _, err := InspectISO(bytes.NewReader(p), int64(len(p)), e); err == nil {
		t.Fatal("nonzero directory allocation padding accepted")
	}
	set(b[24*2048+104+10:], 111)
	set(b[28*2048+10:], 111)
	if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), e); err == nil {
		t.Fatal("record crossing declared directory bytes accepted")
	}
}
