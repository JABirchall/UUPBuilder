package probes

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestUDFRejectsExpandedFileSetSequenceExtent(t *testing.T) {
	b, expected := syntheticBridge()
	if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), expected); err != nil {
		t.Fatal(err)
	}
	for _, sector := range []int{260, 266} {
		p := b[sector*2048 : (sector+1)*2048]
		binary.LittleEndian.PutUint32(p[248:], 32768)
		syntheticUDFTag(p, 6, uint32(sector), 430)
	}
	if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), expected); err == nil {
		t.Fatal("declared file-set metadata extent overlapping ICBs/directories accepted")
	}
}

func TestUDFRejectsShortDeclaredICBExtents(t *testing.T) {
	control, expected := syntheticBridge()
	if _, err := InspectISO(bytes.NewReader(control), int64(len(control)), expected); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"root-ICB", func(b []byte) {
			p := b[300*2048 : 301*2048]
			binary.LittleEndian.PutUint32(p[400:], 1)
			syntheticUDFTag(p, 256, 0, 496)
		}},
		{"ordinary-child-FID", func(b []byte) {
			// UUP/P0000.CAB's FID follows the 40-byte parent FID.
			p := b[313*2048+40 : 313*2048+88]
			binary.LittleEndian.PutUint32(p[20:], 1)
			syntheticUDFTag(p, 257, 13, 32)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := append([]byte(nil), control...)
			test.mutate(b)
			if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), expected); err == nil {
				t.Fatal("full file entry read beyond declared one-byte ICB extent")
			}
		})
	}
}

// These 54 metadata bytes are copied from the actual pinned IMAPI output's
// LVID at sector64+80, independently of the synthetic bridge author. They
// contain tables/producer ID/counts/revisions, no Windows payload or secrets.
func TestUDFNativeLVIDCountsPrecedeRevisionFields(t *testing.T) {
	data, err := hex.DecodeString("0000000004251800004d6963726f736f667420494d4150493220312e3000000006000000000000003000000006000000020102010201")
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 3*2048)
	p := b[2048:4096]
	binary.LittleEndian.PutUint32(p[28:], 1)
	binary.LittleEndian.PutUint32(p[72:], 1)
	binary.LittleEndian.PutUint32(p[76:], 46)
	copy(p[80:], data)
	syntheticUDFTag(p, 9, 1, 118)
	r := &isoReader{ReaderAt: bytes.NewReader(b), size: int64(len(b))}
	files, dirs, err := r.udfIntegrity(udfLayout{blocks: 1582340, integrity: 1, integrityBytes: 2048})
	if err != nil || files != 48 || dirs != 6 {
		t.Fatalf("actual LVID table/implementation layout misread: files=%d dirs=%d error=%v", files, dirs, err)
	}
}

func TestUDFBridgeValidatesEveryRedundantTailAnchor(t *testing.T) {
	b, e := syntheticBridgeWithUDFTail()
	for _, n := range []int{256, 511, 767} {
		p := b[n*2048 : (n+1)*2048]
		binary.LittleEndian.PutUint32(p[24:], 8*2048)
		syntheticUDFTag(p, 2, uint32(n), 496)
	}
	for n := 506; n < 511; n++ {
		p := b[n*2048 : (n+1)*2048]
		copy(p, b[256*2048:257*2048])
		syntheticUDFTag(p, 2, uint32(n), 496)
	}
	if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), e); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{506*2048 + 8, 508*2048 + 8} {
		p := append([]byte(nil), b...)
		p[offset] ^= 1
		if _, err := InspectISO(bytes.NewReader(p), int64(len(p)), e); err == nil {
			t.Fatal("bad redundant reserve/tail anchor CRC accepted")
		}
	}
}

// Native reserve AVDP header from sector1582634 of the observed IMAPI image.
// Its remaining 2016 bytes are zero. This is authored ISO metadata only.
func TestUDFNativeRedundantAnchorChecksPointerLocationCRCAndPadding(t *testing.T) {
	header, err := hex.DecodeString("02000200fc000000910ef0012a26180000800000200000000080000024261800")
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 2048)
	copy(p, header)
	reference := append([]byte(nil), p...)
	if err = udfAnchor(p, 1582634, reference); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{{"pointer", func(p []byte) { binary.LittleEndian.PutUint32(p[20:], 33); syntheticUDFTag(p, 2, 1582634, 496) }}, {"location", func(p []byte) { syntheticUDFTag(p, 2, 1582635, 496) }}, {"CRC", func(p []byte) { p[8] ^= 1 }}, {"unknown-tag", func(p []byte) { syntheticUDFTag(p, 3, 1582634, 496) }}, {"reserved-body", func(p []byte) { p[32] = 1; syntheticUDFTag(p, 2, 1582634, 496) }}, {"block-padding", func(p []byte) { p[512] = 1 }}} {
		t.Run(tc.name, func(t *testing.T) {
			q := append([]byte(nil), p...)
			tc.mutate(q)
			if err := udfAnchor(q, 1582634, reference); err == nil {
				t.Fatal("malformed redundant native-layout anchor accepted")
			}
		})
	}
}

func TestUDFIntegritySequenceRejectsUncheckedTrailingMetadata(t *testing.T) {
	b, e := syntheticBridge()
	for _, n := range []int{260, 266} {
		p := b[n*2048 : (n+1)*2048]
		binary.LittleEndian.PutUint32(p[432:], 4096)
		syntheticUDFTag(p, 6, uint32(n), 430)
	}
	syntheticUDFTag(b[270*2048:271*2048], 8, 270, 496)
	if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), e); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{{"LVID-padding", func(b []byte) { b[269*2048+512] = 1 }}, {"terminator-CRC", func(b []byte) { b[270*2048+8] ^= 1 }}, {"unknown-record", func(b []byte) { p := b[270*2048 : 271*2048]; syntheticUDFTag(p, 9, 270, 496) }}, {"reserved-padding", func(b []byte) { b[270*2048+512] = 1 }}} {
		t.Run(tc.name, func(t *testing.T) {
			p := append([]byte(nil), b...)
			tc.mutate(p)
			if _, err := InspectISO(bytes.NewReader(p), int64(len(p)), e); err == nil {
				t.Fatal("unchecked integrity record accepted")
			}
		})
	}
}

func TestUDFSyntheticCorruptionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"recognition", func(b []byte) { b[20*2048+4] = '3' }},
		{"anchor-checksum", func(b []byte) { b[256*2048+4] ^= 1 }},
		{"anchor-out-of-bounds", func(b []byte) {
			p := b[256*2048 : 257*2048]
			binary.LittleEndian.PutUint32(p[20:], 900)
			syntheticUDFTag(p, 2, 256, 496)
		}},
		{"main-sequence-crc", func(b []byte) { b[259*2048+192] ^= 1 }},
		{"integrity-read-revision", func(b []byte) {
			p := b[269*2048 : 270*2048]
			binary.LittleEndian.PutUint16(p[128:], 0x150)
			syntheticUDFTag(p, 9, 269, 118)
		}},
		{"integrity-write-revision", func(b []byte) {
			p := b[269*2048 : 270*2048]
			binary.LittleEndian.PutUint16(p[130:], 0x150)
			syntheticUDFTag(p, 9, 269, 118)
		}},
		{"integrity-file-count", func(b []byte) {
			p := b[269*2048 : 270*2048]
			binary.LittleEndian.PutUint32(p[120:], 4)
			syntheticUDFTag(p, 9, 269, 118)
		}},
		{"integrity-directory-count", func(b []byte) {
			p := b[269*2048 : 270*2048]
			binary.LittleEndian.PutUint32(p[124:], 7)
			syntheticUDFTag(p, 9, 269, 118)
		}},
		{"reserve-sequence-crc", func(b []byte) { b[265*2048+192] ^= 1 }},
		{"udf-revision", func(b []byte) {
			for _, n := range []int{260, 266} {
				p := b[n*2048 : (n+1)*2048]
				binary.LittleEndian.PutUint16(p[240:], 0x150)
				syntheticUDFTag(p, 6, uint32(n), 430)
			}
		}},
		{"unsupported-partition-map", func(b []byte) {
			for _, n := range []int{260, 266} {
				p := b[n*2048 : (n+1)*2048]
				p[440] = 2
				syntheticUDFTag(p, 6, uint32(n), 430)
			}
		}},
		{"file-set-location", func(b []byte) { p := b[300*2048 : 301*2048]; syntheticUDFTag(p, 256, 1, 496) }},
		{"root-icb-out-of-partition", func(b []byte) {
			p := b[300*2048 : 301*2048]
			binary.LittleEndian.PutUint32(p[404:], 300)
			syntheticUDFTag(p, 256, 0, 496)
		}},
		{"file-entry-allocation-length", func(b []byte) {
			p := b[310*2048 : 311*2048]
			binary.LittleEndian.PutUint32(p[172:], 0xffffffff)
			syntheticUDFTag(p, 261, 10, 168)
		}},
		{"file-entry-content-out-of-partition", func(b []byte) {
			p := b[310*2048 : 311*2048]
			binary.LittleEndian.PutUint32(p[180:], 201)
			syntheticUDFTag(p, 261, 10, 168)
		}},
		{"file-entry-cyclic-allocation", func(b []byte) {
			p := b[310*2048 : 311*2048]
			binary.LittleEndian.PutUint32(p[176:], 0xc0000800)
			syntheticUDFTag(p, 261, 10, 168)
		}},
		{"fid-crc", func(b []byte) { b[313*2048+40+39] ^= 1 }},
		{"fid-cycle", func(b []byte) {
			p := b[303*2048+40 : 303*2048+84]
			binary.LittleEndian.PutUint32(p[24:], 2)
			syntheticUDFTag(p, 257, 3, 28)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, e := syntheticBridge()
			tc.mutate(b)
			if _, err := InspectISO(bytes.NewReader(b), int64(len(b)), e); err == nil {
				t.Fatal("corrupt synthetic UDF accepted")
			}
		})
	}
}
