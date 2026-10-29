package wimcontent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"uupbuilder/internal/metadata/wimindex"
)

func TestAlternateFramingHasSizeTableAndChecksEveryExtent(t *testing.T) {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint64(b, 32773)
	binary.LittleEndian.PutUint32(b[8:], 32768)
	binary.LittleEndian.PutUint32(b[12:], 3)
	binary.LittleEndian.PutUint32(b[16:], 1)
	binary.LittleEndian.PutUint32(b[20:], 5)
	copy(b[24:], []byte("Ztail!"))
	b = b[:30]
	e := wimindex.Entry{Kind: "solid-resource", LogicalSize: 32773, Descriptor: wimindex.Descriptor{Size: 30, Flags: 16}, Location: wimindex.Location{ResourceLogicalSize: 32773, PhysicalSize: 30, ChunkSize: 32768, Compression: 3}}
	l, _ := bounds(Limits{})
	p, er := inspect(context.Background(), bytes.NewReader(b), uint64(len(b)), e, l)
	if er != nil || p.count != 2 || p.table != 24 || len(p.chunks) != 2 || p.chunks[0].offset != 24 || p.chunks[0].size != 1 || p.chunks[1].offset != 25 || p.chunks[1].logical != 5 {
		t.Fatal("alternate sizes mistaken for original offsets", p, er)
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte)
		limits Limits
	}{{"zero-size", func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 0) }, Limits{}}, {"oversized-partial", func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 6) }, Limits{}}, {"header-size", func(b []byte) { binary.LittleEndian.PutUint64(b, 32774) }, Limits{}}, {"header-codec", func(b []byte) { binary.LittleEndian.PutUint32(b[12:], 2) }, Limits{}}, {"trailing", func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 4) }, Limits{}}, {"count-limit", func([]byte) {}, Limits{MaxChunks: 1}}, {"buffer-limit", func([]byte) {}, Limits{MaxBufferBytes: 65536, MaxChunkBytes: 32768}}} {
		t.Run(test.name, func(t *testing.T) {
			v := bytes.Clone(b)
			test.mutate(v)
			l, _ := bounds(test.limits)
			if test.name == "buffer-limit" {
				l.MaxBufferBytes = 32768
			}
			if _, er := inspect(context.Background(), bytes.NewReader(v), uint64(len(v)), e, l); er == nil {
				t.Fatal("bad framing accepted")
			}
		})
	}
	l, _ = bounds(Limits{MaxChunkBytes: 16384})
	if _, er := inspect(context.Background(), bytes.NewReader(b), uint64(len(b)), e, l); !errors.Is(er, ErrLimit) {
		t.Fatal(er)
	}
}
