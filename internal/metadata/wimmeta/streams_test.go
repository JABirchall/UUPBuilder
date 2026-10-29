package wimmeta

import (
	"context"
	"strings"
	"testing"
)

func streamLayoutFixture(attrs uint32, main byte, extra ...[]byte) []byte {
	// Security-free root at 8, root marker at 112, file at 120. Each stream
	// hash 0x01 has an exact seven-byte index witness in boundFixture.
	b := make([]byte, 8)
	le.PutUint32(b, 8)
	root := diskEntry("", 16, 120)
	le.PutUint32(root[12:], 0xffffffff)
	b = append(b, root...)
	b = append(b, make([]byte, 8)...)
	e := diskEntry("x", attrs, 0)
	le.PutUint32(e[12:], 0xffffffff)
	le.PutUint16(e[96:], uint16(len(extra)))
	for i := 64; i < 84; i++ {
		e[i] = main
	}
	b = append(b, e...)
	for _, record := range extra {
		b = append(b, record...)
	}
	return append(b, make([]byte, 8)...)
}

func TestPublicEncryptedStreamSemanticsGateCompleteness(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs uint32
		main  byte
		extra [][]byte
		roles []string
		gaps  int
	}{
		{"zero-main-no-extras", 0x4020, 0, nil, []string{"unresolved-encrypted"}, 1},
		{"zero-main-directory", 0x4010, 0, nil, []string{"unresolved-encrypted"}, 1},
		{"main-efs-raw", 0x4020, 1, nil, []string{"encrypted-raw"}, 0},
		{"extra-efs-raw", 0x4020, 0, [][]byte{diskStream("", 1)}, []string{"unused-main", "encrypted-raw"}, 0},
		{"efs-with-named-extra", 0x4020, 1, [][]byte{diskStream("ads", 1)}, []string{"encrypted-raw", "unresolved-encrypted"}, 1},
		{"efs-with-empty-named-extra", 0x4020, 1, [][]byte{diskStream("ads", 0)}, []string{"encrypted-raw", "unresolved-encrypted"}, 1},
		{"named-extra-no-efs", 0x4020, 0, [][]byte{diskStream("ads", 1)}, []string{"unresolved-encrypted", "unresolved-encrypted"}, 2},
		{"multiple-unnamed-hashes", 0x4020, 1, [][]byte{diskStream("", 1)}, []string{"encrypted-raw", "unresolved-encrypted"}, 1},
		{"efs-with-empty-unnamed-extra", 0x4020, 1, [][]byte{diskStream("", 0)}, []string{"encrypted-raw", "unresolved-encrypted"}, 1},
		{"encrypted-reparse", 0x4420, 1, nil, []string{"encrypted-raw"}, 1},
		{"unencrypted-empty", 0x20, 0, nil, []string{"data"}, 0},
		{"unencrypted-named", 0x20, 1, [][]byte{diskStream("ads", 1)}, []string{"data", "named-data"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := streamLayoutFixture(tc.attrs, tc.main, tc.extra...)
			a, idx := boundFixture(t, b, true)
			o, err := Parse(context.Background(), a, idx, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			s := o.Snapshot()
			if !s.MetadataVerified || s.ContentVerified || s.ConversionSupported || len(s.Entries) != 2 {
				t.Fatal("artifact boundary changed")
			}
			if s.Complete != (tc.gaps == 0) || len(s.Gaps) != tc.gaps {
				t.Fatalf("encrypted acceptance lost: complete=%v gaps=%+v", s.Complete, s.Gaps)
			}
			for _, gap := range s.Gaps {
				if gap.Kind != "encrypted-stream-semantics" || gap.Entry != 1 {
					t.Fatal("unrelated gap hides unsupported encrypted semantics", gap)
				}
			}
			e := s.Entries[1]
			mainSHA := zeroHash
			if tc.main == 1 {
				mainSHA = strings.Repeat("01", 20)
			}
			if e.Attributes != tc.attrs || len(e.Streams) != len(tc.roles) || e.Streams[0].SHA1 != mainSHA {
				t.Fatal("original attributes/hash/stream records lost", e)
			}
			for i, role := range tc.roles {
				stream := e.Streams[i]
				if stream.Kind != role {
					t.Fatalf("stream %d role=%q want=%q", i, stream.Kind, role)
				}
				if stream.SHA1 == zeroHash {
					if !stream.SizeKnown || stream.Size != 0 || stream.SizeProvenance != "metadata-empty" {
						t.Fatal("encoded zero hash changed", stream)
					}
				} else if !stream.SizeKnown || stream.Size != 7 || stream.SizeProvenance != "index-witness" {
					t.Fatal("exact nonempty witness size lost", stream)
				}
			}
			for i, record := range tc.extra {
				if le.Uint16(record[36:]) != 0 && (len(e.Streams[i+1].Name) != 3 || e.Streams[i+1].Name[0] != 'a') {
					t.Fatal("unsupported stream name discarded")
				}
			}
		})
	}
}
