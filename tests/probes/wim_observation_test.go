package probes

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

// A synthetic WIM framing fixture with explicit placeholder compressed chunks.
// The decompression port only recognizes those exact placeholders; this tests
// table/dentry/hash custody, never real LZMS/provider/source-family support.
func syntheticWIM(payload []byte) ([]byte, []byte, []byte) {
	wide := func(s string) []byte {
		u := utf16.Encode([]rune(s))
		b := make([]byte, len(u)*2)
		for i, v := range u {
			binary.LittleEndian.PutUint16(b[i*2:], v)
		}
		return b
	}
	sha := sha256.Sum256(payload)
	filehashes := wide(fmt.Sprintf("[sha256]\r\nupdate.mum=%x,%X\r\n", sha, len(payload)))
	solid := append(append([]byte(nil), payload...), filehashes...)
	dentry := func(name string, body []byte) []byte {
		n := wide(name)
		length := (102 + len(n) + 2 + 7) &^ 7
		b := make([]byte, length)
		binary.LittleEndian.PutUint64(b, uint64(length))
		binary.LittleEndian.PutUint32(b[8:], 0x20)
		h := sha1.Sum(body)
		copy(b[64:], h[:])
		binary.LittleEndian.PutUint16(b[100:], uint16(len(n)))
		copy(b[102:], n)
		return b
	}
	metadata := make([]byte, 112)
	binary.LittleEndian.PutUint32(metadata, 8)
	binary.LittleEndian.PutUint64(metadata[8:], 104)
	binary.LittleEndian.PutUint32(metadata[16:], 0x10)
	binary.LittleEndian.PutUint64(metadata[24:], 112)
	metadata = append(metadata, dentry("update.mum", payload)...)
	metadata = append(metadata, dentry("$filehashes$.dat", filehashes)...)
	metadata = append(metadata, make([]byte, 8)...)
	body := make([]byte, 208)
	copy(body, []byte("MSWIM\x00\x00\x00"))
	binary.LittleEndian.PutUint32(body[8:], 208)
	binary.LittleEndian.PutUint32(body[12:], 0xe00)
	binary.LittleEndian.PutUint32(body[16:], 0x80002)
	binary.LittleEndian.PutUint32(body[20:], 131072)
	binary.LittleEndian.PutUint16(body[40:], 1)
	binary.LittleEndian.PutUint16(body[42:], 1)
	binary.LittleEndian.PutUint32(body[44:], 1)
	body = append(body, 'M')
	solidOffset := len(body)
	solidHeader := make([]byte, 20)
	binary.LittleEndian.PutUint64(solidHeader, uint64(len(solid)))
	binary.LittleEndian.PutUint32(solidHeader[8:], 67108864)
	binary.LittleEndian.PutUint32(solidHeader[12:], 3)
	binary.LittleEndian.PutUint32(solidHeader[16:], 1)
	body = append(body, solidHeader...)
	body = append(body, 'S')
	table := len(body)
	entry := func(size, offset, original uint64, flags byte, hash []byte, refs uint32) {
		e := make([]byte, 50)
		binary.LittleEndian.PutUint64(e, size)
		e[7] = flags
		binary.LittleEndian.PutUint64(e[8:], offset)
		binary.LittleEndian.PutUint64(e[16:], original)
		binary.LittleEndian.PutUint16(e[24:], 1)
		binary.LittleEndian.PutUint32(e[26:], refs)
		copy(e[30:], hash)
		body = append(body, e...)
	}
	metadataHash := sha1.Sum(metadata)
	payloadHash := sha1.Sum(payload)
	filehashesHash := sha1.Sum(filehashes)
	entry(1, 208, uint64(len(metadata)), 6, metadataHash[:], 1)
	entry(21, uint64(solidOffset), 0x100000000, 16, nil, 0)
	entry(uint64(len(payload)), 0, 0, 16, payloadHash[:], 1)
	entry(uint64(len(filehashes)), uint64(len(payload)), 0, 16, filehashesHash[:], 1)
	binary.LittleEndian.PutUint64(body[48:], 200)
	body[55] = 2
	binary.LittleEndian.PutUint64(body[56:], uint64(table))
	binary.LittleEndian.PutUint64(body[64:], 200)
	return body, metadata, solid
}

func syntheticLZMS(metadata, solid []byte) func(context.Context, []byte, int) ([]byte, error) {
	return func(ctx context.Context, input []byte, size int) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var data []byte
		switch string(input) {
		case "M":
			data = metadata
		case "S":
			data = solid
		default:
			return nil, errors.New("unknown synthetic compressed chunk")
		}
		if len(data) != size {
			return nil, errors.New("wrong decompressor size contract")
		}
		return append([]byte(nil), data...), nil
	}
}

func TestObservedWIMParsesResourceAndMemberHashesFromActualFraming(t *testing.T) {
	body, metadata, solid := syntheticWIM([]byte("abc"))
	got, err := extractObservedWIM(context.Background(), body, "update.mum", syntheticLZMS(metadata, solid))
	if err != nil || !bytes.Equal(got.Content, []byte("abc")) || got.ExpectedSHA256 != unitHash || got.MemberSHA1 != "a9993e364706816aba3e25717850c26c9cd0d89d" || got.ContentBlobs != 2 {
		t.Fatalf("actual parsed member/resource binding=%+v error=%v", got, err)
	}
}

func TestObservedWIMRejectsCorruptOrUnimplementedVariant(t *testing.T) {
	for _, name := range []string{"short", "version", "flags", "split", "lookup overflow", "lookup record width", "resource overlap", "metadata original bound", "metadata digest", "solid compression", "solid compressed length", "blob bounds", "blob digest", "member path", "missing member", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			body, metadata, solid := syntheticWIM([]byte("abc"))
			member := "update.mum"
			ctx := context.Background()
			table := int(binary.LittleEndian.Uint64(body[56:]))
			switch name {
			case "short":
				body = body[:100]
			case "version":
				binary.LittleEndian.PutUint32(body[12:], 0x10d00)
			case "flags":
				body[17] = 1
			case "split":
				body[42] = 2
			case "lookup overflow":
				binary.LittleEndian.PutUint64(body[56:], ^uint64(0)-1)
			case "lookup record width":
				body[48] = 199
			case "resource overlap":
				binary.LittleEndian.PutUint64(body[table+50+8:], 208)
			case "metadata original bound":
				binary.LittleEndian.PutUint64(body[table+16:], 1<<30)
			case "metadata digest":
				metadata[8]++
			case "solid compression":
				binary.LittleEndian.PutUint32(body[209+12:], 2)
			case "solid compressed length":
				body[209+16] = 2
			case "blob bounds":
				binary.LittleEndian.PutUint64(body[table+100+8:], ^uint64(0))
			case "blob digest":
				body[table+100+30]++
			case "member path":
				member = "../update.mum"
			case "missing member":
				member = "absent.mum"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := extractObservedWIM(ctx, body, member, syntheticLZMS(metadata, solid)); err == nil {
				t.Fatal("corrupt/unimplemented WIM became normalized content")
			}
		})
	}
}

func TestObservedWIMRequiresSourceEmbeddedExplicitSHA256(t *testing.T) {
	body, metadata, solid := syntheticWIM([]byte("abc"))
	// Corrupt the explicit algorithm section while rebinding the synthetic
	// resource hash; digest width alone must never imply SHA256 semantics.
	needle := []byte{'s', 0, 'h', 0, 'a', 0, '2', 0, '5', 0, '6', 0}
	at := bytes.Index(solid, needle)
	copy(solid[at:], []byte{'u', 0, 'n', 0, 'k', 0, 'n', 0, 'o', 0, 'w', 0})
	table := int(binary.LittleEndian.Uint64(body[56:]))
	h := sha1.Sum(solid[3:])
	copy(body[table+150+30:], h[:])
	// Bind metadata's filehash member to the new source hash as a coherent
	// malicious source container. The parser must reject its absent algorithm.
	p := 112
	length := int(binary.LittleEndian.Uint64(metadata[p:]))
	copy(metadata[p+length+64:], h[:])
	mh := sha1.Sum(metadata)
	copy(body[table+30:], mh[:])
	if _, err := extractObservedWIM(context.Background(), body, "update.mum", syntheticLZMS(metadata, solid)); err == nil || !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("unbound source digest algorithm accepted or wrong failure: %v", err)
	}
}

func TestObservedWIMAcceptsObservedZeroLengthEmptySecurityHeader(t *testing.T) {
	body, metadata, solid := syntheticWIM([]byte("abc"))
	binary.LittleEndian.PutUint32(metadata, 0)
	h := sha1.Sum(metadata)
	table := int(binary.LittleEndian.Uint64(body[56:]))
	copy(body[table+30:], h[:])
	got, err := extractObservedWIM(context.Background(), body, "update.mum", syntheticLZMS(metadata, solid))
	if err != nil || string(got.Content) != "abc" {
		t.Fatalf("zero-entry security header does not allocate descriptors: %+v %v", got, err)
	}
}
