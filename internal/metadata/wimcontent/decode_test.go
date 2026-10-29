package wimcontent

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/model"
	"uupbuilder/internal/rawlzms"
)

var le = binary.LittleEndian

func desc(b []byte, size, off, logical uint64, flags byte) {
	le.PutUint64(b, size)
	b[7] = flags
	le.PutUint64(b[8:], off)
	le.PutUint64(b[16:], logical)
}
func fixture(t *testing.T, mutate func([]byte)) (model.PayloadManifest, []metadata.LocalResource, *wimindex.Index, [][]byte) {
	t.Helper()
	want := [][]byte{bytes.Repeat([]byte("A"), 32766), []byte("AAtail!"), []byte("ordinary"), []byte("AAtail!")}
	b := make([]byte, 8222)
	copy(b, "MSWIM\x00\x00\x00")
	le.PutUint32(b[8:], 208)
	le.PutUint32(b[12:], 0xe00)
	le.PutUint16(b[40:], 1)
	le.PutUint16(b[42:], 1)
	desc(b[48:], 300, 4096, 300, 2)
	u := utf16.Encode([]rune("<WIM></WIM>"))
	for n, v := range u {
		le.PutUint16(b[6000+n*2:], v)
	}
	desc(b[72:], uint64(len(u)*2), 6000, uint64(len(u)*2), 2)
	for n := 0; n < 6; n++ {
		r := b[4096+n*50:]
		le.PutUint16(r[24:], 1)
		le.PutUint32(r[26:], 1)
	}
	desc(b[4096:], 30, 8192, 1<<32, 16)
	desc(b[4146:], 32766, 0, 0, 16)
	desc(b[4196:], 7, 32766, 0, 16)
	desc(b[4246:], 8, 7000, 8, 0)
	desc(b[4296:], 30, 8192, 1<<32, 16)
	desc(b[4346:], 7, 32766, 0, 16)
	for n, ordinal := range []int{1, 2, 3, 5} {
		h := sha1.Sum(want[n])
		copy(b[4096+ordinal*50+30:], h[:])
	}
	copy(b[7000:], want[2])
	le.PutUint64(b[8192:], 32773)
	le.PutUint32(b[8200:], 32768)
	le.PutUint32(b[8204:], 3)
	le.PutUint32(b[8208:], 1)
	le.PutUint32(b[8212:], 5)
	copy(b[8216:], "Ztail!")
	if mutate != nil {
		mutate(b)
	}
	h := sha256.Sum256(b)
	id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(h[:])}, Size: int64(len(b)), Provenance: model.PackageProvenance{Source: "uupdump:get.php:fixture", Name: "fixture.esd"}}
	path := filepath.Join(t.TempDir(), "fixture.esd")
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	m, e := model.NewPayloadManifest(model.SourceIdentity{UpdateID: "fixture", BuildLabel: "1", Architecture: "x86", Language: "en-us"}, []model.Payload{{Identity: id, Destination: "fixture.esd"}})
	if e != nil {
		t.Fatal(e)
	}
	fs := []metadata.LocalResource{{Identity: id, Path: path}}
	idx, e := wimindex.Open(context.Background(), m, fs, wimindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	return m, fs, idx, want
}

// Private synthetic codec exercises the real framing, all original digest
// witnesses, custody and publication. It supplies no production/native proof.
type syntheticCodec struct {
	mode   string
	calls  int
	mutate func()
}

func (c *syntheticCodec) Identity() rawlzms.Identity {
	return rawlzms.Identity{Name: "synthetic-test-only"}
}
func (c *syntheticCodec) Close() error {
	if c.mode == "close" {
		return errors.New("injected close failure")
	}
	return nil
}
func (c *syntheticCodec) DecodeInto(ctx context.Context, in, out []byte) error {
	c.calls++
	if c.mutate != nil {
		c.mutate()
	}
	if string(in) != "Z" || len(out) != 32768 {
		return errors.New("unexpected synthetic port call")
	}
	if c.mode != "noop" {
		for n := range out {
			out[n] = 'A'
		}
	}
	if c.mode == "wrong" {
		out[0] = 'X'
	}
	if c.mode == "error" {
		return errors.New("injected codec error")
	}
	return ctx.Err()
}
func run(t *testing.T, c *syntheticCodec, l Limits) (*Result, error, [][]byte) {
	m, fs, idx, want := fixture(t, nil)
	r, e := decode(context.Background(), m, fs, idx, l, func(context.Context, Limits) (codec, error) { return c, nil })
	return r, e, want
}
func TestDecodeVerifiesCrossChunkAliasesAndReadOnlyOwnedIntervals(t *testing.T) {
	c := &syntheticCodec{}
	r, e, want := run(t, c, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	s := r.Catalog().Snapshot()
	if len(s.Witnesses) != 4 || len(s.Backings) != 2 || s.DecodedBytes != 32781 || !s.NonMetadataVerified || s.ContentVerified || s.ConversionSupported || c.calls != 1 {
		t.Fatal("incomplete or exaggerated byte proof", s, c.calls)
	}
	for n, w := range s.Witnesses {
		a, e := r.Content(n)
		if e != nil {
			t.Fatal(e)
		}
		got, e := io.ReadAll(io.NewSectionReader(a, 0, int64(w.Size)))
		if e != nil || !bytes.Equal(got, want[n]) {
			t.Fatal(n, e)
		}
		h := sha256.Sum256(want[n])
		if w.SHA256 != hex.EncodeToString(h[:]) {
			t.Fatal("wrong logical identity")
		}
	}
	s.Witnesses[0].Entry.SHA1 = "mutated"
	if r.Catalog().Snapshot().Witnesses[0].Entry.SHA1 == "mutated" {
		t.Fatal("mutable receipt")
	}
	a, _ := r.Content(0)
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = a.ReadAt(make([]byte, 1), 0); !errors.Is(e, os.ErrClosed) {
		t.Fatal("borrower remained live", e)
	}
}
func TestWrongNoopOrFailedCodecCannotPublishPartialContent(t *testing.T) {
	for _, mode := range []string{"wrong", "noop", "error", "close"} {
		t.Run(mode, func(t *testing.T) {
			r, e, _ := run(t, &syntheticCodec{mode: mode}, Limits{})
			if r != nil {
				r.Close()
			}
			if e == nil || r != nil {
				t.Fatal("bad codec published", e)
			}
		})
	}
}
