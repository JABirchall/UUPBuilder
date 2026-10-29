package wimcontent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/model"
)

func TestReparseXMLAllocationIsChargedBeforeLowerResultBudget(t *testing.T) {
	m, fs, _, _ := fixture(t, nil)
	b, e := os.ReadFile(fs[0].Path)
	if e != nil {
		t.Fatal(e)
	}
	text := append([]byte("<WIM><!--"), bytes.Repeat([]byte("x"), 128<<10)...)
	text = append(text, []byte("--></WIM>")...)
	xml := make([]byte, len(text)*2)
	for n, v := range text {
		le.PutUint16(xml[n*2:], uint16(v))
	}
	desc(b[72:], uint64(len(xml)), uint64(len(b)), uint64(len(xml)), 2)
	b = append(b, xml...)
	h := sha256.Sum256(b)
	id := fs[0].Identity
	id.Size = int64(len(b))
	id.Digest.Value = hex.EncodeToString(h[:])
	fs[0].Identity = id
	os.WriteFile(fs[0].Path, b, 0600)
	m, e = model.NewPayloadManifest(m.Source, []model.Payload{{Identity: id, Destination: "fixture.esd"}})
	if e != nil {
		t.Fatal(e)
	}
	idx, e := wimindex.Open(context.Background(), m, fs, wimindex.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	called := false
	r, e := decode(context.Background(), m, fs, idx, Limits{MaxResultBytes: 256 << 10}, func(context.Context, Limits) (codec, error) { called = true; return &syntheticCodec{}, nil })
	if r != nil {
		r.Close()
	}
	if !errors.Is(e, ErrLimit) || called {
		t.Fatal("large live XML reparse bypassed lower result budget", e, called)
	}
}
