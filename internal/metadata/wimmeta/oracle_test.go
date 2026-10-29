package wimmeta

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/metadata/wimindex"
	"uupbuilder/internal/model"
)

func boundFixture(t *testing.T, b []byte, extra bool, copies ...int) (*wimindex.MetadataArtifact, *wimindex.Index) {
	t.Helper()
	source := make([]byte, 8192)
	copy(source, "MSWIM\x00\x00\x00")
	le.PutUint32(source[8:], 208)
	le.PutUint32(source[12:], 0xe00)
	le.PutUint16(source[40:], 1)
	le.PutUint16(source[42:], 1)
	le.PutUint32(source[44:], 1)
	putResource := func(at int, size, offset uint64, flags byte) {
		le.PutUint64(source[at:], size)
		source[at+7] = flags
		le.PutUint64(source[at+8:], offset)
		le.PutUint64(source[at+16:], size)
	}
	count := 1
	if extra {
		count = 2
	}
	putResource(48, uint64(count*50), 4096, 2)
	putResource(4096, uint64(len(b)), 256, 2)
	le.PutUint16(source[4120:], 1)
	le.PutUint32(source[4122:], 1)
	h := sha1.Sum(b)
	copy(source[4126:], h[:])
	copy(source[256:], b)
	if extra {
		putResource(4146, 7, 2048, 0)
		le.PutUint16(source[4170:], 1)
		le.PutUint32(source[4172:], 1)
		for i := 4176; i < 4196; i++ {
			source[i] = 1
		}
		copy(source[2048:], "witness")
	}
	u := utf16.Encode([]rune(`<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>0</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`))
	x := make([]byte, len(u)*2)
	for i, v := range u {
		le.PutUint16(x[i*2:], v)
	}
	putResource(72, uint64(len(x)), 6000, 2)
	copy(source[6000:], x)
	h256 := sha256.Sum256(source)
	id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(h256[:])}, Size: int64(len(source)), Provenance: model.PackageProvenance{Source: "uupdump:get.php:fixture", Name: "a.esd"}}
	n := 1
	if len(copies) > 0 {
		n = copies[0]
	}
	var payloads []model.Payload
	var fs []metadata.LocalResource
	for i := 0; i < n; i++ {
		v := id
		v.Provenance.Name = string(rune('a'+i)) + ".esd"
		payloads = append(payloads, model.Payload{Identity: v, Destination: v.Provenance.Name})
		path := filepath.Join(t.TempDir(), v.Provenance.Name)
		if err := os.WriteFile(path, source, 0600); err != nil {
			t.Fatal(err)
		}
		fs = append(fs, metadata.LocalResource{Identity: v, Path: path})
	}
	m, err := model.NewPayloadManifest(model.SourceIdentity{UpdateID: "fixture", BuildLabel: "1", Architecture: "x86", Language: "en-us"}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := wimindex.Open(context.Background(), m, fs, wimindex.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	as, err := wimindex.DecodeMetadata(context.Background(), m, fs, idx, wimindex.DecodeLimits{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, a := range as {
			if err := a.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	return as[0], idx
}
func TestPublicOracleIsBoundImmutableAndDigestMatchesSerialization(t *testing.T) {
	a, idx := boundFixture(t, nestedFixture(), false)
	o, err := Parse(context.Background(), a, idx, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	s := o.Snapshot()
	if !s.MetadataVerified || !s.Complete || s.ContentVerified || s.ConversionSupported || len(s.Hardlinks) != 1 || !s.Hardlinks[0].Consistent || len(s.Hardlinks[0].Entries) != 2 {
		t.Fatal("wrong acceptance/hardlink boundary", s.Summary, s.Gaps)
	}
	before, _ := o.MarshalJSON()
	sum := sha256.Sum256(before)
	if o.Digest() != hex.EncodeToString(sum[:]) {
		t.Fatal("digest is not the exact deterministic serialization")
	}
	s.Entries[0].Name = append(s.Entries[0].Name, 42)
	s.Entries[2].Name[0] = 'X'
	s.Entries[2].PathUTF16[1] = 'X'
	s.Entries[2].Streams[0].SHA1 = "changed"
	s.Security[0].Raw[0] = 0
	s.Hardlinks[0].Entries[0] = 99
	s.Receipt.Entry.Ordinal = 99
	after, _ := o.MarshalJSON()
	if !bytes.Equal(before, after) {
		t.Fatal("accessor mutation changed oracle")
	}
	second, err := Parse(context.Background(), a, idx, Limits{})
	if err != nil || second.Digest() != o.Digest() {
		t.Fatal("nondeterministic oracle", err)
	}
	other, otherIndex := boundFixture(t, securityFixture(0), false)
	if result, err := Parse(context.Background(), a, otherIndex, Limits{}); result != nil || !errors.Is(err, ErrInput) {
		t.Fatal("wrong source/index accepted", err)
	}
	if result, err := Parse(context.Background(), &wimindex.MetadataArtifact{}, idx, Limits{}); result != nil || !errors.Is(err, ErrInput) {
		t.Fatal("forged zero artifact accepted", err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := Parse(context.Background(), other, otherIndex, Limits{}); result != nil || err == nil {
		t.Fatal("closed artifact accepted")
	}
	if result, err := Parse(context.Background(), a, idx, Limits{MaxInputBytes: 1}); result != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("input ceiling ignored", err)
	}
}
func TestReferenceSizeComesFromExactIndexWitnessAndMissingStaysUnresolved(t *testing.T) {
	b := nestedFixture()
	for i := 464; i < 484; i++ {
		b[i] = 1
	}
	for _, present := range []bool{false, true} {
		a, idx := boundFixture(t, b, present)
		o, err := Parse(context.Background(), a, idx, Limits{})
		if err != nil {
			t.Fatal(err)
		}
		s := o.Snapshot()
		stream := s.Entries[2].Streams[0]
		if len(s.References) != 1 || stream.SizeKnown != present || stream.Reference != 0 {
			t.Fatal("reference mapping lost", stream, s.References)
		}
		if present {
			if stream.Size != 7 || stream.SizeProvenance != "index-witness" || len(s.References[0].Witnesses) != 1 || s.References[0].Witnesses[0].Entry != 2 {
				t.Fatal("invented stream size/provenance", stream)
			}
		} else if s.Complete || len(s.Gaps) == 0 {
			t.Fatal("missing stream reference treated as complete")
		}
	}
}
func TestFinalArtifactVerificationRejectsChangedTruncatedAndCanceledBytes(t *testing.T) {
	b := nestedFixture()
	h1, h256 := sha1.Sum(b), sha256.Sum256(b)
	r := wimindex.MetadataReceipt{Size: uint64(len(b)), SHA1: hex.EncodeToString(h1[:]), SHA256: hex.EncodeToString(h256[:])}
	changed := bytes.Clone(b)
	changed[100] ^= 1
	for _, body := range [][]byte{changed, b[:len(b)-1]} {
		if err := verifyArtifact(context.Background(), bytes.NewReader(body), r); !errors.Is(err, ErrIntegrity) {
			t.Fatal("changed bytes accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyArtifact(ctx, bytes.NewReader(b), r); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled verification accepted", err)
	}
}

func TestImpossibleResultBudgetFailsBeforeArtifactRead(t *testing.T) {
	a, idx := boundFixture(t, nestedFixture(), false)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if o, err := Parse(context.Background(), a, idx, Limits{MaxResultBytes: 1}); o != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("attempted artifact read before impossible result budget was rejected", err)
	}
}

func TestWitnessAmbiguityAndLoweredCountBudget(t *testing.T) {
	b := nestedFixture()
	for i := 464; i < 484; i++ {
		b[i] = 1
	}
	a, idx := boundFixture(t, b, true, 2)
	o, err := Parse(context.Background(), a, idx, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	s := o.Snapshot()
	if len(s.References) != 1 || !s.References[0].Ambiguous || len(s.References[0].Witnesses) != 2 || s.References[0].Witnesses[0].Payload.Provenance.Name != "a.esd" || s.References[0].Witnesses[1].Payload.Provenance.Name != "b.esd" {
		t.Fatal("original ambiguity/provenance lost", s.References)
	}
	s.References[0].Witnesses[0].Entry = 99
	if o.Snapshot().References[0].Witnesses[0].Entry != 2 {
		t.Fatal("witness accessor aliases result")
	}
	if o, err := Parse(context.Background(), a, idx, Limits{MaxWitnesses: 1}); o != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("witness count not bounded before lookup copy", err)
	}
}

func TestConflictingHardlinkRecordsStayDistinctAndUnresolved(t *testing.T) {
	b := nestedFixture()
	le.PutUint64(b[312:], 124) // /empty creation time conflicts with /Windows/file.
	a, idx := boundFixture(t, b, false)
	o, err := Parse(context.Background(), a, idx, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	s := o.Snapshot()
	if s.Complete || len(s.Hardlinks) != 1 || s.Hardlinks[0].Consistent || s.Entries[2].CreationTime != 123 || s.Entries[3].CreationTime != 124 {
		t.Fatal("hardlink conflict guessed away", s.Hardlinks)
	}
}

func TestHardlinkComparisonUsesTagValuesRatherThanRecordLocations(t *testing.T) {
	b := nestedFixture()[:40]
	b = append(b, diskEntry("", 16, 152)...)
	b = append(b, make([]byte, 8)...)
	b = append(b, diskEntry("Windows", 16, 416)...)
	tag := make([]byte, 16)
	le.PutUint32(tag, 77)
	le.PutUint32(tag[4:], 3)
	copy(tag[8:], []byte{1, 2, 3})
	for _, name := range []string{"empty", "file"} {
		e := diskEntry(name, 32, 0)
		le.PutUint64(e[88:], 7)
		e = append(e, tag...)
		le.PutUint64(e, uint64(len(e)))
		b = append(b, e...)
		b = append(b, make([]byte, 8)...)
	}
	a, idx := boundFixture(t, b, false)
	o, err := Parse(context.Background(), a, idx, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	s := o.Snapshot()
	if len(s.Hardlinks) != 1 || !s.Hardlinks[0].Consistent || s.Entries[2].Tags[0].Offset == s.Entries[3].Tags[0].Offset {
		t.Fatal("source record locations changed hardlink identity", s.Hardlinks)
	}
}
