package providers

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

func resource(t *testing.T, data []byte) metadata.LocalResource {
	t.Helper()
	sum := sha256.Sum256(data)
	id := model.PayloadIdentity{Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, Size: int64(len(data)), Provenance: model.PackageProvenance{Source: "synthetic-provider-test", Name: "opaque.bin"}}
	path := filepath.Join(t.TempDir(), "opaque.bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return metadata.LocalResource{Identity: id, Path: path}
}

// Reading a fixed offset instead of the XML resource descriptor loses this XML.
func TestWIMReadsVerifiedBoundedXMLResource(t *testing.T) {
	xml := []byte(`<WIM><IMAGE INDEX="3"><WINDOWS><ARCH>12</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`)
	b := make([]byte, 256+len(xml))
	copy(b, "MSWIM\x00\x00\x00")
	binary.LittleEndian.PutUint32(b[8:], 208)
	binary.LittleEndian.PutUint32(b[12:], 0xe00)
	binary.LittleEndian.PutUint16(b[40:], 1)
	binary.LittleEndian.PutUint16(b[42:], 1)
	binary.LittleEndian.PutUint64(b[72:], uint64(len(xml))|2<<56)
	binary.LittleEndian.PutUint64(b[80:], 256)
	binary.LittleEndian.PutUint64(b[88:], uint64(len(xml)))
	copy(b[256:], xml)
	r := resource(t, b)
	got, err := (WIM{}).Inspect(context.Background(), r, metadata.Limits{})
	if err != nil || len(got.Documents) != 1 || !bytes.Equal(got.Documents[0].Original, xml) || got.Documents[0].Resource.Payload != r.Identity || got.Documents[0].Format != metadata.FormatWIMXML {
		t.Fatalf("XML not bound to source: %+v %v", got, err)
	}
	b[79] = 6 // Compressed XML is an unimplemented operation, never absent source.
	r = resource(t, b)
	if _, err := (WIM{}).Inspect(context.Background(), r, metadata.Limits{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("compressed XML: %v", err)
	}
	b[79] = 2
	binary.LittleEndian.PutUint64(b[80:], ^uint64(0))
	if _, err := (WIM{}).Inspect(context.Background(), resource(t, b), metadata.Limits{}); !errors.Is(err, metadata.ErrMalformedMetadata) {
		t.Fatalf("overflow: %v", err)
	}
}

func zipBody(t *testing.T, names []string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, name := range names {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(`<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Example.App" Publisher="CN=Example" Version="1.0.0.0" ProcessorArchitecture="arm64"/></Package>`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// An archive filename cannot supply app identities or invent a license.
func TestAppxReadsManifestWithoutClaimingLicenseOrPhase(t *testing.T) {
	r := resource(t, zipBody(t, []string{"AppxManifest.xml"}))
	got, err := (Appx{}).Inspect(context.Background(), r, metadata.Limits{})
	if err != nil || len(got.Documents) != 1 || got.Documents[0].Resource.Member != "AppxManifest.xml" || len(got.Licenses) != 0 || len(got.AppPhases) != 0 {
		t.Fatalf("app result: %+v %v", got, err)
	}
	for _, names := range [][]string{{"AppxManifest.xml", "appxmanifest.XML"}, {"../AppxManifest.xml"}, {"assets/logo.png"}} {
		if _, err := (Appx{}).Inspect(context.Background(), resource(t, zipBody(t, names)), metadata.Limits{}); err == nil {
			t.Fatalf("accepted unsafe/absent manifest: %v", names)
		}
	}
	if err := os.WriteFile(r.Path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Appx{}).Inspect(context.Background(), r, metadata.Limits{}); !errors.Is(err, metadata.ErrIntegrity) {
		t.Fatalf("modified source: %v", err)
	}
}

func TestProvidersRespectCancellationAndDocumentLimits(t *testing.T) {
	r := resource(t, zipBody(t, []string{"AppxManifest.xml"}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Appx{}).Inspect(ctx, r, metadata.Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := (Appx{}).Inspect(context.Background(), r, metadata.Limits{MaxDocumentBytes: 4}); !errors.Is(err, metadata.ErrLimit) {
		t.Fatalf("limit: %v", err)
	}
	if _, err := (Appx{}).Inspect(context.Background(), r, metadata.Limits{MaxTotalBytes: 4}); !errors.Is(err, metadata.ErrLimit) {
		t.Fatalf("aggregate limit: %v", err)
	}
}

func TestEncryptedContainerRemainsMissingCapability(t *testing.T) {
	r := resource(t, zipBody(t, []string{"AppxManifest.xml"}))
	r.Identity.Encryption = model.EncryptionIdentity{Method: "esrp", Fingerprint: strings.Repeat("a", 64)}
	if _, err := (Appx{}).Inspect(context.Background(), r, metadata.Limits{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing decryptor classified as invalid source or bytes: %v", err)
	}
}

func centralZIP(entries int, declared uint16) []byte {
	const localBytes = 30
	b := make([]byte, localBytes+entries*46+22)
	// Local data is irrelevant to reader construction; only central-directory
	// records are interpreted before any selected manifest can be opened.
	for i := 0; i < entries; i++ {
		at := localBytes + i*46
		binary.LittleEndian.PutUint32(b[at:], 0x02014b50)
	}
	end := len(b) - 22
	binary.LittleEndian.PutUint32(b[end:], 0x06054b50)
	binary.LittleEndian.PutUint16(b[end+8:], declared)
	binary.LittleEndian.PutUint16(b[end+10:], declared)
	binary.LittleEndian.PutUint32(b[end+12:], uint32(entries*46))
	binary.LittleEndian.PutUint32(b[end+16:], localBytes)
	return b
}

func TestAppxDirectoryCountsActualRecordsBeforeReaderAllocation(t *testing.T) {
	// 4,097 records with a lying small EOCD count exercises the standard
	// reader's parse-until-terminal behavior, rather than trusting that count.
	body := centralZIP(4097, 1)
	allocs := testing.AllocsPerRun(1, func() {
		_, err := newAppxZIP(context.Background(), bytes.NewReader(body), int64(len(body)))
		if !errors.Is(err, metadata.ErrLimit) {
			t.Errorf("actual entry ceiling not enforced before construction: %v", err)
		}
	})
	if allocs > 64 {
		t.Fatalf("over-budget directory constructed entry objects: allocations=%g", allocs)
	}
	t.Logf("4,097 actual records / EOCD count 1 refused with %g allocations", allocs)
	if _, err := (Appx{}).Inspect(context.Background(), resource(t, body), metadata.Limits{}); !errors.Is(err, metadata.ErrLimit) {
		t.Fatalf("public Appx path bypassed actual-directory preflight: %v", err)
	}
}

type oversizedDirectory struct {
	size         int64
	end          []byte
	centralReads int
}

func (r *oversizedDirectory) ReadAt(p []byte, off int64) (int, error) {
	if off == 0 {
		r.centralReads++
	}
	if off < 0 || off >= r.size {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.size-off)
	clear(p[:n])
	start := r.size - int64(len(r.end))
	for i := int64(0); i < n; i++ {
		if at := off + i - start; at >= 0 && at < int64(len(r.end)) {
			p[i] = r.end[at]
		}
	}
	if n < int64(len(p)) {
		return int(n), io.EOF
	}
	return int(n), nil
}

func TestAppxDirectoryByteBudgetPrecedesDirectoryReads(t *testing.T) {
	end := make([]byte, 22)
	binary.LittleEndian.PutUint32(end, 0x06054b50)
	binary.LittleEndian.PutUint16(end[8:], 1)
	binary.LittleEndian.PutUint16(end[10:], 1)
	binary.LittleEndian.PutUint32(end[12:], (8<<20)+1)
	r := &oversizedDirectory{size: (8 << 20) + 1 + 22, end: end}
	if _, err := newAppxZIP(context.Background(), r, r.size); !errors.Is(err, metadata.ErrLimit) {
		t.Fatalf("central-directory byte ceiling reached parser: %v", err)
	}
	if r.centralReads != 0 {
		t.Fatalf("over-budget central directory was read %d times", r.centralReads)
	}
}

type cancellingDirectory struct {
	io.ReaderAt
	offset int64
	cancel context.CancelFunc
}

func (r cancellingDirectory) ReadAt(p []byte, off int64) (int, error) {
	n, e := r.ReaderAt.ReadAt(p, off)
	if off == r.offset {
		r.cancel()
	}
	return n, e
}

func TestAppxDirectoryCancellationBeforeManifestParsing(t *testing.T) {
	body := centralZIP(1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := cancellingDirectory{bytes.NewReader(body), 30, cancel}
	if _, err := newAppxZIP(ctx, r, int64(len(body))); !errors.Is(err, context.Canceled) {
		t.Fatalf("directory parsing ignored cancellation: %v", err)
	}
}

func zip64Directory(body []byte) []byte {
	oldEnd := len(body) - 22
	b := append([]byte(nil), body[:oldEnd]...)
	var trailer [98]byte
	binary.LittleEndian.PutUint32(trailer[:], 0x06064b50)
	binary.LittleEndian.PutUint64(trailer[4:], 44)
	binary.LittleEndian.PutUint16(trailer[12:], 45)
	binary.LittleEndian.PutUint16(trailer[14:], 45)
	count := uint64(binary.LittleEndian.Uint16(body[oldEnd+10:]))
	binary.LittleEndian.PutUint64(trailer[24:], count)
	binary.LittleEndian.PutUint64(trailer[32:], count)
	binary.LittleEndian.PutUint64(trailer[40:], uint64(binary.LittleEndian.Uint32(body[oldEnd+12:])))
	binary.LittleEndian.PutUint64(trailer[48:], uint64(binary.LittleEndian.Uint32(body[oldEnd+16:])))
	binary.LittleEndian.PutUint32(trailer[56:], 0x07064b50)
	binary.LittleEndian.PutUint64(trailer[64:], uint64(oldEnd))
	binary.LittleEndian.PutUint32(trailer[72:], 1)
	copy(trailer[76:], body[oldEnd:])
	binary.LittleEndian.PutUint16(trailer[84:], 0xffff)
	binary.LittleEndian.PutUint16(trailer[86:], 0xffff)
	binary.LittleEndian.PutUint32(trailer[88:], 0xffffffff)
	binary.LittleEndian.PutUint32(trailer[92:], 0xffffffff)
	return append(b, trailer[:]...)
}

func TestAppxDirectoryZIP64RemainsBoundedAndReadable(t *testing.T) {
	body := zip64Directory(zipBody(t, []string{"AppxManifest.xml"}))
	got, err := (Appx{}).Inspect(context.Background(), resource(t, body), metadata.Limits{})
	if err != nil || len(got.Documents) != 1 || got.Documents[0].Resource.Member != "AppxManifest.xml" {
		t.Fatalf("bounded ZIP64 manifest: %+v %v", got, err)
	}
	bad := append([]byte(nil), body...)
	at := len(bad) - 98
	binary.LittleEndian.PutUint64(bad[at+24:], 4097)
	binary.LittleEndian.PutUint64(bad[at+32:], 4097)
	if _, err := newAppxZIP(context.Background(), bytes.NewReader(bad), int64(len(bad))); !errors.Is(err, metadata.ErrLimit) {
		t.Fatalf("ZIP64 record budget: %v", err)
	}
	bad = append([]byte(nil), body...)
	binary.LittleEndian.PutUint64(bad[at+64:], ^uint64(0))
	if _, err := newAppxZIP(context.Background(), bytes.NewReader(bad), int64(len(bad))); !errors.Is(err, metadata.ErrMalformedMetadata) {
		t.Fatalf("ZIP64 locator overflow: %v", err)
	}
}

type changingDirectory struct {
	body    []byte
	offset  int64
	changed bool
}

func (r *changingDirectory) ReadAt(p []byte, off int64) (int, error) {
	n, err := bytes.NewReader(r.body).ReadAt(p, off)
	if !r.changed && off == r.offset {
		r.changed = true
		end := len(r.body) - 22
		binary.LittleEndian.PutUint16(r.body[end+8:], 0xffff)
		binary.LittleEndian.PutUint16(r.body[end+10:], 0xffff)
	}
	return n, err
}

func TestAppxDirectorySnapshotPinsValidatedMetadata(t *testing.T) {
	body := centralZIP(1, 1)
	r := &changingDirectory{body: body, offset: 30}
	z, err := newAppxZIP(context.Background(), r, int64(len(body)))
	if err != nil || len(z.File) != 1 || !r.changed {
		t.Fatalf("mutable source replaced validated directory: entries=%v changed=%v %v", z, r.changed, err)
	}
}

type betweenDirectoryReads struct {
	body                    []byte
	mutateAfter, tailOffset int64
	mutate                  func([]byte)
	changed, tailCopied     bool
	readsAfterTail          int
}

func (r *betweenDirectoryReads) ReadAt(p []byte, off int64) (int, error) {
	if r.tailCopied {
		r.readsAfterTail++
	}
	n, err := bytes.NewReader(r.body).ReadAt(p, off)
	if !r.changed && off == r.mutateAfter {
		r.mutate(r.body)
		r.changed = true
	}
	if off == r.tailOffset && int64(n) == int64(len(r.body))-r.tailOffset {
		r.tailCopied = true
	}
	return n, err
}

// Initial descriptors authorize only the last of 4,097 central records. The
// source changes after that descriptor copy but before the final tail copy.
// The exact immutable metadata passed to archive/zip must be checked again.
func TestAppxDirectoryRejectsBetweenReadDescriptorChanges(t *testing.T) {
	const entries = 4097
	ordinary := centralZIP(entries, 1)
	oldOffset := int64(30 + (entries-1)*46)
	end := len(ordinary) - 22
	binary.LittleEndian.PutUint32(ordinary[end+12:], 46)
	binary.LittleEndian.PutUint32(ordinary[end+16:], uint32(oldOffset))
	z64 := zip64Directory(ordinary)
	for _, tc := range []struct {
		name   string
		body   []byte
		after  int64
		mutate func([]byte)
	}{
		{"EOCD", ordinary, int64(len(ordinary) - min(len(ordinary), 65557)), func(b []byte) {
			at := len(b) - 22
			binary.LittleEndian.PutUint16(b[at+8:], entries)
			binary.LittleEndian.PutUint16(b[at+10:], entries)
			binary.LittleEndian.PutUint32(b[at+12:], entries*46)
			binary.LittleEndian.PutUint32(b[at+16:], 30)
		}},
		{"ZIP64-end", z64, int64(len(z64) - 98), func(b []byte) {
			at := len(b) - 98
			binary.LittleEndian.PutUint64(b[at+24:], entries)
			binary.LittleEndian.PutUint64(b[at+32:], entries)
			binary.LittleEndian.PutUint64(b[at+40:], entries*46)
			binary.LittleEndian.PutUint64(b[at+48:], 30)
		}},
		{"ZIP64-locator", z64, int64(len(z64) - 42), func(b []byte) { binary.LittleEndian.PutUint64(b[len(b)-34:], ^uint64(0)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(1, func() {
				r := &betweenDirectoryReads{body: append([]byte(nil), tc.body...), mutateAfter: tc.after, tailOffset: oldOffset, mutate: tc.mutate}
				z, err := newAppxZIP(context.Background(), r, int64(len(r.body)))
				count := 0
				if z != nil {
					count = len(z.File)
				}
				if !r.changed || !r.tailCopied || !errors.Is(err, metadata.ErrIntegrity) || z != nil {
					t.Errorf("unchecked replacement descriptor reached constructor: changed=%v snapshot=%v entries=%d err=%v", r.changed, r.tailCopied, count, err)
				}
				if r.readsAfterTail != 0 {
					t.Errorf("reader construction followed descriptor mismatch: source reads after snapshot=%d", r.readsAfterTail)
				}
			})
			if allocs > 64 {
				t.Fatalf("replacement descriptor allocated entries: allocations=%g", allocs)
			}
			t.Logf("between-read descriptor replacement refused with %g allocations", allocs)
		})
	}
}
