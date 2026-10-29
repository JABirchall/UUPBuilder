package providers

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
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
