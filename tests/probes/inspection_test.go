package probes

import (
	"context"
	"strings"
	"testing"
)

func TestCompDBInspectionReadsIdentityAndRejectsAmbiguousXML(t *testing.T) {
	want := CompDBIdentity{"arm64", "Baseless", "b5347a24-b65f-7c51-ac95-8bdd36d866a1", "10.0.22000.1"}
	got, err := inspectCompDB(context.Background(), strings.NewReader(syntheticXML))
	if err != nil || got != want {
		t.Fatalf("actual CompDB identity=%+v err=%v", got, err)
	}
	for _, test := range []string{
		strings.Replace(syntheticXML, "BuildArch=\"arm64\"", "BuildArch=\"arm64\" BuildArch=\"x86\"", 1),
		strings.Replace(syntheticXML, "<CompDB ", "<!DOCTYPE x><CompDB ", 1),
		syntheticXML + syntheticXML,
		strings.Replace(syntheticXML, "<Packages />", "<Packages>", 1),
		strings.Replace(syntheticXML, "ImageUpdate", "wrong", 1),
		strings.Replace(syntheticXML, "BuildID=\"b5347a24-b65f-7c51-ac95-8bdd36d866a1\"", "", 1),
		strings.Replace(syntheticXML, "<Packages />", strings.Repeat(" ", 4<<20), 1),
	} {
		if _, err := inspectCompDB(context.Background(), strings.NewReader(test)); err == nil {
			t.Fatal("ambiguous/malformed/unbounded XML accepted")
		}
	}
}

const syntheticPackage = `<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Synthetic-Foundation" version="1.0.0.0" processorArchitecture="arm64" publicKeyToken="0123456789abcdef" language="neutral"/></assembly>`
const syntheticPackageHash = "fd7c159055786f78e4c3256bcd621a3e4de6199348c60d5686fa579ea45f5bbe"

func TestPackageInspectionReadsDirectIdentityAndRejectsAmbiguity(t *testing.T) {
	want := PackageIdentity{"Synthetic-Foundation", "1.0.0.0", "arm64", "0123456789abcdef", "neutral"}
	got, err := inspectPackage(context.Background(), strings.NewReader(syntheticPackage))
	if err != nil || got != want {
		t.Fatalf("package=%+v err=%v", got, err)
	}
	for _, bad := range []string{strings.Replace(syntheticPackage, "<assembly ", "<!DOCTYPE assembly><assembly ", 1), strings.Replace(syntheticPackage, "name=\"Synthetic-Foundation\"", "name=\"a\" name=\"b\"", 1), syntheticPackage + syntheticPackage, strings.Replace(syntheticPackage, "</assembly>", "<assemblyIdentity name=\"second\"/></assembly>", 1), strings.Replace(syntheticPackage, "urn:schemas-microsoft-com:asm.v3", "wrong", 1), strings.Replace(syntheticPackage, "processorArchitecture=\"arm64\"", "", 1)} {
		if _, err := inspectPackage(context.Background(), strings.NewReader(bad)); err == nil {
			t.Fatal("ambiguous package XML accepted")
		}
	}
}

func TestIndependentHashInspectionRejectsMissingOrAmbiguousDigest(t *testing.T) {
	got, err := parseCertutilSHA256("localized heading\r\n" + syntheticXMLHash + "\r\nlocalized footer\r\n")
	if err != nil || got != syntheticXMLHash {
		t.Fatalf("hash=%q err=%v", got, err)
	}
	for _, text := range []string{"", "success", syntheticXMLHash + "\n" + unitHash, "garbage" + syntheticXMLHash, strings.Repeat("a", 65), strings.Repeat(" ", 65537)} {
		if _, err := parseCertutilSHA256(text); err == nil {
			t.Fatal("missing/ambiguous hash accepted")
		}
	}
}
