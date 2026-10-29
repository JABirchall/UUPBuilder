package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
	"uupbuilder/internal/engine/source"
	"uupbuilder/internal/model"
)

func TestNativeXMLKeepsOriginalBaselineIdentity(t *testing.T) {
	for _, text := range []string{`<IMAGE INDEX="1"><WINDOWS><ARCH>0</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>19041</BUILD><SPBUILD>1</SPBUILD></VERSION></WINDOWS></IMAGE>`, `<WIM><IMAGE INDEX="1"><WINDOWS><ARCH>0</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>19041</BUILD><SPBUILD>1</SPBUILD></VERSION></WINDOWS></IMAGE></WIM>`} {
		u := utf16.Encode([]rune(text))
		b := make([]byte, len(u)*2)
		for n, v := range u {
			binary.LittleEndian.PutUint16(b[n*2:], v)
		}
		s, e := imageInformation(b)
		if e != nil || s != (ImageInformation{1, "0", "Professional", "Client", "10.0.19041.1"}) {
			t.Fatal(s, e)
		}
	}
}

func TestNativeExpectedIdentityComesFromOriginalRecipe(t *testing.T) {
	d := source.Descriptor{Recipe: source.Recipe{Source: model.SourceIdentity{Architecture: "x86"}, Edition: "Professional", BaselineVersion: "10.0.19041.1"}}
	got, e := expectedImage(d)
	if e != nil || got != (ImageInformation{1, "0", "Professional", "Client", "10.0.19041.1"}) {
		t.Fatal(got, e)
	}
	d.Recipe.BaselineVersion = ""
	if _, e = expectedImage(d); !errors.Is(e, ErrInput) {
		t.Fatal("missing source expectations", e)
	}
}

func TestNativeCacheRejectsOwnerReplacementAndLatchesCleanup(t *testing.T) {
	temp, e := newNativeTemp()
	if e != nil {
		t.Fatal(e)
	}
	path := temp.workspace.Path()
	marker := filepath.Join(path, ".uupbuilder-owner.json")
	if e = os.WriteFile(marker, []byte("foreign owner"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = temp.Check(); !errors.Is(e, ErrIntegrity) {
		t.Fatal("foreign owner accepted", e)
	}
	first := temp.Close()
	if first == nil || temp.Close() != first {
		t.Fatal("cleanup not latched", first)
	}
	// The component must preserve the changed entry. This test removes only its
	// deliberately changed marker and exact still-identical fresh directory.
	info, e := os.Stat(path)
	if e != nil || !os.SameFile(info, temp.initial) {
		t.Fatal("cache custody changed", e)
	}
	if e = os.Remove(marker); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
}

func TestNativeInspectionRequiresPrivateSourceBoundVerifiedArtifact(t *testing.T) {
	for _, a := range []*Artifact{nil, {}, {receipt: Receipt{BytesVerified: true}}} {
		if _, e := InspectReadOnly(context.Background(), a); !errors.Is(e, ErrInput) {
			t.Fatal("unbound native request", e)
		}
	}
	a, e := writeStandard(context.Background(), inputFixture(), Limits{})
	if e != nil {
		t.Fatal(e)
	}
	a.Close()
	if _, e = InspectReadOnly(context.Background(), a); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
}
