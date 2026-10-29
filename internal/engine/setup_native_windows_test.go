package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"uupbuilder/internal/engine/source"
)

func setupInspectionFixture(t *testing.T) (*SetupBootArtifact, func()) {
	t.Helper()
	in, media, _, closeParents := setupFixture(t, setupFixtureOptions{})
	r, e := source.BindSetupBoot(context.Background(), in, media, source.Limits{})
	if e != nil {
		t.Fatal(e)
	}
	a, e := BuildSetupBoot(context.Background(), r, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := a.Close(); e != nil {
			t.Error(e)
		}
	})
	return a, closeParents
}

// A catalog label or generated XML must never replace the validated original
// PE identity; the fixture deliberately has catalog build 19045.7811.
func TestSetupReadOnlyBindsOriginalPEAndOutputSummary(t *testing.T) {
	a, _ := setupInspectionFixture(t)
	l, e := beginSetupReadOnly(context.Background(), a)
	if e != nil {
		t.Fatal(e)
	}
	out, runErr := NativeObservation{FormatInteroperable: true}, error(nil)
	defer l.finish(context.Background(), &out, &runErr)
	if a.archive.expected != (ImageInformation{1, "0", "WindowsPE", "WindowsPE", "10.0.19041.1"}) || l.summary != (source.ImageSummary{Directories: 5, Files: 9, TotalBytes: 561, HardlinkBytes: 27}) {
		t.Fatal("not original PE identity and independently counted summaries", a.archive.expected, l.summary)
	}
	r := a.Receipt()
	if r.Source.Oracle.MetadataComplete || r.Complete || r.NativeFilesystemPreservation || r.Archive.WindowsCompatible || r.Archive.NativeFilesystemPreservation {
		t.Fatal("operational capability minted")
	}
}

func TestSetupReadOnlyRejectsInvalidBeforeNative(t *testing.T) {
	for _, a := range []*SetupBootArtifact{nil, {}, {archive: &Artifact{}}} {
		out, e := InspectSetupReadOnly(context.Background(), a)
		if !errors.Is(e, ErrInput) || out.LastOperation != "" || out.Provider.SHA256 != "" {
			t.Fatal("invalid request reached native", out, e)
		}
	}
	for _, kind := range []string{"source", "manifest", "rule", "proof", "summary", "output-proof", "output-recipe", "output-hash", "resource", "missing-recipe", "revoked", "closed", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			a, closeParents := setupInspectionFixture(t)
			ctx := context.Background()
			switch kind {
			case "source":
				a.source.Source.UpdateID = "foreign"
			case "manifest":
				a.source.ManifestDigest = strings.Repeat("0", 64)
			case "rule":
				a.source.RuleDigest = strings.Repeat("0", 64)
			case "proof":
				a.source.ProofDigest = strings.Repeat("0", 64)
			case "summary":
				a.source.OutputSummary.Files++
			case "output-proof":
				a.archive.receipt.ProofDigest = strings.Repeat("0", 64)
			case "output-recipe":
				a.archive.receipt.RecipeDigest = strings.Repeat("0", 64)
			case "output-hash":
				a.archive.receipt.SHA256 = strings.Repeat("0", 64)
			case "resource":
				a.archive.receipt.Resources[0].Size++
			case "missing-recipe":
				a.recipe = nil
			case "revoked":
				closeParents()
			case "closed":
				a.Close()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			out, e := InspectSetupReadOnly(ctx, a)
			if e == nil || out.LastOperation != "" || out.Provider.SHA256 != "" {
				t.Fatal("invalid request reached native", out, e)
			}
		})
	}
}

func TestSetupReadOnlyRetainsArchiveAndRejectsRevocationAfterUse(t *testing.T) {
	a, closeParents := setupInspectionFixture(t)
	l, e := beginSetupReadOnly(context.Background(), a)
	if e != nil {
		t.Fatal(e)
	}
	closed := make(chan error, 1)
	go func() { closed <- a.Close() }()
	select {
	case e := <-closed:
		t.Fatal("Close invalidated archive during inspection", e)
	case <-time.After(20 * time.Millisecond):
	}
	closeParents()
	first := errors.New("first native failure")
	out, runErr := NativeObservation{FormatInteroperable: true}, error(first)
	l.finish(context.Background(), &out, &runErr)
	if out.FormatInteroperable || !errors.Is(runErr, first) || !errors.Is(runErr, os.ErrClosed) {
		t.Fatal("postcheck lost revocation or first failure", out, runErr)
	}
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("archive lock not released")
	}
}

func TestSetupNativeXMLRequiresFourSourceBoundSummaryScalars(t *testing.T) {
	a, _ := setupInspectionFixture(t)
	xml := a.recipe.XML()
	want := source.ImageSummary{Directories: 5, Files: 9, TotalBytes: 561, HardlinkBytes: 27}
	for _, field := range []string{"", "DIRCOUNT", "FILECOUNT", "TOTALBYTES", "HARDLINKBYTES"} {
		changed := want
		switch field {
		case "DIRCOUNT":
			changed.Directories++
		case "FILECOUNT":
			changed.Files++
		case "TOTALBYTES":
			changed.TotalBytes++
		case "HARDLINKBYTES":
			changed.HardlinkBytes++
		}
		im, sum, e := setupImageInformation(xml, changed)
		if field == "" {
			if e != nil || im != (ImageInformation{1, "0", "WindowsPE", "WindowsPE", "10.0.19041.1"}) || sum != want {
				t.Fatal(im, sum, e)
			}
		} else if !errors.Is(e, ErrIntegrity) {
			t.Fatal("summary mismatch accepted", field, e)
		}
	}
}

func TestSetupReadOnlyRejectsNonbootAndForeignArchive(t *testing.T) {
	a, _ := setupInspectionFixture(t)
	d := a.recipe.Descriptor()
	in := writeInput{XML: a.recipe.XML(), HeaderFlags: a.recipe.HeaderFlags(), RecipeDigest: d.RuleDigest, ProofDigest: d.ProofDigest, CheckLive: a.recipe.CheckLive}
	for i := 0; i < d.Resources; i++ {
		id, reader, e := a.recipe.Resource(i)
		if e != nil {
			t.Fatal(e)
		}
		in.Resources = append(in.Resources, inputResource{SHA1: id.SHA1, SHA256: id.SHA256, Size: id.Size, References: id.References, Metadata: i == 0, Reader: reader})
	}
	nonboot, e := writeStandard(context.Background(), in, Limits{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { nonboot.Close() })
	nonboot.expected = a.archive.expected
	for _, candidate := range []*SetupBootArtifact{{archive: nonboot, recipe: a.recipe, source: a.source}, {archive: a.archive, recipe: a.recipe, source: a.source}} {
		if candidate.archive == a.archive {
			candidate.source.Media.ProofDigest = "foreign media"
		}
		out, e := InspectSetupReadOnly(context.Background(), candidate)
		if e == nil || out.LastOperation != "" {
			t.Fatal("unbound boot framing/archive reached native", out, e)
		}
	}
}

func TestCanonicalReadOnlyDoesNotAcceptSetupArtifact(t *testing.T) {
	a, _ := setupInspectionFixture(t)
	out, e := InspectReadOnly(context.Background(), a.archive)
	if !errors.Is(e, ErrInput) || out.LastOperation != "" {
		t.Fatal("canonical OS entry accepted Setup", out, e)
	}
}

func TestSetupNativeXMLRejectsMissingDuplicateAndForeignIdentity(t *testing.T) {
	a, _ := setupInspectionFixture(t)
	xml := a.recipe.XML()
	u := make([]uint16, len(xml)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(xml[i*2:])
	}
	text := string(utf16.Decode(u))
	for _, changed := range []string{
		strings.Replace(text, "<HARDLINKBYTES>27</HARDLINKBYTES>", "", 1),
		strings.Replace(text, "<HARDLINKBYTES>27</HARDLINKBYTES>", "<HARDLINKBYTES>27</HARDLINKBYTES><HARDLINKBYTES>27</HARDLINKBYTES>", 1),
		strings.Replace(text, "<EDITIONID>WindowsPE</EDITIONID>", "<EDITIONID>Professional</EDITIONID>", 1),
		strings.Replace(text, "<BUILD>19041</BUILD>", "<BUILD>19045</BUILD>", 1),
	} {
		if changed == text {
			t.Fatal("fixture edit did not match")
		}
		u := utf16.Encode([]rune(changed))
		b := make([]byte, len(u)*2)
		for i, v := range u {
			binary.LittleEndian.PutUint16(b[i*2:], v)
		}
		if _, _, e := setupImageInformation(b, source.ImageSummary{Directories: 5, Files: 9, TotalBytes: 561, HardlinkBytes: 27}); !errors.Is(e, ErrIntegrity) {
			t.Fatal("unbound native identity/summary accepted", e)
		}
	}
}

func TestSetupReadOnlyRejectsUnknownArchiveCustodyEntry(t *testing.T) {
	a, _ := setupInspectionFixture(t)
	path := filepath.Join(a.archive.store.Path(), "unknown")
	if e := os.WriteFile(path, []byte("foreign entry"), 0600); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(path)
	l, e := beginSetupReadOnly(context.Background(), a)
	if l != nil {
		out, runErr := NativeObservation{}, error(nil)
		l.finish(context.Background(), &out, &runErr)
	}
	if e == nil {
		t.Fatal("unknown archive scope entry accepted")
	}
}
