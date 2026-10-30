package worker

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// Fixed image positions and a selected-source digest must not choose the input.
func TestAssemblyInspectsReorderedSourceImagesAndReferenceClosure(t *testing.T) {
	for _, count := range []int{1, 3, 24} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			src := model.SourceIdentity{UpdateID: "another-source", BuildLabel: "26300.9818", Architecture: "arm64", Language: "en-us"}
			selection := model.Selection{UpdateID: src.UpdateID, Architecture: src.Architecture, Language: src.Language, Editions: []string{"Professional"}}
			main, mainPath := assemblyWIMFixture(t, "main.WIM", `<WIM><IMAGE INDEX="9"><NAME>Windows Setup Media</NAME></IMAGE><IMAGE INDEX="5"><NAME>PE</NAME><WINDOWS><ARCH>12</ARCH><EDITIONID>WindowsPE</EDITIONID><INSTALLATIONTYPE>WindowsPE</INSTALLATIONTYPE><LANGUAGES><LANGUAGE>en-us</LANGUAGE></LANGUAGES></WINDOWS></IMAGE><IMAGE INDEX="7"><NAME>Windows Pro</NAME><WINDOWS><ARCH>12</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>26300</BUILD><SPBUILD>1</SPBUILD></VERSION><LANGUAGES><LANGUAGE>en-us</LANGUAGE></LANGUAGES></WINDOWS></IMAGE></WIM>`)
			payloads := []model.Payload{main}
			paths := map[model.PayloadIdentity]string{main.Identity: mainPath}
			for i := 0; i < count; i++ {
				p, path := assemblyWIMFixture(t, fmt.Sprintf("ref-%02d.esd", i), `<WIM><IMAGE INDEX="1"><NAME>Reference content</NAME><WINDOWS><ARCH>12</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><LANGUAGES><LANGUAGE>en-us</LANGUAGE></LANGUAGES></WINDOWS></IMAGE></WIM>`)
				payloads = append(payloads, p)
				paths[p.Identity] = path
			}
			manifest, err := model.NewPayloadManifest(src, payloads)
			if err != nil {
				t.Fatal(err)
			}
			layout, image, err := inspectAssemblyMedia(context.Background(), manifest, selection, paths)
			if err != nil {
				t.Fatal(err)
			}
			if layout.Payload != main.Identity || layout.OSIndex != 7 || layout.MediaIndex != 9 || layout.PEIndex != 5 || image.Edition != "Professional" || image.Build != "10.0.26300.1" {
				t.Fatalf("wrong assembly source: %+v %+v", layout, image)
			}
			wanted := assemblyInputPaths(manifest, t.TempDir())
			if len(wanted) != count+1 {
				t.Fatalf("lost exact reference closure: %d", len(wanted))
			}
		})
	}
}

func TestAssemblyMetadataRejectsChangedMaterializedBytesAndCancellation(t *testing.T) {
	p, path := assemblyWIMFixture(t, "input.esd", `<WIM/>`)
	src := model.SourceIdentity{UpdateID: "other", BuildLabel: "any", Architecture: "amd64", Language: "en-us"}
	manifest, err := model.NewPayloadManifest(src, []model.Payload{p})
	if err != nil {
		t.Fatal(err)
	}
	selection := model.Selection{UpdateID: src.UpdateID, Architecture: src.Architecture, Language: src.Language, Editions: []string{"Professional"}}
	if err = os.WriteFile(path, make([]byte, p.Identity.Size), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = inspectAssemblyMedia(context.Background(), manifest, selection, map[model.PayloadIdentity]string{p.Identity: path}); !errors.Is(err, metadata.ErrIntegrity) {
		t.Fatalf("tampered input accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err = inspectAssemblyMedia(ctx, manifest, selection, map[model.PayloadIdentity]string{p.Identity: path}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

// Exporting only the first requested image would silently lose a base edition.
func TestAssemblyReportsMultiBaseLayoutInsteadOfDroppingImages(t *testing.T) {
	xml := `<WIM><IMAGE INDEX="8"><NAME>Windows Setup Media</NAME></IMAGE><IMAGE INDEX="6"><WINDOWS><ARCH>9</ARCH><EDITIONID>WindowsPE</EDITIONID><INSTALLATIONTYPE>WindowsPE</INSTALLATIONTYPE><LANGUAGES><LANGUAGE>en-us</LANGUAGE></LANGUAGES></WINDOWS></IMAGE>`
	for i, edition := range []string{"Professional", "Education"} {
		xml += fmt.Sprintf(`<IMAGE INDEX="%d"><WINDOWS><ARCH>9</ARCH><EDITIONID>%s</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><LANGUAGES><LANGUAGE>en-us</LANGUAGE></LANGUAGES></WINDOWS></IMAGE>`, i+3, edition)
	}
	p, path := assemblyWIMFixture(t, "multi.esd", xml+`</WIM>`)
	src := model.SourceIdentity{UpdateID: "multi", BuildLabel: "26300.9818", Architecture: "amd64", Language: "en-us"}
	manifest, err := model.NewPayloadManifest(src, []model.Payload{p})
	if err != nil {
		t.Fatal(err)
	}
	selection := model.Selection{UpdateID: src.UpdateID, Architecture: src.Architecture, Language: src.Language, Editions: []string{"Professional", "Education"}}
	if _, _, err = inspectAssemblyMedia(context.Background(), manifest, selection, map[model.PayloadIdentity]string{p.Identity: path}); err == nil || !strings.Contains(err.Error(), "2 selected base editions") {
		t.Fatalf("multi-base selection was lost: %v", err)
	}
}

func TestAssemblyInputPathsKeepExactContainerClosure(t *testing.T) {
	var payloads []model.Payload
	for _, name := range []string{"selected.ESD", "reference.WIM", "content.CAB", "update.msu", "app.msix", "metadata.xml"} {
		payload, _ := assemblyWIMFixture(t, name, `<WIM/>`)
		payloads = append(payloads, payload)
	}
	src := model.SourceIdentity{UpdateID: "closure", BuildLabel: "26300.9818", Architecture: "amd64", Language: "en-us"}
	manifest, err := model.NewPayloadManifest(src, payloads)
	if err != nil {
		t.Fatal(err)
	}
	paths := assemblyInputPaths(manifest, t.TempDir())
	if len(paths) != 3 {
		t.Fatalf("wrong assembly closure: %v", paths)
	}
	for _, payload := range payloads {
		ext := strings.ToLower(filepath.Ext(payload.Destination))
		if ext == ".esd" || ext == ".wim" || ext == ".cab" {
			if paths[payload.Identity] == "" || filepath.Ext(paths[payload.Identity]) != ext {
				t.Fatalf("container missing from closure: %s", payload.Destination)
			}
		} else if paths[payload.Identity] != "" {
			t.Fatalf("nonassembly payload included: %s", payload.Destination)
		}
	}
}

func assemblyWIMFixture(t *testing.T, name, xml string) (model.Payload, string) {
	t.Helper()
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
	sum := sha256.Sum256(b)
	p := model.Payload{Destination: name, Identity: model.PayloadIdentity{Size: int64(len(b)), Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, Provenance: model.PackageProvenance{Source: "assembly-fixture", Name: name}}}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p, path
}
