package output

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"uupbuilder/internal/engine/isocontent"
	"uupbuilder/internal/engine/service"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

func TestNativeMasterComponent(t *testing.T) {
	media := os.Getenv("UUP_OUTPUT_MEDIA")
	if media == "" {
		t.Skip("native component source not configured")
	}
	w, err := platform.CreateWorkspace(os.TempDir(), "output-native-component")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	e, err := MediaExpectations(context.Background(), media, "U10_COMPONENT", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	n := Native{Workspace: w}
	path := filepath.Join(w.Path(), "component-only.iso")
	if err = n.Master(context.Background(), media, path, e); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, _ := f.Stat()
	inspection, err := isocontent.InspectWindowsISO(f, s.Size(), e)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verified %d original files, size %d, SHA256 %s", len(inspection.UDFFiles), inspection.Size, inspection.SHA256)
	t.Logf("private component output %s", path)
}

// A complete output-stage exercise using real source media and tiny synthetic
// Windows-labelled image contents. It is not native servicing/Setup acceptance.
func TestNativeSyntheticOutputJourney(t *testing.T) {
	media, exe := os.Getenv("UUP_OUTPUT_MEDIA"), os.Getenv("UUP_OUTPUT_WIMLIB")
	if media == "" || exe == "" {
		t.Skip("native component inputs not configured")
	}
	ctx := context.Background()
	plan := outputPlan(t)
	w, err := platform.CreateWorkspace(os.TempDir(), "output-native-journey")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	n := Native{Workspace: w, WIMLib: exe}
	root := plainPath(w.Path())
	tree := filepath.Join(root, "media")
	if err = os.Mkdir(tree, 0700); err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(media, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(media, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(tree, rel)
		if d.IsDir() {
			return os.MkdirAll(dest, 0700)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		closeErr := out.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
	if err != nil {
		t.Fatal(err)
	}
	small := t.TempDir()
	if err = os.WriteFile(filepath.Join(small, "fixture.txt"), []byte("synthetic image data, not Windows"), 0600); err != nil {
		t.Fatal(err)
	}
	makeWIM := func(path, edition string) File {
		t.Helper()
		if err := n.wim(ctx, []string{"capture", small, path, "--no-acls", "--check"}); err != nil {
			t.Fatal(err)
		}
		if err := n.wim(ctx, []string{"info", path, "1", "--image-property", "WINDOWS/ARCH=9", "--image-property", "WINDOWS/EDITIONID=" + edition, "--image-property", "WINDOWS/LANGUAGES/LANGUAGE=en-GB"}); err != nil {
			t.Fatal(err)
		}
		if edition == "WindowsPE" {
			if err := n.wim(ctx, []string{"info", path, "1", "--boot"}); err != nil {
				t.Fatal(err)
			}
		}
		f, err := fileIdentity(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	customFile := makeWIM(filepath.Join(root, "customized.wim"), plan.CustomizationPlan().Editions[0])
	boot := makeWIM(filepath.Join(tree, "sources/boot.wim"), "WindowsPE")
	custom := service.CustomizedImages{PlanDigest: plan.CustomizationPlan().Digest, WIMPath: customFile.Path, Images: []service.ImageIdentity{{Index: 1, Edition: plan.CustomizationPlan().Editions[0], Architecture: "amd64", Language: "en-GB"}}, Observations: []service.CustomizationObservation{{Edition: plan.CustomizationPlan().Editions[0]}}, Outputs: []jobstore.OutputIdentity{{Path: "customized.wim", Size: customFile.Size, SHA256: customFile.SHA256, Role: "customized-install-image"}}}
	exported, err := Prepare(ctx, ExportRequest{Plan: plan, Customized: custom, Directory: filepath.Join(root, "exported")}, &n)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range exported.Files {
		b, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(tree, "sources", filepath.Base(f.Path)), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	iso := filepath.Join(root, "synthetic-component.iso")
	prepared, err := Master(ctx, MasterRequest{Plan: plan, Export: exported, MediaDirectory: tree, ISOPath: iso, Label: "U10_SYNTHETIC", BootWIM: boot, BootImages: []service.ImageIdentity{{Index: 1, Edition: "WindowsPE", Architecture: "amd64", Language: "en-GB"}}}, &n)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(ctx, plan, iso, prepared)
	if err != nil {
		t.Fatal(err)
	}
	published, err := PublishVerified(ctx, verified, t.TempDir(), "synthetic-component.iso")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := published.Artifact(ctx, plan.Digest(), plan.Manifest().Source)
	if err != nil || artifact.Size == 0 {
		t.Fatalf("destination verification: %+v %v", artifact, err)
	}
	t.Logf("synthetic output round trip passed: size=%d SHA256=%s; retained private local %s", artifact.Size, artifact.SHA256, iso)
}

func TestNativeInternalRepresentations(t *testing.T) {
	exe := os.Getenv("UUP_OUTPUT_WIMLIB")
	if exe == "" {
		t.Skip("pinned native exporter not configured")
	}
	w, err := platform.CreateWorkspace(os.TempDir(), "output-native-export")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	n := Native{Workspace: w, WIMLib: exe}
	ctx := context.Background()
	source := t.TempDir()
	if err = os.WriteFile(filepath.Join(source, "data.txt"), []byte("native output format fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(w.Path(), "fixture.wim")
	if err = n.wim(ctx, []string{"capture", source, plainPath(base), "--no-acls", "--check"}); err != nil {
		t.Fatal(err)
	}
	for _, format := range []model.ImageFormat{model.ImageWIM, model.ImageESD, model.ImageSWM} {
		t.Run(string(format), func(t *testing.T) {
			dir := filepath.Join(w.Path(), string(format))
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(dir, "install."+string(format))
			if err := n.Export(ctx, base, dst, format, 3800); err != nil {
				t.Fatal(err)
			}
			if err := n.VerifyImage(ctx, dst, format); err != nil {
				t.Fatal(err)
			}
			f, err := fileIdentity(ctx, dst)
			if err != nil || f.Size <= 208 {
				t.Fatalf("missing export %v", err)
			}
			t.Logf("native %s size=%d SHA256=%s", format, f.Size, f.SHA256)
		})
	}
}

func TestNativeLargeFileComponent(t *testing.T) {
	media, large := os.Getenv("UUP_OUTPUT_MEDIA"), os.Getenv("UUP_OUTPUT_LARGE_FILE")
	if media == "" || large == "" {
		t.Skip("native large-file component inputs not configured")
	}
	ctx := context.Background()
	original, err := fileIdentity(ctx, large)
	if err != nil {
		t.Fatal(err)
	}
	if original.Size <= 1<<32 {
		t.Fatal("component input does not exceed 4 GiB")
	}
	w, err := platform.CreateWorkspace(os.TempDir(), "output-native-large-component")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	root := plainPath(w.Path())
	tree := filepath.Join(root, "media")
	copyFile := func(src, relative string) {
		t.Helper()
		dst := filepath.Join(tree, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			t.Fatal(err)
		}
		in, err := os.Open(src)
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.Copy(out, in); err != nil {
			out.Close()
			t.Fatal(err)
		}
		if err = out.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"boot/etfsboot.com", "efi/microsoft/boot/efisys.bin", "efi/boot/bootx64.efi"} {
		copyFile(filepath.Join(media, filepath.FromSlash(name)), name)
	}
	copyFile(large, "data/update.msu")
	e, err := MediaExpectations(ctx, tree, "U10_LARGE_COMPONENT", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	n := Native{Workspace: w}
	path := filepath.Join(root, "large-component-only.iso")
	if err = n.Master(ctx, tree, path, e); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := isocontent.InspectWindowsISO(f, s.Size(), e)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range inspection.UDFFiles {
		if file.Path == "data/update.msu" {
			found = file.Size == original.Size && file.SHA256 == original.SHA256
		}
	}
	if !found {
		t.Fatal("large UDF file bytes differ from original source")
	}
	if err = checkFile(ctx, original); err != nil {
		t.Fatal("original source changed: ", err)
	}
	t.Logf("large-file native content verified: input size=%d SHA256=%s; ISO size=%d SHA256=%s; private path=%s", original.Size, original.SHA256, inspection.Size, inspection.SHA256, path)
}
