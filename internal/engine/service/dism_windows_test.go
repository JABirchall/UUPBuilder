package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"reflect"
	"testing"
	"uupbuilder/internal/engine/rules"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
	"uupbuilder/internal/tools"
)

func TestManagedDISMRejectsUnacquiredRuntime(t *testing.T) {
	w, err := platform.CreateWorkspace(t.TempDir(), "managed-dism-test")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err = NewManagedDISM(context.Background(), w, &tools.SelectedRuntime{}); err == nil {
		t.Fatal("unacquired runtime accepted")
	}
}

func TestDISMUsesOrdinaryPathsForOwnedLocalInputs(t *testing.T) {
	got := ordinaryDISMArguments([]string{`/Image:\\?\C:\owned\mount`, `/ScratchDir:\\?\C:\owned\scratch`, `/English`})
	want := []string{`/Image:C:\owned\mount`, `/ScratchDir:C:\owned\scratch`, `/English`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("native paths: %v", got)
	}
}

func TestDISMPackageInspectionKeepsExactIdentityAndState(t *testing.T) {
	text := "Deployment Image Servicing and Management tool\r\nPackage Identity : Package_for_RollupFix~31bf3856ad364e35~amd64~~28000.3365.1.1\r\nState : Install Pending\r\nRelease Type : Security Update\r\n\r\nPackage Identity : Package_for_ServicingStack~31bf3856ad364e35~amd64~~28000.1.1.1\r\nState : Installed\r\nThe operation completed successfully.\r\n"
	packages, err := parsePackages(text)
	if err != nil {
		t.Fatal(err)
	}
	want := []PackageObservation{{Identity: metadata.PackageIdentity{Name: "Package_for_RollupFix", PublicKeyToken: "31bf3856ad364e35", Architecture: "amd64", Version: "28000.3365.1.1"}, State: "Install Pending"}, {Identity: metadata.PackageIdentity{Name: "Package_for_ServicingStack", PublicKeyToken: "31bf3856ad364e35", Architecture: "amd64", Version: "28000.1.1.1"}, State: "Installed"}}
	if !reflect.DeepEqual(packages, want) {
		t.Fatalf("wrong CBS observation: %+v", packages)
	}
	if _, err := parsePackages("Package Identity : invalid\nState : Installed\n"); err == nil {
		t.Fatal("malformed identity accepted")
	}
	if err := verifyPackages([]PackageObservation{{Identity: want[0].Identity, State: "Staged"}}, []metadata.PackageIdentity{want[0].Identity}); err == nil {
		t.Fatal("staged package counted as integrated")
	}
}

func TestPackageVerificationNormalizesCBSNeutralLanguage(t *testing.T) {
	expected := metadata.PackageIdentity{Name: "Package_for_RollupFix", Version: "28000.3365.1.1", PublicKeyToken: "31bf3856ad364e35", Architecture: "amd64", Language: "neutral"}
	actual := expected
	actual.Language = ""
	actual.Name = "Package_for_rollupfix"
	if err := verifyPackages([]PackageObservation{{Identity: actual, State: "Installed"}}, []metadata.PackageIdentity{expected}); err != nil {
		t.Fatalf("equivalent CBS identity rejected: %v", err)
	}
	actual.Architecture = "arm64"
	if err := verifyPackages([]PackageObservation{{Identity: actual, State: "Installed"}}, []metadata.PackageIdentity{expected}); err == nil {
		t.Fatal("wrong architecture satisfied package requirement")
	}
}

func TestDISMRejectsCorruptedStagedUpdateOnReuse(t *testing.T) {
	w, err := platform.CreateWorkspace(t.TempDir(), "stage-update-test")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err = w.MkdirAll("packages"); err != nil {
		t.Fatal(err)
	}
	body := []byte("verified CAB")
	sum := sha256.Sum256(body)
	id := model.PayloadIdentity{Size: int64(len(body)), Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, Provenance: model.PackageProvenance{Source: "fixture", Name: "package.cab"}}
	name := "packages/" + id.Key() + ".cab"
	file, err := w.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("partial stale output")); err != nil {
		t.Fatal(err)
	}
	file.Close()
	d := &DISM{workspace: w}
	_, err = d.stageUpdate(context.Background(), rules.UpdatePlan{Update: metadata.Update{Format: metadata.UpdateCAB, Resource: metadata.ResourceReference{Payload: id}}}, "unused-original.cab")
	if err == nil {
		t.Fatal("corrupted reused staged update accepted")
	}
}
func TestDISMWIMInspectionPreservesIndexEditionAndLanguage(t *testing.T) {
	text := "Index : 2\r\nName : Enterprise\r\nArchitecture : x64\r\nEdition : Enterprise\r\nLanguages :\r\n        en-GB (Default)\r\nThe operation completed successfully.\r\n"
	image, err := parseImage(text)
	if err != nil {
		t.Fatal(err)
	}
	if image.Index != 2 || image.Edition != "Enterprise" || image.Architecture != "amd64" || image.Language != "en-GB" {
		t.Fatalf("wrong image observation: %+v", image)
	}
	if _, err := parseImage("Index : 1\nName : Professional\n"); err == nil {
		t.Fatal("WIM label substituted for missing edition")
	}
}
