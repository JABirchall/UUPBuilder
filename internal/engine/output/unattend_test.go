package output

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"uupbuilder/internal/engine/isocontent"
)

type unusedMasterer struct{}

func (unusedMasterer) Master(context.Context, string, string, isocontent.ISOExpectations) error {
	panic("mastering must not run with incomplete media")
}

func TestMasterRemovesStagedUnattendOnFailure(t *testing.T) {
	answer := filepath.Join(t.TempDir(), "answer.xml")
	if err := os.WriteFile(answer, []byte("<unattend/>"), 0600); err != nil {
		t.Fatal(err)
	}
	req, backend := exportFixtureWithUnattend(t, answer)
	exported, err := Prepare(context.Background(), req, backend)
	if err != nil {
		t.Fatal(err)
	}
	media := t.TempDir()
	_, err = Master(context.Background(), MasterRequest{Plan: req.Plan, Export: exported, MediaDirectory: media, ISOPath: filepath.Join(t.TempDir(), "result.iso"), Label: "U10_SYNTHETIC"}, unusedMasterer{})
	if err == nil {
		t.Fatal("incomplete media accepted")
	}
	if _, err := os.Stat(filepath.Join(media, "autounattend.xml")); !os.IsNotExist(err) {
		t.Fatalf("answer file left after failed mastering: %v", err)
	}
}

func TestStageUnattendCopiesBytesToISORoot(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(t.TempDir(), "answer.xml")
	want := []byte("<unattend>fixture</unattend>\r\n")
	if err := os.WriteFile(source, want, 0600); err != nil {
		t.Fatal(err)
	}
	if err := stageUnattend(context.Background(), root, source); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "autounattend.xml"))
	if err != nil || string(got) != string(want) {
		t.Fatalf("staged bytes %q, error %v", got, err)
	}
}

func TestStageUnattendRejectsMissingEmptyAndConflictingFiles(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "directory", "collision"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(t.TempDir(), "answer.xml")
			switch kind {
			case "empty":
				if err := os.WriteFile(source, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(source, 0700); err != nil {
					t.Fatal(err)
				}
			case "collision":
				if err := os.WriteFile(source, []byte("new"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "AutoUnattend.xml"), []byte("existing"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := stageUnattend(context.Background(), root, source); err == nil {
				t.Fatal("invalid input accepted")
			}
			if kind == "collision" {
				b, err := os.ReadFile(filepath.Join(root, "AutoUnattend.xml"))
				if err != nil || string(b) != "existing" {
					t.Fatalf("existing file changed: %q %v", b, err)
				}
			}
		})
	}
}
