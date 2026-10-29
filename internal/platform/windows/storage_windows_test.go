package windows

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStorageProbeUsesChosenVolumeAndLeavesMissingDirectoriesUntouched(t *testing.T) {
	root := t.TempDir()
	chosen := filepath.Join(root, "not-created", "scratch")
	before, err := InspectStorage(root)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := InspectStorage(chosen)
	if err != nil {
		t.Fatal(err)
	}
	if actual.ID == "" || actual.ID != before.ID || actual.AvailableBytes == 0 || actual.MaxFileBytes < 5<<30 || actual.Path != chosen {
		t.Fatalf("actual chosen-volume facts: %#v", actual)
	}
	if _, err := os.Stat(filepath.Dir(chosen)); !os.IsNotExist(err) {
		t.Fatalf("preflight created or touched directory: %v", err)
	}
	if actual.Capabilities.Name != "NTFS" {
		t.Fatalf("available test host volume is %s", actual.Capabilities.Name)
	}
}
