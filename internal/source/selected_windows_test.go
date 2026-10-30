package source

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"uupbuilder/internal/config"
	"uupbuilder/internal/metadata"
)

func TestSelectedActualAppClosure(t *testing.T) {
	dir := os.Getenv("UUP_BUILDER_U09_PLAN_WORKSPACE")
	if dir == "" {
		t.Skip("actual selected metadata not configured")
	}
	data, e := os.ReadFile(filepath.Join(dir, "selected-app-catalog.json"))
	if e != nil {
		t.Fatal(e)
	}
	var snapshot AppCatalogSnapshot
	if e = json.Unmarshal(data, &snapshot); e != nil {
		t.Fatal(e)
	}
	cfg, e := config.Load(filepath.Join(dir, "iso-settings.toml"))
	if e != nil {
		t.Fatal(e)
	}
	_, settings, e := cfg.Request()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "source-metadata/apps/desktoptargetcompdb_app_neutral.xml.cab"))
	if e != nil {
		t.Fatal(e)
	}
	var ref metadata.DocumentReference
	for _, r := range snapshot.Documents {
		if filepath.Base(filepath.FromSlash(r.Resource.Member)) == "DesktopTargetCompDB_APP_Neutral.xml" {
			ref = r
		}
	}
	if ref.SHA256 == "" {
		for _, r := range snapshot.Documents {
			if r.Resource.Member != "" && len(raw) > 0 {
				ref = r
				break
			}
		}
	}
	// The selection helper validates the CompDB independently; this reference
	// identifies the actual source document, not a synthetic app policy.
	for _, r := range snapshot.Documents {
		if r.Resource.Member != "" {
			b := filepath.Base(filepath.Dir(filepath.FromSlash(r.Resource.Member)))
			if b == "DesktopTargetCompDB_APP_Neutral.xml.cab" || b == "desktoptargetcompdb_app_neutral.xml.cab" {
				ref = r
			}
		}
	}
	got, e := SelectedAppPayloads(context.Background(), snapshot, []metadata.Document{{Reference: ref, Original: raw}}, settings.Apps.Include)
	if e != nil {
		t.Fatal(e)
	}
	if len(got) != 255 {
		t.Fatalf("selected closure = %d, want actual 255", len(got))
	}
}
