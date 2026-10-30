package providers

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// Opt-in functional parser check for this task's actual downloaded app closure.
// This is read-only metadata evidence, never native provisioning acceptance.
func TestSelectedAppPayloadManifests(t *testing.T) {
	path := os.Getenv("UUP_BUILDER_U09_APP_RECEIPT")
	if path == "" {
		t.Skip("set UUP_BUILDER_U09_APP_RECEIPT to a prepared source receipt")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var receipt struct {
		Manifest model.PayloadManifest
		Files    []struct {
			Path     string
			Identity model.PayloadIdentity
		}
	}
	if e = json.Unmarshal(data, &receipt); e != nil {
		t.Fatal(e)
	}
	if receipt.Manifest.Validate() != nil || len(receipt.Files) == 0 {
		t.Fatal("invalid prepared source receipt")
	}
	packages, bundles := 0, 0
	for _, file := range receipt.Files {
		found := false
		for _, p := range receipt.Manifest.Payloads {
			found = found || p.Identity == file.Identity
		}
		if !found {
			t.Fatal("unbound prepared payload")
		}
		result, e := (Appx{}).Inspect(context.Background(), metadata.LocalResource{Identity: file.Identity, Path: file.Path}, metadata.Limits{})
		if e != nil {
			t.Fatalf("%s: %v", file.Identity.Provenance.Name, e)
		}
		if len(result.Documents) != 1 {
			t.Fatalf("%s: missing manifest", file.Identity.Provenance.Name)
		}
		d := result.Documents[0]
		if d.Format == metadata.FormatAppxBundleXML {
			bundles++
		} else {
			packages++
		}
	}
	t.Logf("actual source closure: %d verified package manifests, %d verified bundle manifests; provisioning and native stub state remain pending", packages, bundles)
}
