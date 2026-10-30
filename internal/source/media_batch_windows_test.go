package source

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"uupbuilder/internal/download"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

func mediaManyApps(t *testing.T, count, padding int, duplicateLast bool) (model.PayloadManifest, download.Materialized) {
	t.Helper()
	var payloads []model.Payload
	files := download.Materialized{}
	dir := t.TempDir()
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("Example.App%d", i)
		if duplicateLast && i == count-1 {
			name = "Example.App0"
		}
		text := fmt.Sprintf(`<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="%s" Publisher="CN=Example" Version="1.0.0.0" ProcessorArchitecture="amd64"/><Properties><DisplayName>%s</DisplayName></Properties></Package>`, name, strings.Repeat("x", padding))
		var body bytes.Buffer
		z := zip.NewWriter(&body)
		entry, err := z.Create("AppxManifest.xml")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = entry.Write([]byte(text)); err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		raw := body.Bytes()
		sum := sha256.Sum256(raw)
		p := sourcePayload(fmt.Sprintf("app%04d.appx", i), "a")
		p.Identity.Size = int64(len(raw))
		p.Identity.Digest.Value = hex.EncodeToString(sum[:])
		file := filepath.Join(dir, p.Destination)
		if err = os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, p)
		files[p.Identity] = download.CachedFile{Identity: p.Identity, Path: file, SHA256: p.Identity.Digest.Value}
	}
	m, err := model.NewPayloadManifest(sourceIdentity(), payloads)
	if err != nil {
		t.Fatal(err)
	}
	return m, files
}

func TestMediaInventoryBatchesIndependentAppContainers(t *testing.T) {
	m, files := mediaManyApps(t, 300, 0, false)
	inv, err := inspectMediaFiles(context.Background(), m, files, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Documents) != 300 || len(inv.Apps.Packages) != 300 {
		t.Fatalf("lost source manifests: documents=%d packages=%d", len(inv.Documents), len(inv.Apps.Packages))
	}
	for _, app := range inv.Apps.Packages {
		if app.Evidence.Source != m.Source || app.Evidence.Document.Resource.Member != "AppxManifest.xml" || files[app.Evidence.Document.Resource.Payload].Identity != app.Evidence.Document.Resource.Payload {
			t.Fatal("merged manifest lost exact original source binding")
		}
	}
	if err = mediaDocumentBudget(&inv, nil); err != nil {
		t.Fatalf("native completion reapplied per-inspection document cap to aggregate: %v", err)
	}
}

func TestMediaInventoryBatchesKeepGlobalByteBudget(t *testing.T) {
	m, files := mediaManyApps(t, 260, 128<<10, false)
	_, err := inspectMediaFiles(context.Background(), m, files, nil)
	if !errors.Is(err, metadata.ErrLimit) {
		t.Fatalf("aggregate32MiB budget bypassed: %v", err)
	}
}

func TestMediaInventoryBatchesRejectCrossBatchIdentityConflict(t *testing.T) {
	m, files := mediaManyApps(t, 300, 0, true)
	_, err := inspectMediaFiles(context.Background(), m, files, nil)
	if !errors.Is(err, metadata.ErrConflictingMetadata) {
		t.Fatalf("duplicate Appx identity across batches not rejected: %v", err)
	}
}

func TestMediaInventoryBatchesPreserveContainerLimitAndPayloadDiagnostic(t *testing.T) {
	m, files := mediaManyApps(t, 1, 0, false)
	p := m.Payloads[0]
	var raw bytes.Buffer
	z := zip.NewWriter(&raw)
	for i := 0; i < 4097; i++ {
		entry, err := z.Create(fmt.Sprintf("entry%04d", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = entry.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	body := raw.Bytes()
	sum := sha256.Sum256(body)
	old := files[p.Identity]
	p.Identity.Size = int64(len(body))
	p.Identity.Digest.Value = hex.EncodeToString(sum[:])
	if err := os.WriteFile(old.Path, body, 0600); err != nil {
		t.Fatal(err)
	}
	old.Identity = p.Identity
	old.SHA256 = p.Identity.Digest.Value
	files = download.Materialized{p.Identity: old}
	var err error
	m, err = model.NewPayloadManifest(m.Source, []model.Payload{p})
	if err != nil {
		t.Fatal(err)
	}
	_, err = inspectMediaFiles(context.Background(), m, files, nil)
	if !errors.Is(err, metadata.ErrLimit) || !strings.Contains(err.Error(), p.Destination) || !strings.Contains(err.Error(), "providers.Appx") {
		t.Fatalf("per-container limit or exact payload diagnosis lost: %v", err)
	}
}

func TestMediaInventoryAggregateDocumentLimitRemainsFinite(t *testing.T) {
	inv := metadata.Inventory{Documents: make([]metadata.Document, 8193)}
	if err := mediaDocumentBudget(&inv, nil); !errors.Is(err, metadata.ErrLimit) {
		t.Fatalf("aggregate document index unbounded: %v", err)
	}
}
