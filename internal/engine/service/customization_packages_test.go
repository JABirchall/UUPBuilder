package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"uupbuilder/internal/metadata"
)

func TestCustomizationPreservesPackageInstallationRequirements(t *testing.T) {
	identity := metadata.PackageIdentity{
		Name:           "Microsoft-OneCore-ApplicationModel-Sync-Desktop-FOD-Package",
		Version:        "10.0.26100.1742",
		PublicKeyToken: "31bf3856ad364e35",
		Architecture:   "amd64",
	}
	for _, test := range []struct {
		name, before, after string
		wantError           bool
	}{
		{"staged FoD remains staged", "Staged", "Staged", false},
		{"staged FoD is absent", "Staged", "", false},
		{"absent FoD remains absent", "Not Present", "Not Present", false},
		{"installed package remains installed", "Installed", "Installed", false},
		{"pending package completes installation", "Install Pending", "Installed", false},
		{"superseded package remains superseded", "Superseded", "Superseded", false},
		{"installed package becomes staged", "Installed", "Staged", true},
		{"installed package disappears", "Installed", "", true},
		{"pending package disappears", "Install Pending", "", true},
		{"superseded package disappears", "Superseded", "", true},
		{"unknown state is not exempt", "Unknown", "Unknown", true},
		{"empty state is not exempt", "", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			req, backend := customizationRequestFixture(t)
			image, err := readFixture(req.Images[0].WIMPath)
			if err != nil {
				t.Fatal(err)
			}
			if test.after != "" {
				image.Packages = []PackageObservation{{Identity: identity, State: test.after}}
			}
			if err = writeFixture(req.Images[0].WIMPath, image); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(req.Images[0].WIMPath)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(body)
			for i := range req.Images {
				req.Images[i].SHA256 = hex.EncodeToString(sum[:])
				req.Images[i].Identity.Packages = []PackageObservation{{Identity: identity, State: test.before}}
			}
			result, err := (&CustomizationExecutor{Backend: backend}).Execute(context.Background(), req, nil)
			if test.wantError {
				if !errors.Is(err, ErrVerification) {
					t.Fatalf("lost installed package was not rejected: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid package state rejected during customization: %v", err)
			}
			if len(result.Images) != 2 {
				t.Fatalf("customization did not produce both editions: %+v", result.Images)
			}
		})
	}
}
