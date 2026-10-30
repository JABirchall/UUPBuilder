package service

import (
	"context"
	"errors"
	"testing"

	"uupbuilder/internal/engine/rules"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

// Native cleanup can remove superseded checkpoint identities. Keep the native
// boundary modeled in fixtures while exercising the real servicing verifier.
type checkpointCleanupBackend struct {
	*fixtureBackend
	removed []metadata.PackageIdentity
}

func (b *checkpointCleanupBackend) Cleanup(_ context.Context, mount platform.OwnedMount, _ bool, _ model.Emit) error {
	path := b.mounted[mount.RelativePath]
	image, err := readFixture(path)
	if err != nil {
		return err
	}
	var retained []PackageObservation
	for _, observed := range image.Packages {
		remove := false
		for _, identity := range b.removed {
			remove = remove || samePackage(observed.Identity, identity)
		}
		if !remove {
			retained = append(retained, observed)
		}
	}
	image.Packages = retained
	return writeFixture(path, image)
}

func checkpointPackage(name, version string) metadata.PackageIdentity {
	return metadata.PackageIdentity{Name: name, Version: version, PublicKeyToken: "31bf3856ad364e35", Architecture: "amd64", Language: "neutral"}
}

func TestServicingAcceptsCheckpointPackagesReplacedBeforeFinalInspection(t *testing.T) {
	oldSSU := checkpointPackage("Package_for_ServicingStack_1738", "26100.1738.1.3")
	oldLCU := checkpointPackage("Package_for_RollupFix", "26100.1742.1.10")
	newSSU := checkpointPackage("Package_for_ServicingStack_9815", "26100.9815.1.3")
	newLCU := checkpointPackage("Package_for_RollupFix", "26100.9818.1.42")
	for _, removed := range [][]metadata.PackageIdentity{{oldSSU}, {oldLCU}, {oldSSU, oldLCU}} {
		t.Run(removed[0].Name, func(t *testing.T) {
			req, backend := executorFixture(t, model.UpdatesIntegrate)
			checkpoint := req.Plan.Updates[0]
			checkpoint.ID = "checkpoint"
			checkpoint.Packages = []metadata.PackageIdentity{oldSSU, oldLCU}
			latest := checkpoint
			latest.ID = "latest"
			latest.Predecessors = []string{"checkpoint"}
			latest.Packages = []metadata.PackageIdentity{newSSU, newLCU}
			req.Plan.Updates = []rules.UpdatePlan{checkpoint, latest}
			req.Plan.Strategy = model.ServicingPerEdition
			path, err := req.Transaction.ScratchPath("edition-001.wim")
			if err != nil {
				t.Fatal(err)
			}
			if err = backend.Export(context.Background(), req.Images[0].ImageRef, path, nil); err != nil {
				t.Fatal(err)
			}
			executor := Executor{Backend: &checkpointCleanupBackend{fixtureBackend: backend, removed: removed}}
			if _, err = executor.serviceOne(context.Background(), req, path, "edition-mount-1", "Professional", false, true, map[string]string{}, nil); err != nil {
				t.Fatalf("verified latest cumulative update rejected after checkpoint cleanup: %v", err)
			}
		})
	}
}

func TestStrictPackageVerificationStillRejectsMissingPackages(t *testing.T) {
	want := checkpointPackage("Package_for_ServicingStack_1738", "26100.1738.1.3")
	newer := checkpointPackage("Package_for_ServicingStack_9815", "26100.9815.1.3")
	if err := verifyPackages([]PackageObservation{{Identity: newer, State: "Installed"}}, []metadata.PackageIdentity{want}); !errors.Is(err, ErrVerification) {
		t.Fatalf("per-update verification accepted an unverified replacement: %v", err)
	}
}

func TestIntegratedPackageVerificationRequiresVerifiedApplicableDescendant(t *testing.T) {
	old := checkpointPackage("Package_for_ServicingStack_1738", "26100.1738.1.3")
	latest := checkpointPackage("Package_for_ServicingStack_9815", "26100.9815.1.3")
	tests := []struct {
		name   string
		change func(*rules.UpdatePlan, *[]PackageObservation)
	}{
		{"latest missing", func(_ *rules.UpdatePlan, observed *[]PackageObservation) { *observed = nil }},
		{"only checkpoint remains", func(_ *rules.UpdatePlan, observed *[]PackageObservation) {
			*observed = []PackageObservation{{Identity: old, State: "Installed"}}
		}},
		{"wrong architecture", func(update *rules.UpdatePlan, _ *[]PackageObservation) { update.Packages[0].Architecture = "arm64" }},
		{"wrong OS build", func(update *rules.UpdatePlan, _ *[]PackageObservation) { update.Packages[0].Version = "26200.9815.1.3" }},
		{"wrong family", func(update *rules.UpdatePlan, _ *[]PackageObservation) {
			update.Packages[0].Name = "Package_for_Unrelated_9815"
		}},
		{"wrong publisher", func(update *rules.UpdatePlan, _ *[]PackageObservation) {
			update.Packages[0].PublicKeyToken = "different"
		}},
		{"wrong language", func(update *rules.UpdatePlan, _ *[]PackageObservation) { update.Packages[0].Language = "en-us" }},
		{"lower version", func(update *rules.UpdatePlan, _ *[]PackageObservation) { update.Packages[0].Version = "26100.999.1.3" }},
		{"staged replacement", func(_ *rules.UpdatePlan, observed *[]PackageObservation) { (*observed)[0].State = "Staged" }},
		{"superseded replacement", func(_ *rules.UpdatePlan, observed *[]PackageObservation) { (*observed)[0].State = "Superseded" }},
		{"unplanned replacement", func(_ *rules.UpdatePlan, observed *[]PackageObservation) {
			(*observed)[0].Identity.Version = "26100.9999.1.3"
		}},
		{"no checkpoint dependency", func(update *rules.UpdatePlan, _ *[]PackageObservation) { update.Predecessors = nil }},
		{"external descendant", func(update *rules.UpdatePlan, _ *[]PackageObservation) { update.Integrate = false }},
		{"different edition", func(update *rules.UpdatePlan, _ *[]PackageObservation) { update.Editions = []string{"Enterprise"} }},
		{"different image target", func(update *rules.UpdatePlan, _ *[]PackageObservation) { update.Target = metadata.RoleWinRE }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checkpoint := rules.UpdatePlan{Update: metadata.Update{ID: "checkpoint", Packages: []metadata.PackageIdentity{old}}, Integrate: true}
			update := rules.UpdatePlan{Update: metadata.Update{ID: "latest", Packages: []metadata.PackageIdentity{latest}, Predecessors: []string{"checkpoint"}}, Integrate: true}
			observed := []PackageObservation{{Identity: latest, State: "Installed"}}
			test.change(&update, &observed)
			// Match the planned replacement so mismatched family/build/architecture
			// tests exercise the supersedence boundary, not merely exact matching.
			if len(observed) > 0 && test.name != "unplanned replacement" && test.name != "only checkpoint remains" {
				observed[0].Identity = update.Packages[0]
			}
			if err := verifyIntegratedPackages(observed, []rules.UpdatePlan{checkpoint, update}, "Professional"); !errors.Is(err, ErrVerification) {
				t.Fatalf("invalid replacement satisfied a required package: %v", err)
			}
		})
	}
	for _, state := range []string{"Installed", "Install Pending"} {
		t.Run(state, func(t *testing.T) {
			updates := []rules.UpdatePlan{
				{Update: metadata.Update{ID: "checkpoint", Packages: []metadata.PackageIdentity{old}}, Integrate: true},
				{Update: metadata.Update{ID: "middle", Predecessors: []string{"checkpoint"}, Packages: []metadata.PackageIdentity{checkpointPackage("Package_for_RollupFix", "26100.5000.1.1")}}, Integrate: true},
				{Update: metadata.Update{ID: "latest", Predecessors: []string{"middle"}, Packages: []metadata.PackageIdentity{latest}}, Integrate: true},
			}
			observed := []PackageObservation{{Identity: latest, State: state}, {Identity: updates[1].Packages[0], State: "Installed"}}
			if err := verifyIntegratedPackages(observed, updates, "Professional"); err != nil {
				t.Fatalf("active transitive descendant rejected: %v", err)
			}
			updates[0].Packages = append(updates[0].Packages, checkpointPackage("Package_for_Unrelated", "26100.1.1.1"))
			if err := verifyIntegratedPackages(observed, updates, "Professional"); !errors.Is(err, ErrVerification) {
				t.Fatalf("missing unrelated package accepted: %v", err)
			}
		})
	}
}
