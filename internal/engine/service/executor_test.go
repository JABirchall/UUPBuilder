package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"uupbuilder/internal/config"
	"uupbuilder/internal/engine/rules"
	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
)

// This backend models image contents for executor control-flow tests. It is not
// native servicing evidence. Real DISM is tested separately without elevation.
type imageFixture struct {
	Images        []ImageIdentity
	Packages      []PackageObservation
	Customization CustomizationObservation
}
type fixtureBackend struct {
	mounted                 map[string]string
	omitPackage, wrongFinal bool
	failMount               bool
}

func readFixture(path string) (imageFixture, error) {
	var v imageFixture
	b, e := os.ReadFile(path)
	if e != nil {
		return v, e
	}
	e = json.Unmarshal(b, &v)
	return v, e
}
func writeFixture(path string, v imageFixture) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return os.WriteFile(path, b, 0600)
}
func (f *fixtureBackend) Check(context.Context, ServiceRequest) error { return nil }
func (f *fixtureBackend) Export(_ context.Context, src ImageRef, dst string, _ model.Emit) error {
	v, e := readFixture(src.WIMPath)
	if e != nil {
		return e
	}
	if src.Index < 1 || src.Index > len(v.Images) {
		return errors.New("bad fixture index")
	}
	image := v.Images[src.Index-1]
	out, e := readFixture(dst)
	if !errors.Is(e, os.ErrNotExist) && e != nil {
		return e
	}
	image.Index = len(out.Images) + 1
	out.Images = append(out.Images, image)
	out.Packages = append(out.Packages, v.Packages...)
	return writeFixture(dst, out)
}
func (f *fixtureBackend) Mount(_ context.Context, path string, m platform.OwnedMount, _ model.Emit) error {
	f.mounted[m.RelativePath] = path
	if f.failMount {
		return errors.New("mount failed after partial creation")
	}
	return nil
}
func (f *fixtureBackend) Inspect(_ context.Context, m platform.OwnedMount, _ model.Emit) (Inspection, error) {
	v, e := readFixture(f.mounted[m.RelativePath])
	if e != nil {
		return Inspection{}, e
	}
	return Inspection{Edition: v.Images[0].Edition, Packages: v.Packages}, nil
}
func (f *fixtureBackend) Apply(_ context.Context, m platform.OwnedMount, u rules.UpdatePlan, _ string, _ model.Emit) error {
	if f.omitPackage {
		return nil
	}
	path := f.mounted[m.RelativePath]
	v, e := readFixture(path)
	if e != nil {
		return e
	}
	for _, id := range u.Packages {
		v.Packages = append(v.Packages, PackageObservation{Identity: id, State: "Installed"})
	}
	return writeFixture(path, v)
}
func (f *fixtureBackend) SetEdition(_ context.Context, m platform.OwnedMount, edition string, _ model.Emit) error {
	path := f.mounted[m.RelativePath]
	v, e := readFixture(path)
	if e != nil {
		return e
	}
	v.Images[0].Edition = edition
	return writeFixture(path, v)
}
func (f *fixtureBackend) Cleanup(context.Context, platform.OwnedMount, bool, model.Emit) error {
	return nil
}
func (f *fixtureBackend) Unmount(_ context.Context, m platform.OwnedMount, _ bool, _ model.Emit) error {
	delete(f.mounted, m.RelativePath)
	return nil
}
func (f *fixtureBackend) InspectWIM(_ context.Context, path string, _ model.Emit) ([]ImageIdentity, error) {
	v, e := readFixture(path)
	if f.wrongFinal && len(v.Images) > 1 {
		v.Images[0].Edition = "Professional"
	}
	return v.Images, e
}

func executorFixture(t *testing.T, policy model.UpdatePolicy) (ServiceRequest, *fixtureBackend) {
	t.Helper()
	ctx := context.Background()
	parent := t.TempDir()
	store, e := jobstore.Create(parent, "service-test", nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := store.Close(); e != nil {
			t.Error(e)
		}
	})
	source := model.SourceIdentity{UpdateID: "service-test", BuildLabel: "28000.3365", Architecture: "amd64", Language: "en-gb"}
	updateBytes := []byte("verified update bytes")
	sum := sha256.Sum256(updateBytes)
	payload := model.Payload{Destination: "update.msu", Identity: model.PayloadIdentity{Size: int64(len(updateBytes)), Digest: model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, Provenance: model.PackageProvenance{Source: "fixture", Name: "update.msu"}}}
	manifest, e := model.NewPayloadManifest(source, []model.Payload{payload})
	if e != nil {
		t.Fatal(e)
	}
	inv := metadata.Inventory{Source: source, Manifest: manifest, Images: []metadata.Image{{Index: 1, Edition: "Professional", Build: "10.0.28000.1", Architecture: "amd64"}}, EditionBases: []metadata.EditionBase{{Edition: "Enterprise", Base: "Professional"}}, Updates: []metadata.Update{{ID: "lcu", Kind: metadata.UpdateCumulative, Format: metadata.UpdateMSU, Resource: metadata.ResourceReference{Payload: payload.Identity}, Packages: []metadata.PackageIdentity{{Name: "Package_for_RollupFix", Version: "28000.3365.1.1", PublicKeyToken: "31bf3856ad364e35", Architecture: "amd64"}}}}}
	c := config.Defaults()
	c.Image.UpdateID = "service-test"
	_, settings, e := c.Request()
	if e != nil {
		t.Fatal(e)
	}
	settings.Conversion.Updates = policy
	settings.Conversion.Editions.Derived = []string{"Enterprise"}
	settings.Output.EditionOrder = []string{"Enterprise", "Professional"}
	plan, e := planner.BuildServicePlan(inv, settings)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := store.Begin(ctx, jobstore.MutationIntent{JobID: "service-test", PlanDigest: plan.Digest, ConfigDigest: plan.Digest, StageID: "service-image", Inputs: []jobstore.NamedDigest{{Name: "service-plan", Digest: plan.Digest}}, OwnedPaths: plan.OutputPaths()})
	if e != nil {
		t.Fatal(e)
	}
	imagePath := filepath.Join(parent, "source.wim")
	if e := writeFixture(imagePath, imageFixture{Images: []ImageIdentity{{Index: 1, Edition: "Professional", Architecture: "amd64", Language: "en-gb"}}}); e != nil {
		t.Fatal(e)
	}
	imageBytes, e := os.ReadFile(imagePath)
	if e != nil {
		t.Fatal(e)
	}
	imageSum := sha256.Sum256(imageBytes)
	updatePath := filepath.Join(parent, "source.msu")
	if e := os.WriteFile(updatePath, updateBytes, 0600); e != nil {
		t.Fatal(e)
	}
	req := ServiceRequest{Plan: plan, Transaction: tx, Images: []InspectedImage{{ImageRef: ImageRef{WIMPath: imagePath, Index: 1}, Identity: ImageIdentity{Index: 1, Edition: "Professional", Architecture: "amd64", Language: "en-gb"}, SHA256: hex.EncodeToString(imageSum[:])}}, Payloads: []UpdateInput{{Resource: metadata.ResourceReference{Payload: payload.Identity}, Path: updatePath}}}
	return req, &fixtureBackend{mounted: map[string]string{}}
}

func TestFinalEditionInventoryMatchesPlan(t *testing.T) {
	req, backend := executorFixture(t, model.UpdatesIntegrate)
	result, e := (&Executor{Backend: backend}).Execute(context.Background(), req, nil)
	if e != nil {
		t.Fatal(e)
	}
	var editions []string
	for i, image := range result.Images {
		if image.Index != i+1 {
			t.Fatalf("wrong image index: %+v", image)
		}
		editions = append(editions, image.Edition)
	}
	if !reflect.DeepEqual(editions, []string{"Enterprise", "Professional"}) {
		t.Fatalf("final order/base leakage: %v", editions)
	}
	if result.WIMPath == "" || len(result.Outputs) == 0 {
		t.Fatal("no concrete final image artifact")
	}
}

func TestSuccessfulHelperMissingPackageFailsStage(t *testing.T) {
	req, b := executorFixture(t, model.UpdatesIntegrate)
	b.omitPackage = true
	if _, e := (&Executor{Backend: b}).Execute(context.Background(), req, nil); !errors.Is(e, ErrVerification) {
		t.Fatalf("missing required package accepted: %v", e)
	}
}
func TestFinalInspectionRejectsWrongEdition(t *testing.T) {
	req, b := executorFixture(t, model.UpdatesIntegrate)
	b.wrongFinal = true
	if _, e := (&Executor{Backend: b}).Execute(context.Background(), req, nil); !errors.Is(e, ErrVerification) {
		t.Fatalf("wrong final edition accepted: %v", e)
	}
}
func TestExternalPolicyCopiesWithoutInstalling(t *testing.T) {
	req, b := executorFixture(t, model.UpdatesExternal)
	b.omitPackage = true
	result, e := (&Executor{Backend: b}).Execute(context.Background(), req, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(result.RetainedUpdates) != 1 {
		t.Fatal("external update missing")
	}
	for _, out := range result.Images {
		if len(out.Packages) != 0 {
			t.Fatal("external updates entered image")
		}
	}
}
func TestExecutorRejectsInactiveTransaction(t *testing.T) {
	req, b := executorFixture(t, model.UpdatesOmit)
	if e := req.Transaction.Commit(context.Background(), nil); e == nil {
		t.Fatal("empty checkpoint unexpectedly accepted")
	}
	if _, e := (&Executor{Backend: b}).Execute(context.Background(), req, nil); e == nil {
		t.Fatal("inactive transaction accepted")
	}
}

func TestPartialMountFailureAttemptsOwnedCleanup(t *testing.T) {
	req, backend := executorFixture(t, model.UpdatesOmit)
	backend.failMount = true
	if _, err := (&Executor{Backend: backend}).Execute(context.Background(), req, nil); err == nil {
		t.Fatal("partial mount failure accepted")
	}
	if len(backend.mounted) != 0 {
		t.Fatal("partial mount remained after failed stage")
	}
}
