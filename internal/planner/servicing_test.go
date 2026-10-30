package planner

import (
	"context"
	"github.com/pelletier/go-toml/v2"
	"reflect"
	"strings"
	"testing"

	"uupbuilder/internal/config"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
	"uupbuilder/internal/tools"
)

func serviceFixture(t *testing.T) (metadata.Inventory, model.ResolvedSettings) {
	t.Helper()
	c := config.Defaults()
	c.Image.UpdateID = "service-fixture"
	_, settings, err := c.Request()
	if err != nil {
		t.Fatal(err)
	}
	settings.Output.EditionOrder = []string{"Professional", "Enterprise"}
	settings.Conversion.Editions.Derived = []string{"Enterprise"}
	source := model.SourceIdentity{UpdateID: "service-fixture", BuildLabel: "28000.3365", Architecture: "amd64", Language: "en-gb"}
	payload := model.Payload{Destination: "update.msu", Identity: model.PayloadIdentity{Size: 1, Digest: model.Digest{Algorithm: model.DigestSHA256, Value: strings.Repeat("a", 64)}, Provenance: model.PackageProvenance{Source: "uup", Name: "update.msu"}}}
	manifest, err := model.NewPayloadManifest(source, []model.Payload{payload})
	if err != nil {
		t.Fatal(err)
	}
	ref := metadata.ResourceReference{Payload: payload.Identity}
	inv := metadata.Inventory{Source: source, Manifest: manifest, Images: []metadata.Image{{Index: 1, Edition: "Professional", Build: "10.0.28000.1", Architecture: "amd64", Languages: []string{"en-gb"}}}, EditionBases: []metadata.EditionBase{{Edition: "Enterprise", Base: "Professional"}}, Updates: []metadata.Update{
		{ID: "lcu", Kind: metadata.UpdateCumulative, Format: metadata.UpdateMSU, Resource: ref, Packages: []metadata.PackageIdentity{{Name: "Package_for_RollupFix", Version: "28000.3365.1.1", PublicKeyToken: "31bf3856ad364e35", Architecture: "amd64"}}, Predecessors: []string{"checkpoint"}},
		{ID: "checkpoint", Kind: metadata.UpdateCheckpoint, Format: metadata.UpdateMSU, Resource: ref, Packages: []metadata.PackageIdentity{{Name: "Package_for_RollupFix", Version: "28000.1000.1.1", PublicKeyToken: "31bf3856ad364e35", Architecture: "amd64"}}, Predecessors: []string{"ssu"}},
		{ID: "ssu", Kind: metadata.UpdateServicingStack, Format: metadata.UpdateCAB, Resource: ref, Packages: []metadata.PackageIdentity{{Name: "Package_for_ServicingStack", Version: "28000.1.1.1", PublicKeyToken: "31bf3856ad364e35", Architecture: "amd64"}}},
	}}
	return inv, settings
}

func TestDecoderRejectsServicingChoicesDifferentFromFrozenSettings(t *testing.T) {
	p, req := fixture(t)
	req.Intent = BuildMedia
	p.SelectTools = func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }
	plan, err := p.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*ServicePlan)
	}{
		{"cleanup", func(p *ServicePlan) { p.Cleanup = false }},
		{"policy", func(p *ServicePlan) { p.Policy = model.UpdatesExternal }},
		{"preserve bases", func(p *ServicePlan) { p.PreserveRequiredBases = false }},
		{"edition", func(p *ServicePlan) { p.Editions[0].Edition = "Enterprise"; p.Editions[0].Derive = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := copyOf(*plan.data)
			test.change(changed.Servicing)
			changed.Servicing.Digest = changed.Servicing.digest()
			changed.Operations = graph(changed)
			raw, err := toml.Marshal(struct {
				Digest string
				Plan   frozen
			}{hash(changed), changed})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeReadyPlan(raw); err == nil {
				t.Fatal("resealed service choices differ from requested settings")
			}
		})
	}
}

func TestCheckpointUpdatesRequirePredecessors(t *testing.T) {
	inv, settings := serviceFixture(t)
	plan, err := BuildServicePlan(inv, settings)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, update := range plan.Updates {
		ids = append(ids, update.ID)
	}
	if !reflect.DeepEqual(ids, []string{"ssu", "checkpoint", "lcu"}) {
		t.Fatalf("wrong update sequence: %v", ids)
	}
	inv.Updates = append(inv.Updates[:1], inv.Updates[2:]...)
	if _, err := BuildServicePlan(inv, settings); err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("missing checkpoint accepted: %v", err)
	}
}

func TestExternalUpdatesRemainOutsideImages(t *testing.T) {
	inv, settings := serviceFixture(t)
	settings.Conversion.Updates = model.UpdatesExternal
	plan, err := BuildServicePlan(inv, settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, update := range plan.Updates {
		if update.Integrate || !update.Retain {
			t.Fatalf("external policy mutates image or drops media update: %+v", update)
		}
	}
}

func TestOmittedUpdatesDoNotEnterMedia(t *testing.T) {
	inv, settings := serviceFixture(t)
	settings.Conversion.Updates = model.UpdatesOmit
	plan, err := BuildServicePlan(inv, settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Updates) != 0 {
		t.Fatalf("omitted updates retained: %+v", plan.Updates)
	}
}

func TestUnclassifiedMSUCannotBeSilentlyDropped(t *testing.T) {
	inv, settings := serviceFixture(t)
	other := inv.Manifest.Payloads[0]
	other.Destination = "another-update.msu"
	other.Identity.Provenance.Name = "another-update.msu"
	other.Identity.Digest.Value = strings.Repeat("b", 64)
	manifest, err := model.NewPayloadManifest(inv.Source, append(append([]model.Payload(nil), inv.Manifest.Payloads...), other))
	if err != nil {
		t.Fatal(err)
	}
	inv.Manifest = manifest
	if _, err := BuildServicePlan(inv, settings); err == nil {
		t.Fatal("an unclassified update payload was silently omitted")
	}
}

func TestEditionDerivationPreservesDifferences(t *testing.T) {
	inv, settings := serviceFixture(t)
	plan, err := BuildServicePlan(inv, settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Editions) != 2 || plan.Editions[0].Edition != "Professional" || plan.Editions[1].Edition != "Enterprise" || plan.Editions[1].Base != "Professional" || !plan.Editions[1].Derive {
		t.Fatalf("edition difference lost: %+v", plan.Editions)
	}
	settings.Output.EditionOrder = []string{"Enterprise"}
	plan, err = BuildServicePlan(inv, settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Editions) != 1 || plan.Editions[0].Edition != "Enterprise" || !reflect.DeepEqual(plan.Bases, []string{"Professional"}) {
		t.Fatalf("temporary base leaked into final editions: %+v", plan)
	}
	inv.EditionBases = nil
	if _, err := BuildServicePlan(inv, settings); err == nil {
		t.Fatal("unsupported explicit derivation accepted")
	}
}

func TestCleanupResetBaseFollowGenerationRules(t *testing.T) {
	inv, settings := serviceFixture(t)
	settings.Conversion.ResetBase = model.ResetBaseOn
	plan, err := BuildServicePlan(inv, settings)
	if err != nil || !plan.Cleanup || !plan.ResetBase {
		t.Fatalf("cleanup/resetbase: %+v, %v", plan, err)
	}
	settings.Conversion.Cleanup = false
	if _, err := BuildServicePlan(inv, settings); err == nil {
		t.Fatal("resetbase without cleanup accepted")
	}
	settings.Conversion.ResetBase = model.ResetBaseOff
	inv.Images[0].Build = "10.0.19045.1"
	if _, err := BuildServicePlan(inv, settings); err == nil {
		t.Fatal("unimplemented generation silently accepted")
	}
}

func TestServicePlanIsFrozenWithOperations(t *testing.T) {
	inv, settings := serviceFixture(t)
	service, err := BuildServicePlan(inv, settings)
	if err != nil {
		t.Fatal(err)
	}
	p, req := fixture(t)
	settings.Storage = req.Settings.Storage
	settings.Output.Directory = req.Settings.Output.Directory
	req.Intent = BuildMedia
	req.Selection.Editions = []string{"Professional"}
	req.Settings = settings
	req.Resolution.Selection = req.Selection
	req.Resolution.Settings = settings
	inv.Source = req.Resolution.Manifest.Source
	inv.Manifest = req.Resolution.Manifest
	for i := range inv.Updates {
		inv.Updates[i].Resource.Payload = inv.Manifest.Payloads[0].Identity
	}
	req.Resolution.Inventory = inv
	p.SelectTools = func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }
	plan, err := p.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	frozen := plan.ServicePlan()
	if frozen == nil || len(frozen.Editions) != len(service.Editions) {
		t.Fatal("service plan absent from frozen graph")
	}
	frozen.Editions[0].Edition = "Corrupted"
	if plan.ServicePlan().Editions[0].Edition != "Professional" {
		t.Fatal("service plan accessor aliases frozen state")
	}
	var found bool
	for _, op := range plan.Operations() {
		if op.Kind == ServiceImage {
			for _, input := range op.Inputs {
				if input.Name == "service-plan" && input.Digest == plan.ServicePlan().Digest {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("service operation not bound to exact typed plan")
	}
	encoded, err := plan.MarshalTOML()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReadyPlan(encoded); err != nil {
		t.Fatal(err)
	}
}

func TestFrozenFinalEditionOrderCannotDropSelectedEdition(t *testing.T) {
	inv, settings := serviceFixture(t)
	p, req := fixture(t)
	settings.Storage = req.Settings.Storage
	settings.Output.Directory = req.Settings.Output.Directory
	req.Intent = BuildMedia
	req.Selection.Editions = []string{"Professional"}
	settings.Output.EditionOrder = []string{"Enterprise"}
	req.Settings = settings
	req.Resolution.Selection = req.Selection
	req.Resolution.Settings = settings
	inv.Source = req.Resolution.Manifest.Source
	inv.Manifest = req.Resolution.Manifest
	for i := range inv.Updates {
		inv.Updates[i].Resource.Payload = inv.Manifest.Payloads[0].Identity
	}
	req.Resolution.Inventory = inv
	p.SelectTools = func(r tools.Requirement) (tools.Selection, error) { return tools.Selection{Requirement: r}, nil }
	if _, err := p.Resolve(context.Background(), req); err == nil {
		t.Fatal("explicit order dropped selected Professional edition")
	}
}

func TestServicePoliciesRejectUnresolvedExplicitChoices(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*metadata.Inventory, *model.ResolvedSettings)
	}{
		{"shared edition-specific update", func(inv *metadata.Inventory, s *model.ResolvedSettings) {
			s.Conversion.ServicingStrategy = model.ServicingSharedBase
			inv.Updates[0].Editions = []string{"Enterprise"}
		}},
		{"expansion lacks member order", func(_ *metadata.Inventory, s *model.ResolvedSettings) {
			s.Conversion.CumulativeUpdates = model.ExpansionExpand
		}},
		{"enablement unavailable", func(_ *metadata.Inventory, s *model.ResolvedSettings) {
			s.Conversion.EnablementPackages = model.InclusionInclude
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			inv, settings := serviceFixture(t)
			test.change(&inv, &settings)
			if _, err := BuildServicePlan(inv, settings); err == nil {
				t.Fatal("unsupported explicit choice accepted")
			}
		})
	}
}
