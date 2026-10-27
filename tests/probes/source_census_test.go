package probes

import "testing"

func TestSourceCensusSeparatesUnavailableFromUnimplemented(t *testing.T) {
	s := SourceCensus{Complete: false, Limitations: []string{"sampled resolver-filtered census"}, Families: []SourceFamily{
		{ID: "forward-express", Observation: "observed", Availability: "unknown", Implementation: "unimplemented", MediaCapability: "unknown", Proof: Unverified, Metadata: []Artifact{unitArtifact("compdb", "metadata")}, Algorithms: []string{"base-relative-delta"}, Gaps: []string{"No reconstructed output fixture."}},
		{ID: "future", Observation: "unknown", Availability: "unknown", Implementation: "unknown", MediaCapability: "unknown", Proof: Unverified, Gaps: []string{"Not surveyed."}},
	}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateBuildable("forward-express", nil, nil); err == nil {
		t.Fatal("unimplemented family became buildable")
	}
	if err := s.ValidateBuildable("future", nil, nil); err == nil {
		t.Fatal("unknown family became buildable")
	}
	s.Families[0].Availability = "unavailable"
	if err := s.Validate(); err == nil {
		t.Fatal("missing algorithm relabeled as upstream unavailable")
	}
	s.Families[0].MissingUpstream = []MissingMaterial{{Identity: "exact-required-payload", Failure: "http-404", Evidence: unitArtifact("failure", "availability-report")}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Families[0].MissingUpstream[0].Failure = "http-429"
	if s.Validate() == nil {
		t.Fatal("rate limit treated as removed upstream material")
	}
}

func TestSourceCensusRejectsPassWithoutFamilyEvidence(t *testing.T) {
	s := SourceCensus{Complete: false, Limitations: []string{"not exhaustive"}, Families: []SourceFamily{{ID: "canonical", Observation: "observed", Availability: "unknown", Implementation: "unimplemented", MediaCapability: "unknown", Proof: Passed, Metadata: []Artifact{unitArtifact("compdb", "metadata")}}}}
	if s.Validate() == nil {
		t.Fatal("metadata-only family was marked passed")
	}
}

func TestSourceCensusRequiresFamilyAlgorithms(t *testing.T) {
	c, e := unitRecord()
	c.Gate = "S"
	e.CaseDigest = c.Digest()
	s := SourceCensus{Complete: false, Limitations: []string{"unit records only"}, Families: []SourceFamily{{ID: "canonical", Observation: "observed", Availability: "available", Implementation: "implemented", MediaCapability: "iso-capable", Proof: Passed, Metadata: []Artifact{unitArtifact("compdb", "metadata")}, Algorithms: []string{"different-family-algorithm"}, ProofCases: []string{c.ID}}}}
	if s.ValidateBuildable("canonical", []Case{c}, []Evidence{e}) == nil {
		t.Fatal("unexecuted family algorithm accepted")
	}
}

func TestSourceCensusAcceptsOnlyBoundFamilyRecordShape(t *testing.T) {
	// Synthetic validator records, not a claim of real family support or Gate P.
	c, e := unitRecord()
	c.Gate = "S"
	e.CaseDigest = c.Digest()
	s := SourceCensus{Complete: false, Limitations: []string{"synthetic records only"}, Families: []SourceFamily{{ID: "canonical", Observation: "observed", Availability: "available", Implementation: "implemented", MediaCapability: "iso-capable", Proof: Passed, Metadata: []Artifact{unitArtifact("compdb", "metadata")}, Algorithms: []string{"unit-algorithm"}, ProofCases: []string{c.ID}}}}
	if err := s.ValidateBuildable("canonical", []Case{c}, []Evidence{e}); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateBuildable("canonical", []Case{c}, nil); err == nil {
		t.Fatal("missing family runtime record accepted")
	}
	if err := s.ValidateBuildable("canonical", nil, []Evidence{e}); err == nil {
		t.Fatal("missing bound family case accepted")
	}
	if err := s.ValidateBuildable("unknown", []Case{c}, []Evidence{e}); err == nil {
		t.Fatal("unknown family accepted")
	}
}

func TestSourceCensusRejectsDetachedAlgorithmProof(t *testing.T) {
	// A scoped Gate S record must inherit the expected-result algorithm binding.
	// These synthetic records do not establish actual source-family support.
	c, e := unitRecord()
	c.Gate = "S"
	e.CaseDigest = c.Digest()
	s := SourceCensus{Complete: false, Limitations: []string{"synthetic records only"}, Families: []SourceFamily{{ID: "canonical", Observation: "observed", Availability: "available", Implementation: "implemented", MediaCapability: "iso-capable", Proof: Passed, Metadata: []Artifact{unitArtifact("compdb", "metadata")}, Algorithms: []string{"unit-algorithm"}, ProofCases: []string{c.ID}}}}
	if err := s.ValidateBuildable("canonical", []Case{c}, []Evidence{e}); err != nil {
		t.Fatalf("control with algorithm bound to expected reconstructed output rejected: %v", err)
	}
	moveUnitAlgorithmsToDetachedInvocation(&e)
	if s.ValidateBuildable("canonical", []Case{c}, []Evidence{e}) == nil {
		t.Fatal("detached invocation opened scoped family record gate")
	}
}

func TestSourceCensusAcceptsPortableFamilyCoverage(t *testing.T) {
	// Synthetic validator fixtures only; not actual source-family proof.
	required, observed := unitArchitectureSuite()
	var ids []string
	for i := range required {
		required[i].Gate = "S"
		ids = append(ids, required[i].ID)
		for j := range observed {
			if observed[j].CaseID == required[i].ID {
				observed[j].CaseDigest = required[i].Digest()
			}
		}
	}
	s := SourceCensus{Complete: false, Limitations: []string{"synthetic records only"}, Families: []SourceFamily{{ID: "canonical", Observation: "observed", Availability: "available", Implementation: "implemented", MediaCapability: "iso-capable", Proof: Passed, Metadata: []Artifact{unitArtifact("compdb", "metadata")}, Algorithms: []string{"unit-algorithm"}, ProofCases: ids}}}
	if err := s.ValidateBuildable("canonical", required, observed); err != nil {
		t.Fatal(err)
	}
	observed = observed[:2]
	if s.ValidateBuildable("canonical", required, observed) == nil {
		t.Fatal("portable family coverage inferred an unobserved target")
	}
}
