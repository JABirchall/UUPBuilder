package planner

import (
	"fmt"
	"uupbuilder/internal/tools"
)

func (p *Planner) dependencies(req Request) ([]tools.Requirement, error) {
	if req.Intent == DownloadOnly {
		return nil, nil
	}
	manifest, err := tools.DefaultManifest()
	if err != nil {
		return nil, err
	}
	requirement := tools.Requirement{Host: req.Host, Target: req.Selection.Architecture, Operations: []tools.Operation{tools.Extract, tools.Inspect, tools.Reconstruct, tools.Service, tools.MasterISO}, ManifestDigest: manifest.Digest(), Source: req.Resolution.Manifest.Source, SourceManifestDigest: req.Resolution.Manifest.Digest, RuleDigest: hash("u06-source-preparation-v1")}
	selectTools := manifest.Select
	if p != nil && p.SelectTools != nil {
		selectTools = p.SelectTools
	}
	selected, err := selectTools(requirement)
	if err != nil {
		return nil, err
	}
	if hash(selected.Requirement) != hash(requirement) {
		return nil, ErrIdentityChanged
	}
	if len(selected.Blockers) > 0 {
		return nil, fmt.Errorf("%w: %s: %s", tools.ErrUnverified, selected.Blockers[0].Code, selected.Blockers[0].Detail)
	}
	// A producer must also clear each candidate's unresolved blockers before it
	// can claim this complete requirement is operational.
	for _, candidate := range selected.Candidates {
		if len(candidate.Blockers) > 0 {
			return nil, fmt.Errorf("%w: %s: %s", tools.ErrUnverified, candidate.Blockers[0].Code, candidate.Blockers[0].Detail)
		}
	}
	return []tools.Requirement{requirement}, nil
}

func graph(f frozen) []Operation {
	kinds := []OperationKind{DownloadPayloads}
	if f.Intent == BuildMedia {
		kinds = append(kinds, AssembleImage)
		if f.AppPhase == "post-assembly" {
			kinds = append(kinds, InspectApps)
		}
		kinds = append(kinds, ServiceImage, CustomizeImage, ExportImage, MasterISO, PublishISO)
	}
	var ops []Operation
	for _, kind := range kinds {
		op := Operation{ID: string(kind), Kind: kind, SourceDigest: f.Manifest.Digest, Rules: []Identity{{Name: "u05-graph-v1", Version: "1", Digest: hash("u05-graph-v1")}, {Name: "source-inventory", Version: "1", Digest: f.InventoryDigest}}, Inputs: []InputIdentity{{Name: "manifest", Digest: f.Manifest.Digest}}, OwnedPaths: []string{"result.json"}}
		if kind == DownloadPayloads {
			for _, payload := range f.Manifest.Payloads {
				op.OwnedPaths = append(op.OwnedPaths, "payloads/"+payload.Identity.Key()+".data")
			}
		}
		if kind == ServiceImage && f.Servicing != nil {
			op.Inputs = append(op.Inputs, InputIdentity{Name: "service-plan", Digest: f.Servicing.Digest})
			op.Rules = append(op.Rules, Identity{Name: f.Servicing.Generation.ID, Version: "1", Digest: hash(f.Servicing.Generation)})
			op.OwnedPaths = f.Servicing.OutputPaths()
		}
		if kind == CustomizeImage && f.Customization != nil {
			op.Inputs = append(op.Inputs, InputIdentity{Name: "customization-plan", Digest: f.Customization.Digest})
			op.OwnedPaths = f.Customization.OutputPaths()
		}
		if len(ops) > 0 {
			op.DependsOn = []string{ops[len(ops)-1].ID}
		}
		if f.AppPhase == "post-assembly" && kind != DownloadPayloads && kind != AssembleImage && kind != InspectApps && !contains(op.DependsOn, string(InspectApps)) {
			op.DependsOn = append(op.DependsOn, string(InspectApps))
		}
		if kind != DownloadPayloads {
			for _, tool := range f.Tools {
				op.ToolDigests = append(op.ToolDigests, hash(tool))
			}
		}
		ops = append(ops, op)
	}
	return ops
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
