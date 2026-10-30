package source

import (
	"context"
	"slices"

	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

// AppCatalog offers source-backed requests before full image resolution. A
// successful load does not establish package/provisioning applicability.
type AppCatalog interface {
	Load(context.Context, model.Selection) (AppCatalogSnapshot, error)
}
type AppCatalogState string

const (
	AppCatalogAvailable AppCatalogState = "available"
	AppCatalogDeferred  AppCatalogState = "deferred"
)

type AppCompatibilityBinding struct {
	BuildID, BaselineOSVersion string
	Architecture               model.Architecture
}
type AppEditionReference struct {
	Edition, Type, Selector string
	Document                metadata.DocumentReference
}
type AppCatalogEntry struct {
	FeatureID, Type, Selector string
	Document                  metadata.DocumentReference
	Editions                  []AppEditionReference
	Dependencies              []metadata.AppFeatureDependency
	Packages                  []metadata.CompositionPackageReference
	Media                     []metadata.AppMediaHint
	InitialIntents            []string
	Licenses                  []metadata.AppLicenseObservation
}
type AppMetadataContainer struct {
	Member, SHA256 string
	Inventory      metadata.CABInventory
}
type AppCatalogSnapshot struct {
	Selection                 model.Selection
	SelectedSource, AppSource model.SourceIdentity
	AppQuery                  model.SourceQuery
	AppManifest               model.PayloadManifest
	SelectedManifests         []model.PayloadManifest
	CAB                       model.PayloadIdentity
	Documents                 []metadata.DocumentReference
	Containers                []AppMetadataContainer
	Binding                   AppCompatibilityBinding
	Entries                   []AppCatalogEntry
	State                     AppCatalogState
	Gaps                      []string
}

func (s AppCatalogSnapshot) Clone() AppCatalogSnapshot {
	s.Selection.Editions = slices.Clone(s.Selection.Editions)
	s.AppQuery.Projection = slices.Clone(s.AppQuery.Projection)
	s.AppManifest.Payloads = slices.Clone(s.AppManifest.Payloads)
	s.AppManifest.Queries = model.CloneSourceQueries(s.AppManifest.Queries)
	s.SelectedManifests = slices.Clone(s.SelectedManifests)
	for i := range s.SelectedManifests {
		s.SelectedManifests[i].Payloads = slices.Clone(s.SelectedManifests[i].Payloads)
		s.SelectedManifests[i].Queries = model.CloneSourceQueries(s.SelectedManifests[i].Queries)
	}
	s.Documents = slices.Clone(s.Documents)
	s.Gaps = slices.Clone(s.Gaps)
	s.Containers = slices.Clone(s.Containers)
	for i := range s.Containers {
		s.Containers[i].Inventory.Members = slices.Clone(s.Containers[i].Inventory.Members)
	}
	s.Entries = slices.Clone(s.Entries)
	for i := range s.Entries {
		e := &s.Entries[i]
		e.Editions = slices.Clone(e.Editions)
		e.Dependencies = slices.Clone(e.Dependencies)
		e.Packages = slices.Clone(e.Packages)
		e.Media = slices.Clone(e.Media)
		e.InitialIntents = slices.Clone(e.InitialIntents)
		e.Licenses = slices.Clone(e.Licenses)
	}
	return s
}
