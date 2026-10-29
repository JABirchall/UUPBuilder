package app

import (
	"uupbuilder/internal/download"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	"uupbuilder/internal/source"
	"uupbuilder/internal/worker"
)

// RegisterSourcePreparation binds the U06 handler to an application's fixed
// registry. Keep the borrowed manager/workspaces alive through controller Close.
// U12 owns final application composition; this does not enable BuildMedia or
// supply handlers for reconstruction, servicing or publication.
func RegisterSourcePreparation(registry *worker.Registry, manager *download.Manager, resolver *source.Resolver, emit model.Emit) error {
	if registry == nil || manager == nil || resolver == nil || resolver.Fetcher != manager || resolver.Catalog == nil {
		return download.ErrInvalidOptions
	}
	return registry.Register(planner.DownloadPayloads, worker.PreparationHandler(manager, emit))
}
