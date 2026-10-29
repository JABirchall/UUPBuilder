package app

import "uupbuilder/internal/source"

func composeInteractiveApps(opts *Options) {
	if opts.Dependencies.AppCatalog != nil {
		return
	}
	if opts.Dependencies.AppCatalogFactory == nil {
		// A discovery-only fixture opts out of automatic app composition. An
		// explicit app factory owns startup regardless of discovery injection.
		if opts.Dependencies.Catalog != nil {
			return
		}
		opts.Dependencies.AppCatalogFactory = func(endpoint string) source.AppCatalog { return source.NewAppCatalog(endpoint) }
	}
	opts.Dependencies.AppCatalog = opts.Dependencies.AppCatalogFactory(opts.Config.Catalog.Endpoint)
}
