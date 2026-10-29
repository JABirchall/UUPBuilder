package app

import "uupbuilder/internal/source"

func composeInteractiveApps(opts *Options) {
	// Explicit fixture discovery ports stay unavailable unless their owner also
	// supplies an app producer. Normal application startup owns both factories.
	if opts.Dependencies.Catalog != nil || opts.Dependencies.AppCatalog != nil {
		return
	}
	if opts.Dependencies.AppCatalogFactory == nil {
		opts.Dependencies.AppCatalogFactory = func(endpoint string) source.AppCatalog { return source.NewAppCatalog(endpoint) }
	}
	opts.Dependencies.AppCatalog = opts.Dependencies.AppCatalogFactory(opts.Config.Catalog.Endpoint)
}
