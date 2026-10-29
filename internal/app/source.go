//go:build windows

package app

import (
	"uupbuilder/internal/download"
	"uupbuilder/internal/source"
)

// NewSourceManager binds the cycle at the application boundary. Configure the
// resolver before use; the caller owns the manager and its workspaces' lifetime.
// Run does not invoke this helper until startup composition is implemented.
func NewSourceManager(options download.Options, resolver *source.Resolver) (*download.Manager, error) {
	if resolver == nil {
		return nil, download.ErrInvalidOptions
	}
	options.Refresh = resolver.RefreshLinks
	manager, err := download.NewManager(options)
	if err != nil {
		return nil, err
	}
	resolver.Fetcher = manager
	if resolver.Catalog != nil {
		discovery := &source.Discovery{Catalog: resolver.Catalog}
		if resolver.Discover == nil {
			resolver.Discover = discovery.Metadata
		}
		if resolver.DiscoverApps == nil {
			resolver.DiscoverApps = discovery.Apps
		}
	}
	return manager, nil
}
