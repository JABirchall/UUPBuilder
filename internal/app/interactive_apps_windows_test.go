package app

import (
	"testing"

	"uupbuilder/internal/config"
	"uupbuilder/internal/source"
	"uupbuilder/internal/tui"
)

func TestInteractiveAppFactoryComposesWithInjectedDiscovery(t *testing.T) {
	cfg := config.Defaults()
	cfg.Catalog.Endpoint = "https://catalog.example/"
	producer := source.NewAppCatalog(cfg.Catalog.Endpoint)
	endpoint := ""
	calls := 0
	opts := Options{Config: cfg, Dependencies: tui.Dependencies{Catalog: startupCatalog{}, AppCatalogFactory: func(value string) source.AppCatalog { calls++; endpoint = value; return producer }}}
	composeInteractiveApps(&opts)
	if opts.Dependencies.AppCatalog != producer || endpoint != "https://catalog.example/" || calls != 1 {
		t.Fatalf("explicit factory ignored at startup: producer=%T endpoint=%q calls=%d", opts.Dependencies.AppCatalog, endpoint, calls)
	}
	// A supplied app port is already composed; invoking the factory again must
	// not replace it. Discovery-only fixtures still opt out of app composition.
	composeInteractiveApps(&opts)
	if calls != 1 {
		t.Fatal("existing app port was recomposed")
	}
	fixture := Options{Config: cfg, Dependencies: tui.Dependencies{Catalog: startupCatalog{}}}
	composeInteractiveApps(&fixture)
	if fixture.Dependencies.AppCatalog != nil || fixture.Dependencies.AppCatalogFactory != nil {
		t.Fatal("discovery-only fixture gained a default app port")
	}
}
