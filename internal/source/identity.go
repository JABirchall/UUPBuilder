// Package source freezes source inputs independently of runtime download links.
package source

import (
	"errors"
	"net/url"
	"uupbuilder/internal/catalog"
	"uupbuilder/internal/metadata"
	"uupbuilder/internal/model"
)

type Resolution struct {
	Selection      model.Selection
	Settings       model.ResolvedSettings
	Manifest       model.PayloadManifest
	Locators       model.Locators `json:"-" toml:"-"`
	Inventory      metadata.Inventory
	Classification metadata.Classification
	Diagnostics    []model.Diagnostic
	AppPhase       metadata.AppPhase
}

var (
	ErrInputIdentityChanged    = errors.New("source input identity changed")
	ErrPayloadUnavailable      = errors.New("source payload unavailable upstream")
	ErrConflictingDestinations = errors.New("conflicting source payload destinations")
	ErrInvalidInput            = errors.New("invalid source resolution input")
	ErrImplementationGap       = errors.New("source resolution producer unavailable")
)

func validLocator(locator model.Locator) bool {
	u, err := url.Parse(locator.URL)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil && u.Fragment == ""
}

func upstreamUnavailable(err error) bool {
	if errors.Is(err, ErrPayloadUnavailable) {
		return true
	}
	var api *catalog.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.Code {
	case "MISSING_FILES", "NO_FILES", "UNSUPPORTED_COMBINATION", "UNSUPPORTED_EDITION", "UNSUPPORTED_LANG", "EMPTY_FILELIST":
		return true
	}
	return false
}
