package app

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"

	"uupbuilder/internal/download"
	"uupbuilder/internal/model"
	"uupbuilder/internal/planner"
	platform "uupbuilder/internal/platform/windows"
)

// One Prepare owns these fresh capabilities until both Resolver and Planner
// return. Only projected semantic inputs are materialized. No serialized
// receipt or path grants authority, and nothing is borrowed by the ReadyPlan.
type sourcePreparation struct {
	cache, job           *platform.Workspace
	cacheReady, jobReady bool
	manager              *download.Manager
	transport            *http.Transport
	inspect              func(context.Context, string) (planner.Volume, error)
	payloads             map[model.PayloadIdentity]bool
	retainDownloads      bool
}

func (p *sourcePreparation) check(ctx context.Context, payloads []model.Payload) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var required, largest uint64
	for _, payload := range payloads {
		if payload.Validate() != nil {
			return download.ErrInvalidInput
		}
		size := uint64(payload.Identity.Size)
		if size > math.MaxUint64-required {
			return download.ErrInvalidInput
		}
		required += size
		largest = max(largest, size)
	}
	used := map[string]uint64{}
	for _, w := range []*platform.Workspace{p.cache, p.job} {
		v, err := p.inspect(ctx, w.Path())
		if err != nil {
			return fmt.Errorf("semantic metadata storage inspection: %w", err)
		}
		if v.Path != w.Path() || v.ID == "" || v.MaxFileBytes < largest || required > math.MaxUint64-used[v.ID] {
			return download.ErrStorage
		}
		used[v.ID] += required
		if used[v.ID] > v.AvailableBytes {
			return download.ErrStorage
		}
	}
	if p.payloads == nil {
		p.payloads = make(map[model.PayloadIdentity]bool)
	}
	for _, payload := range payloads {
		p.payloads[payload.Identity] = true
	}
	return nil
}

func (p *sourcePreparation) Fetch(ctx context.Context, manifest model.PayloadManifest, locators model.Locators, emit model.Emit) (download.Materialized, error) {
	if manifest.Validate() != nil {
		return nil, download.ErrInvalidInput
	}
	if err := p.check(ctx, manifest.Payloads); err != nil {
		return nil, err
	}
	return p.manager.Fetch(ctx, manifest, locators, emit)
}
func (p *sourcePreparation) FetchOne(ctx context.Context, payload model.Payload, locator download.Locator, emit model.Emit) (download.CachedFile, error) {
	if err := p.check(ctx, []model.Payload{payload}); err != nil {
		return download.CachedFile{}, err
	}
	return p.manager.FetchOne(ctx, payload, locator, emit)
}

func (p *sourcePreparation) Close() error {
	var err error
	if p.manager != nil {
		err = p.manager.Close()
	}
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
	leaseErr := err
	// A failed lease release is preserved; it cannot authorize deletion.
	for _, scope := range []struct {
		w        *platform.Workspace
		ready    bool
		suffixes []string
	}{
		{p.job, p.jobReady, []string{".part", ".resume.json", ".resume.json.tmp"}},
		{p.cache, p.cacheReady, []string{".data", ".json", ".staging", ".json.tmp"}},
	} {
		w := scope.w
		if w == nil {
			continue
		}
		cleanupErr := leaseErr
		if leaseErr == nil && scope.w == p.cache && p.retainDownloads {
			// The selected job explicitly requested retaining these verified
			// downloads. Release handles but preserve this owned cache and marker.
		} else if leaseErr == nil && !scope.ready {
			cleanupErr = w.RemoveEmpty()
		} else if leaseErr == nil {
			for id := range p.payloads {
				for _, suffix := range scope.suffixes {
					if e := w.Remove(id.Key() + suffix); e != nil && !errors.Is(e, os.ErrNotExist) {
						cleanupErr = errors.Join(cleanupErr, e)
					}
				}
			}
			if e := w.Remove("download-manager.lock"); e != nil && !errors.Is(e, os.ErrNotExist) {
				cleanupErr = errors.Join(cleanupErr, e)
			}
			if cleanupErr == nil {
				cleanupErr = w.RemoveEmpty()
			}
		}
		cleanupErr = errors.Join(cleanupErr, w.Close())
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("preflight resources preserved at %s [job=%s]: %w", w.Path(), w.Identity().JobID, cleanupErr))
		}
	}
	return err
}
