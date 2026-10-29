package planner

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"uupbuilder/internal/source"
)

func (p *Planner) space(ctx context.Context, req Request) (Estimate, []StorageCheck, error) {
	var e Estimate
	var largest uint64
	for _, payload := range req.Resolution.Manifest.Payloads {
		size := uint64(payload.Identity.Size)
		if size > math.MaxUint64-e.KnownPayloadBytes {
			return e, nil, fmt.Errorf("%w: payload size overflow", ErrBlocked)
		}
		e.KnownPayloadBytes += size
		if size > largest {
			largest = size
		}
	}
	if e.KnownPayloadBytes > math.MaxUint64/4 {
		return e, nil, fmt.Errorf("%w: space estimate overflow", ErrBlocked)
	}
	e.ScratchBytes = e.KnownPayloadBytes
	e.ScratchEstimated = true
	if req.Intent == BuildMedia {
		e.ScratchBytes = e.KnownPayloadBytes * 3
		e.OutputBytes = e.KnownPayloadBytes * 2
		e.OutputEstimated = true
	}
	if p == nil || p.InspectStorage == nil {
		return e, nil, fmt.Errorf("%w: chosen-volume storage discovery unavailable", ErrBlocked)
	}
	var checks []StorageCheck
	roles := []struct {
		role, path        string
		required, largest uint64
	}{{"scratch", req.Settings.Storage.Workspace, e.ScratchBytes, largest}, {"cache", req.Settings.Storage.Cache, e.KnownPayloadBytes, largest}, {"output", req.Settings.Output.Directory, e.OutputBytes, largest}}
	if e.OutputBytes > roles[2].largest {
		roles[2].largest = e.OutputBytes
	}
	used := map[string]uint64{}
	available := map[string]uint64{}
	for _, r := range roles {
		if !filepath.IsAbs(r.path) {
			return e, nil, fmt.Errorf("%w: storage.%s requires a resolved absolute path", ErrBlocked, r.role)
		}
		v, err := p.InspectStorage(ctx, r.path)
		if err != nil {
			return e, nil, fmt.Errorf("%w: %s volume inspection failed", ErrBlocked, r.role)
		}
		if v.Path != r.path || v.ID == "" || v.MaxFileBytes == 0 {
			return e, nil, fmt.Errorf("%w: %s volume discovery identity incomplete", ErrBlocked, r.role)
		}
		if r.role == "scratch" && (!v.FileSystem.Local || !strings.EqualFold(v.FileSystem.Name, "NTFS") || !v.FileSystem.ACLs || !v.FileSystem.AlternateStreams || !v.FileSystem.HardLinks) {
			return e, nil, fmt.Errorf("%w: scratch requires local NTFS with ACLs, streams and hardlinks", ErrBlocked)
		}
		if v.MaxFileBytes < r.largest {
			return e, nil, fmt.Errorf("%w: %s volume lacks large-file support for %d bytes", ErrBlocked, r.role, r.largest)
		}
		if r.required > math.MaxUint64-used[v.ID] {
			return e, nil, fmt.Errorf("%w: aggregate space overflow", ErrBlocked)
		}
		used[v.ID] += r.required
		if old, ok := available[v.ID]; !ok || v.AvailableBytes < old {
			available[v.ID] = v.AvailableBytes
		}
		if used[v.ID] > available[v.ID] {
			return e, nil, fmt.Errorf("%w: insufficient shared-volume space on %s", ErrBlocked, r.role)
		}
		checks = append(checks, StorageCheck{Role: r.role, Volume: v, RequiredBytes: r.required, LargestFileBytes: r.largest})
	}
	return e, checks, nil
}

// RecheckStorage repeats actual-volume/capacity checks immediately before the
// controller creates resources. A changed destination volume invalidates a plan.
func (p ReadyPlan) RecheckStorage(ctx context.Context, probe func(context.Context, string) (Volume, error)) error {
	if err := p.Validate(); err != nil {
		return err
	}
	checker := Planner{InspectStorage: probe}
	_, checks, err := checker.space(ctx, Request{Settings: p.EffectiveSettings(), Resolution: source.Resolution{Manifest: p.Manifest()}, Intent: p.Intent()})
	if err != nil {
		return err
	}
	for i, c := range checks {
		old := p.data.Storage[i]
		if c.Volume.ID != old.Volume.ID || c.Volume.FileSystem != old.Volume.FileSystem {
			return ErrIdentityChanged
		}
	}
	return nil
}
