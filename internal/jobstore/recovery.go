//go:build windows

package jobstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// resourceState obtains OS evidence independently of mount ownership claims.
// A failed/partial OS inventory never means an empty mounted-image list.
func (s *Store) resourceState(ctx context.Context) ([]string, []PreservedResource, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	snapshot, err := s.inspector.Inspect(ctx, s.w.Path())
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err != nil || !snapshot.Complete {
		reason := "actual OS mount inventory unavailable or incomplete"
		if err != nil {
			reason += ": " + err.Error()
		}
		return nil, []PreservedResource{{Path: s.w.Path(), Reason: reason}}, nil
	}
	root, err := normalizedAbsolute(s.w.Path())
	if err != nil {
		return nil, nil, err
	}
	preserved := []PreservedResource{}
	for _, m := range snapshot.Mounts {
		path, err := normalizedAbsolute(m.Path)
		if err != nil {
			preserved = append(preserved, PreservedResource{Path: s.w.Path(), Reason: "ambiguous OS mount path"})
			continue
		}
		if pathsOverlap(root, path) {
			preserved = append(preserved, PreservedResource{Path: m.Path, Reason: "actual OS mounted image or unresolved mount state: " + string(m.State)})
		}
	}
	// Do not walk into a known mounted image to decide whether it is safe.
	if len(preserved) > 0 {
		return nil, preserved, nil
	}
	entries, err := topology(ctx, s.w.Path())
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, []PreservedResource{{Path: s.w.Path(), Reason: err.Error()}}, nil
	}
	for _, st := range s.state.Stages {
		for _, path := range st.MountPaths {
			f, err := s.w.OpenFile(path, os.O_RDONLY, 0)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				preserved = append(preserved, PreservedResource{Path: path, Reason: "mount directory cannot be inspected"})
				continue
			}
			f.Close()
			found := false
			for _, claim := range st.Mounts {
				if claim.RelativePath == path {
					found = true
					if err := s.w.RestoreMount(claim); err != nil {
						preserved = append(preserved, PreservedResource{Path: path, Reason: "mount ownership changed: " + err.Error()})
					} else if err := s.w.ValidateMount(claim); err != nil {
						preserved = append(preserved, PreservedResource{Path: path, Reason: "mount ownership unresolved: " + err.Error()})
					}
				}
			}
			if !found {
				preserved = append(preserved, PreservedResource{Path: path, Reason: "mount directory claim was never durably recorded"})
			}
		}
	}
	return entries, preserved, nil
}

func (s *Store) clearResources(ctx context.Context) error {
	_, preserved, err := s.resourceState(ctx)
	if err != nil {
		return err
	}
	if len(preserved) > 0 {
		return fmt.Errorf("preserved unresolved resource %s: %s", preserved[0].Path, preserved[0].Reason)
	}
	return nil
}

func (s *Store) inspect(ctx context.Context) (RecoveryPlan, error) {
	result := RecoveryPlan{Discarded: s.state.Discarded}
	entries, preserved, err := s.resourceState(ctx)
	if err != nil {
		return result, err
	}
	result.Preserved = preserved
	files, dirs := s.knownPaths()
	for _, entry := range entries {
		if !files[entry] && !dirs[entry] {
			result.Preserved = append(result.Preserved, PreservedResource{Path: entry, Reason: "entry has no durable job ownership record"})
		}
	}
	valid := map[PredecessorIdentity]bool{}
	for _, c := range s.state.Checkpoints {
		status := CheckpointStatus{Checkpoint: clone(c.Checkpoint), Valid: true}
		if err := validateCheckpoint(c); err != nil {
			status.Valid = false
			status.Reason = err.Error()
		}
		for _, p := range c.Checkpoint.Intent.Predecessors {
			if !valid[p] {
				status.Valid = false
				status.Reason = "predecessor " + p.StageID + " is missing or invalid"
				break
			}
		}
		if status.Valid {
			for _, o := range c.Checkpoint.Outputs {
				if err := s.verifyOutput(ctx, o); err != nil {
					if ctx.Err() != nil {
						return result, ctx.Err()
					}
					status.Valid = false
					status.Reason = "output " + o.Path + ": " + err.Error()
					break
				}
			}
		}
		result.Checkpoints = append(result.Checkpoints, status)
		if status.Valid {
			valid[PredecessorIdentity{StageID: c.Checkpoint.Intent.StageID, Digest: c.Checkpoint.Digest}] = true
		}
	}
	for _, st := range s.state.Stages {
		if !st.Committed {
			result.Interrupted = append(result.Interrupted, InterruptedStage{Intent: clone(st.Intent), ScratchPath: st.Scratch})
		}
	}
	result.CanResume = !s.state.Discarded && len(result.Preserved) == 0
	return result, nil
}

// InspectRecovery rereads actual bytes, mount inventory, directory identities
// and topology. Journal completion flags alone never authorize checkpoint reuse.
func (s *Store) InspectRecovery(ctx context.Context, jobID string) (RecoveryPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, jobID); err != nil {
		return RecoveryPlan{}, err
	}
	return s.inspect(ctx)
}

// AbsoluteOutputPath resolves a validated snapshot path for read-only providers.
// This revalidates ancestry, real bytes and resources before returning a path;
// callers must not use the path as a writable stage destination.
func (s *Store) AbsoluteOutputPath(ctx context.Context, output OutputIdentity) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, s.Identity().JobID); err != nil {
		return "", err
	}
	recovery, err := s.inspect(ctx)
	if err != nil {
		return "", err
	}
	if !recovery.CanResume {
		return "", errors.New("output reuse requires resolved resources and an active job")
	}
	for _, c := range recovery.Checkpoints {
		if !c.Valid {
			continue
		}
		for _, known := range c.Checkpoint.Outputs {
			if known == output {
				return filepath.Join(s.w.Path(), filepath.FromSlash(known.Path)), nil
			}
		}
	}
	return "", errors.New("output not in a committed checkpoint")
}
