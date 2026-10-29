package jobstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	platform "uupbuilder/internal/platform/windows"
)

type directoryRecord struct {
	Path, SourceDigest, IntentDigest string
	Role                             string `json:",omitempty"`
	Identity                         platform.FileIdentity
	Released                         bool
}

func (c *DirectoryClaim) Role() string {
	if c == nil {
		return ""
	}
	return c.record.Role
}

// DirectoryClaim borrows the active transaction's single writer. It is not a
// mount, checkpoint, persisted re-open capability or worker authorization.
type DirectoryClaim struct {
	tx       *Transaction
	record   directoryRecord
	tree     *platform.OwnedTree
	released bool
}

func (c *DirectoryClaim) Tree() *platform.OwnedTree {
	if c == nil {
		return nil
	}
	return c.tree
}
func (c *DirectoryClaim) SourceDigest() string {
	if c == nil {
		return ""
	}
	return c.record.SourceDigest
}
func (c *DirectoryClaim) IntentDigest() string {
	if c == nil {
		return ""
	}
	return c.record.IntentDigest
}

// CheckLive validates only the original active durable claim. It neither
// reopens persisted state nor grants observation, descendant or release rights.
func (c *DirectoryClaim) CheckLive(ctx context.Context) error {
	if c == nil || ctx == nil || c.tx == nil || c.tx.store == nil || c.tree == nil {
		return platform.ErrTreePreserved
	}
	s := c.tx.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx, c.tx.intent.JobID); e != nil {
		return e
	}
	if e := c.tx.usable(); e != nil {
		return e
	}
	if s.lock == nil {
		return platform.ErrTreePreserved
	}
	if _, e := s.lock.Stat(); e != nil {
		return errors.Join(platform.ErrTreePreserved, e)
	}
	if c.released || c.record.Released || c.record.Identity.FileIndex == 0 ||
		c.record.IntentDigest != intentDigest(c.tx.intent) || !sourceProof(c.tx.intent, c.record.SourceDigest) {
		return platform.ErrTreePreserved
	}
	i := s.stageIndex(c.tx.id)
	if i < 0 {
		return platform.ErrTreePreserved
	}
	stage := s.state.Stages[i]
	if stage.Committed || stage.Scratch != c.tx.scratch || intentDigest(stage.Intent) != c.record.IntentDigest {
		return platform.ErrTreePreserved
	}
	found := 0
	for _, r := range s.state.Stages[i].Directories {
		if r == c.record {
			found++
		}
	}
	id := c.tree.Identity()
	if found != 1 || id.Root != c.record.Identity || id.SourceDigest != c.record.SourceDigest ||
		id.RelativePath != c.record.Path || id.OperationID != c.tx.intent.StageID || id.Workspace != s.w.Identity() {
		return platform.ErrTreePreserved
	}
	return c.tree.CheckObservationLive(ctx)
}
func intentDigest(in MutationIntent) string { b, _ := json.Marshal(in); return hashBytes(b) }
func directoryOverlap(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
func sourceProof(in MutationIntent, digest string) bool {
	for _, v := range in.Inputs {
		if v.Name == "preservation-proof" && v.Digest == digest {
			return true
		}
	}
	return false
}

// ClaimDirectory fixes the descriptor digest in an existing intent input and
// journals a fresh generated path before creation, then the native identity
// before returning success. Partial creation returns the retained claim + error.
func (tx *Transaction) ClaimDirectory(ctx context.Context, source string) (*DirectoryClaim, error) {
	if tx == nil || tx.store == nil || ctx == nil {
		return nil, platform.ErrTreePreserved
	}
	s := tx.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx, tx.intent.JobID); e != nil {
		return nil, e
	}
	if e := tx.usable(); e != nil {
		return nil, e
	}
	if !validDigest(source) || !sourceProof(tx.intent, source) {
		return nil, errors.New("directory descriptor absent from exact transaction intent")
	}
	if e := s.clearResources(ctx); e != nil {
		return nil, e
	}
	return tx.claimDirectoryLocked(ctx, source, "")
}

// ClaimFixedSourceApplyDirectories is the fixed destination/cache pair only.
// The unchanged resource guard runs once before either durable creation intent.
// Each published/partial claim retains its own role, record and native custody.
// It cannot append to an unresolved pair or authorize native descendants.
func (tx *Transaction) ClaimFixedSourceApplyDirectories(ctx context.Context, source string) (destination, cache *DirectoryClaim, runErr error) {
	if tx == nil || tx.store == nil || ctx == nil {
		return nil, nil, platform.ErrTreePreserved
	}
	s := tx.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx, tx.intent.JobID); e != nil {
		return nil, nil, e
	}
	if e := tx.usable(); e != nil {
		return nil, nil, e
	}
	if s.lock == nil {
		return nil, nil, platform.ErrTreePreserved
	}
	if _, e := s.lock.Stat(); e != nil {
		return nil, nil, e
	}
	if !validDigest(source) || !fixedSourceApplyPairIntent(tx.intent, source) {
		return nil, nil, platform.ErrTreePreserved
	}
	if e := tx.checkFixedPairStageLocked(); e != nil {
		return nil, nil, e
	}
	if e := s.clearResources(ctx); e != nil {
		return nil, nil, e
	}
	destination, runErr = tx.claimDirectoryLocked(ctx, source, "destination")
	if runErr != nil {
		return destination, nil, runErr
	}
	if e := tx.checkFixedPairStageLocked(); e != nil {
		return destination, nil, e
	}
	cache, runErr = tx.claimDirectoryLocked(ctx, source, "wimgapi-cache")
	return destination, cache, runErr
}
func (tx *Transaction) checkFixedPairStageLocked() error {
	i := tx.store.stageIndex(tx.id)
	if i < 0 {
		return platform.ErrTreePreserved
	}
	stage := tx.store.state.Stages[i]
	if stage.Committed || stage.Scratch != tx.scratch || intentDigest(stage.Intent) != intentDigest(tx.intent) {
		return platform.ErrTreePreserved
	}
	return nil
}
func fixedSourceApplyPairIntent(in MutationIntent, source string) bool {
	if in.StageID != "fixed-source-contract-apply" || in.PlanDigest != source || len(in.Tools) != 1 || len(in.Rules) != 1 || len(in.Inputs) != 7 || len(in.OwnedPaths) != 1 || in.OwnedPaths[0] != "unused-component-output" {
		return false
	}
	t, r := in.Tools[0], in.Rules[0]
	if t.Name != "installed-wimgapi.dll" || t.Version != "measured-fixed-apply" || !validDigest(t.Digest) || r.Name != "fixed-apply-profile" || r.Version != "1" || r.Digest != in.ConfigDigest {
		return false
	}
	for j, name := range []string{"generated-wim", "original-index", "original-manifest", "original-oracle", "original-recipe", "original-references", "preservation-proof"} {
		if in.Inputs[j].Name != name || !validDigest(in.Inputs[j].Digest) {
			return false
		}
	}
	return in.Inputs[6].Digest == source
}

// Caller holds the store lock and has checked unchanged global resources.
// Used by the ordinary one-claim API and the exact fixed pair above.
func (tx *Transaction) claimDirectoryLocked(ctx context.Context, source, role string) (*DirectoryClaim, error) {
	s := tx.store
	id, e := token()
	if e != nil {
		return nil, e
	}
	r := directoryRecord{Path: tx.scratch + "/tree-" + id, SourceDigest: source, IntentDigest: intentDigest(tx.intent), Role: role}
	for _, p := range tx.intent.OwnedPaths {
		if directoryOverlap(r.Path, tx.scratch+"/"+p) {
			return nil, platform.ErrTreePreserved
		}
	}
	idx := s.stageIndex(tx.id)
	next := clone(s.state)
	next.Stages[idx].Directories = append(next.Stages[idx].Directories, r)
	if e = s.writeJournal(next); e != nil {
		return nil, e
	}
	c := &DirectoryClaim{tx: tx, record: r}
	s.directories = append(s.directories, c)
	if e = s.interrupt("directory-before-create"); e != nil {
		return c, e
	}
	c.tree, e = s.w.CreateOwnedTree(r.Path, tx.intent.StageID, source, platform.TreeLimits{})
	if e != nil {
		return c, errors.Join(platform.ErrTreePreserved, e)
	}
	c.record.Identity = c.tree.Identity().Root
	next = clone(s.state)
	n := len(next.Stages[idx].Directories) - 1
	next.Stages[idx].Directories[n] = c.record
	if e = s.writeJournal(next); e != nil {
		return c, errors.Join(platform.ErrTreePreserved, e)
	}
	if e = ctx.Err(); e != nil {
		return c, errors.Join(platform.ErrTreePreserved, e)
	}
	return c, nil
}

// Release requires an empty, unchanged held scope and a complete independent OS
// resource observation. No path is adopted, traversed through a source link or
// recursively removed; any uncertainty keeps the durable claim unresolved.
func (c *DirectoryClaim) Release(ctx context.Context) error {
	if c == nil || c.tx == nil || c.tree == nil || ctx == nil {
		return platform.ErrTreePreserved
	}
	s := c.tx.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.released {
		return nil
	}
	if e := s.check(ctx, c.tx.intent.JobID); e != nil {
		return e
	}
	if e := c.tx.usable(); e != nil {
		return e
	}
	if c.record.IntentDigest != intentDigest(c.tx.intent) || !sourceProof(c.tx.intent, c.record.SourceDigest) || c.tree.Identity().Root != c.record.Identity {
		return platform.ErrTreePreserved
	}
	idx := s.stageIndex(c.tx.id)
	found := -1
	for n, r := range s.state.Stages[idx].Directories {
		if r == c.record {
			found = n
		}
	}
	if found < 0 {
		return platform.ErrTreePreserved
	}
	snap, e := s.inspector.Inspect(ctx, s.w.Path())
	if e != nil || !snap.Complete {
		return errors.Join(platform.ErrTreePreserved, e)
	}
	root, e := normalizedAbsolute(s.w.Path())
	if e != nil {
		return e
	}
	for _, m := range snap.Mounts {
		p, e := normalizedAbsolute(m.Path)
		if e != nil || pathsOverlap(root, p) {
			return platform.ErrTreePreserved
		}
	}
	entries, e := topology(ctx, s.w.Path())
	if e != nil {
		return errors.Join(platform.ErrTreePreserved, e)
	}
	files, dirs := s.knownPaths()
	for _, p := range entries {
		if !files[p] && !dirs[p] {
			return fmt.Errorf("%w: unknown entry %s", platform.ErrTreePreserved, p)
		}
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = c.tree.RemoveEmpty(ctx); e != nil {
		return e
	}
	next := clone(s.state)
	next.Stages[idx].Directories[found].Released = true
	if e = s.writeJournal(next); e != nil {
		return errors.Join(platform.ErrTreePreserved, e)
	}
	c.released = true
	return nil
}

func (s *Store) validateDirectoryRecords(st stageRecord) error {
	seen := map[string]bool{}
	for _, r := range st.Directories {
		n, e := cleanRelative(r.Path)
		if e != nil || n != r.Path || filepath.ToSlash(filepath.Dir(n)) != st.Scratch || !strings.HasPrefix(filepath.Base(n), "tree-") || seen[strings.ToLower(n)] || !validDigest(r.SourceDigest) || !sourceProof(st.Intent, r.SourceDigest) || r.IntentDigest != intentDigest(st.Intent) {
			return errors.New("invalid directory claim")
		}
		seen[strings.ToLower(n)] = true
		for _, p := range st.Intent.OwnedPaths {
			if directoryOverlap(n, st.Scratch+"/"+p) {
				return errors.New("directory overlaps file output")
			}
		}
		for _, p := range st.MountPaths {
			if directoryOverlap(n, p) {
				return errors.New("directory overlaps mount claim")
			}
		}
	}
	return nil
}
