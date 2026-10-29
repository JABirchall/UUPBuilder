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
	Identity                         platform.FileIdentity
	Released                         bool
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
	id, e := token()
	if e != nil {
		return nil, e
	}
	r := directoryRecord{Path: tx.scratch + "/tree-" + id, SourceDigest: source, IntentDigest: intentDigest(tx.intent)}
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
