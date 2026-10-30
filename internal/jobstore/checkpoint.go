//go:build windows

package jobstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

func validateOutput(o OutputIdentity) error {
	n, err := cleanRelative(o.Path)
	if err != nil || n != o.Path || o.Size < 0 || !validDigest(o.SHA256) || !validLabel(o.Role) {
		return errors.New("output requires a logical path, size, SHA256 and role")
	}
	return nil
}

func checkpointDigest(in MutationIntent, outputs []OutputIdentity, directory string) (string, error) {
	logical := clone(outputs)
	for i, o := range logical {
		if err := validateOutput(o); err != nil {
			return "", err
		}
		if !strings.HasPrefix(o.Path, directory+"/") {
			return "", errors.New("checkpoint output outside its immutable directory")
		}
		logical[i].Path = strings.TrimPrefix(o.Path, directory+"/")
	}
	sort.Slice(logical, func(i, j int) bool { return logical[i].Path < logical[j].Path })
	b, err := json.Marshal(struct {
		Intent  MutationIntent   `json:"intent"`
		Outputs []OutputIdentity `json:"outputs"`
	}{in, logical})
	if err != nil {
		return "", err
	}
	return hashBytes(b), nil
}
func validateCheckpoint(c checkpointRecord) error {
	if len(c.Checkpoint.Outputs) == 0 {
		return errors.New("empty checkpoint")
	}
	in, err := normalizeIntent(c.Checkpoint.Intent)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, o := range c.Checkpoint.Outputs {
		if err := validateOutput(o); err != nil {
			return err
		}
		if !strings.HasPrefix(o.Path, c.Directory+"/") {
			return errors.New("foreign checkpoint output")
		}
		logical := strings.TrimPrefix(o.Path, c.Directory+"/")
		if !contains(in.OwnedPaths, logical) || seen[strings.ToLower(o.Path)] {
			return errors.New("checkpoint output not owned by intent")
		}
		seen[strings.ToLower(o.Path)] = true
	}
	digest, err := checkpointDigest(in, c.Checkpoint.Outputs, c.Directory)
	if err != nil || digest != c.Checkpoint.Digest {
		return errors.New("checkpoint identity checksum mismatch")
	}
	return nil
}

func regularUnshared(f *os.File) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("output is not a regular file")
	}
	var native windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &native); err != nil {
		return err
	}
	if native.NumberOfLinks != 1 || native.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("output has shared links or reparse topology")
	}
	return nil
}

type contextReader struct {
	context.Context
	r io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
func (s *Store) verifyOutput(ctx context.Context, output OutputIdentity) error {
	f, err := s.w.OpenFile(output.Path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := regularUnshared(f); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx, f})
	if err != nil {
		return err
	}
	if n != output.Size || hex.EncodeToString(h.Sum(nil)) != output.SHA256 {
		return errors.New("output size or SHA256 differs from checkpoint")
	}
	return nil
}

// copyOutput never renames mutable provider scratch into a reusable checkpoint.
// Its independent synced copy is checked against caller-declared actual bytes.
func (s *Store) copyOutput(ctx context.Context, source string, output OutputIdentity) error {
	src, err := s.w.OpenFile(source, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	if err := regularUnshared(src); err != nil {
		return err
	}
	if err := s.w.MkdirAll(filepath.ToSlash(filepath.Dir(output.Path))); err != nil {
		return err
	}
	dst, err := s.w.OpenFile(output.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), contextReader{ctx, src})
	if err == nil && (n != output.Size || hex.EncodeToString(h.Sum(nil)) != output.SHA256) {
		err = errors.New("output bytes differ from declared size or SHA256")
	}
	if err == nil {
		err = dst.Sync()
	}
	err = errors.Join(err, dst.Close())
	if err != nil {
		return err
	}
	return s.verifyOutput(ctx, output)
}

func (s *Store) stageIndex(id string) int {
	for i, st := range s.state.Stages {
		if st.ID == id {
			return i
		}
	}
	return -1
}

// Commit validates real predecessors and output bytes before atomically
// publishing the new checkpoint record. Any failure ends mutation permission;
// a subsequent attempt begins with new scratch, preserving all older outputs.
func (tx *Transaction) Commit(ctx context.Context, outputs []OutputIdentity) (resultErr error) {
	s := tx.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, tx.intent.JobID); err != nil {
		return err
	}
	if err := tx.usable(); err != nil {
		return err
	}
	defer func() { tx.done = true; s.active = nil; resultErr = errors.Join(resultErr, tx.closePredecessors()) }()
	if len(outputs) == 0 || len(outputs) > len(tx.intent.OwnedPaths) {
		return errors.New("bounded nonempty outputs required")
	}
	recovery, err := s.inspect(ctx)
	if err != nil {
		return err
	}
	if len(recovery.Preserved) > 0 {
		return errors.New("unresolved resources prevent checkpoint promotion")
	}
	for _, p := range tx.intent.Predecessors {
		found := false
		for _, c := range recovery.Checkpoints {
			if c.Valid && c.Checkpoint.Digest == p.Digest && c.Checkpoint.Intent.StageID == p.StageID {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("predecessor %s changed before commit", p.StageID)
		}
	}
	idx := s.stageIndex(tx.id)
	if idx < 0 {
		return errors.New("durable intent missing")
	}
	st := s.state.Stages[idx]
	candidates := clone(outputs)
	seen := map[string]bool{}
	for i, o := range candidates {
		if err := validateOutput(o); err != nil {
			return err
		}
		src, err := tx.owned(o.Path)
		if err != nil {
			return err
		}
		if seen[strings.ToLower(o.Path)] {
			return errors.New("duplicate output path")
		}
		seen[strings.ToLower(o.Path)] = true
		actual := o
		actual.Path = src
		if err := s.verifyOutput(ctx, actual); err != nil {
			return fmt.Errorf("validate stage output: %w", err)
		}
		candidates[i].Path = st.Promotion + "/" + o.Path
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Path < candidates[j].Path })
	// Promotion paths themselves are also durable intent before file creation.
	next := clone(s.state)
	next.Stages[idx].Candidates = candidates
	if err := s.writeJournal(next); err != nil {
		return err
	}
	if err := s.interrupt("promotion-before-copy"); err != nil {
		return err
	}
	for _, o := range candidates {
		logical := strings.TrimPrefix(o.Path, st.Promotion+"/")
		if err := s.copyOutput(ctx, st.Scratch+"/"+logical, o); err != nil {
			return fmt.Errorf("promote output: %w", err)
		}
	}
	if err := s.interrupt("promotion-after-copy"); err != nil {
		return err
	}
	// Revalidate dependencies after copying, before making output reusable.
	final, err := s.inspect(ctx)
	if err != nil {
		return err
	}
	if len(final.Preserved) > 0 {
		return errors.New("resources changed during checkpoint promotion")
	}
	for _, p := range tx.intent.Predecessors {
		found := false
		for _, c := range final.Checkpoints {
			if c.Valid && c.Checkpoint.Digest == p.Digest && c.Checkpoint.Intent.StageID == p.StageID {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("predecessor %s or its ancestry changed during promotion", p.StageID)
		}
	}
	for _, o := range candidates {
		if err := s.verifyOutput(ctx, o); err != nil {
			return fmt.Errorf("copied output changed during promotion: %w", err)
		}
	}
	if err := s.interrupt("promotion-before-journal"); err != nil {
		return err
	}
	digest, err := checkpointDigest(tx.intent, candidates, st.Promotion)
	if err != nil {
		return err
	}
	next = clone(s.state)
	next.Stages[idx].Committed = true
	next.Checkpoints = append(next.Checkpoints, checkpointRecord{Directory: st.Promotion, Checkpoint: Checkpoint{Digest: digest, Intent: tx.intent, Outputs: candidates}})
	if err := s.writeJournal(next); err != nil {
		return err
	}
	return s.interrupt("promotion-after-journal")
}
