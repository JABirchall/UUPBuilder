//go:build windows

// Package jobstore persists private mutation intent and validated immutable
// checkpoints independently of planning, engine providers and UI state.
package jobstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

type NamedDigest struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}
type VersionedIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}
type PredecessorIdentity struct {
	StageID string `json:"stage_id"`
	Digest  string `json:"digest"`
}

// MutationIntent contains identities only. Never put runtime locators,
// credentials or decryption keys in these private durable records.
type MutationIntent struct {
	JobID        string                `json:"job_id"`
	PlanDigest   string                `json:"plan_digest"`
	ConfigDigest string                `json:"config_digest"`
	StageID      string                `json:"stage_id"`
	Inputs       []NamedDigest         `json:"inputs"`
	Tools        []VersionedIdentity   `json:"tools"`
	Rules        []VersionedIdentity   `json:"rules"`
	Predecessors []PredecessorIdentity `json:"predecessors"`
	OwnedPaths   []string              `json:"owned_paths"`
}

// OutputIdentity.Path is scratch-relative when passed to Commit, and
// workspace-relative in a committed checkpoint. SHA256 is lowercase hex.
type OutputIdentity struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Role   string `json:"role"`
}
type Checkpoint struct {
	Digest  string           `json:"digest"`
	Intent  MutationIntent   `json:"intent"`
	Outputs []OutputIdentity `json:"outputs"`
}
type CheckpointStatus struct {
	Checkpoint Checkpoint
	Valid      bool
	Reason     string
}
type InterruptedStage struct {
	Intent      MutationIntent
	ScratchPath string
}
type PreservedResource struct {
	Path   string
	Reason string
}
type RecoveryPlan struct {
	Checkpoints []CheckpointStatus
	Interrupted []InterruptedStage
	Preserved   []PreservedResource
	CanResume   bool
	Discarded   bool
}
type MountState string

const MountMounted MountState = "mounted"

type MountObservation struct {
	Path  string
	State MountState
}

// Complete means the OS inventory succeeded, not that journal claims matched.
// Store additionally checks the real workspace topology before destructive IO.
type MountSnapshot struct {
	Complete bool
	Mounts   []MountObservation
}

// MountInspector must query actual OS state. Nil selects the system DISM API;
// test inventories must never be used to authorize production mutation.
type MountInspector interface {
	Inspect(context.Context, string) (MountSnapshot, error)
}

type Store struct {
	mu        sync.Mutex
	w         *platform.Workspace
	lock      *os.File
	state     journal
	inspector MountInspector
	active    *Transaction
	closed    bool
	// Unexported, nil in production; tests inject one bounded interruption.
	fail func(string) error
}
type Transaction struct {
	store       *Store
	id, scratch string
	intent      MutationIntent
	done        bool
}

const journalPath = "journal.json"

// Create creates a new protected local NTFS workspace; it never adopts a path.
func Create(parent, jobID string, inspector MountInspector) (*Store, error) {
	if !validLabel(jobID) {
		return nil, errors.New("invalid job identity")
	}
	w, err := platform.CreateWorkspace(parent, jobID)
	if err != nil {
		return nil, err
	}
	s, err := bind(w, inspector)
	if err != nil {
		w.Close()
		return nil, err
	}
	if err := s.writeJournal(journal{Version: 1, JobID: jobID}); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Open requires a trusted private recovery capability, and excludes concurrent
// writers. An interrupted transaction never regains mutation permission.
func Open(identity platform.WorkspaceIdentity, inspector MountInspector) (*Store, error) {
	w, err := platform.OpenWorkspace(identity)
	if err != nil {
		return nil, err
	}
	s, err := bind(w, inspector)
	if err != nil {
		w.Close()
		return nil, err
	}
	if err := s.readJournal(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func bind(w *platform.Workspace, inspector MountInspector) (*Store, error) {
	if inspector == nil {
		inspector = nativeMountInspector{}
	}
	s := &Store{w: w, inspector: inspector}
	if err := s.acquire(); err != nil {
		return nil, err
	}
	return s, nil
}

// Identity is a PRIVATE recovery capability. Do not include it in public plans,
// events, reports, or checkpoint serialization.
func (s *Store) Identity() platform.WorkspaceIdentity { return s.w.Identity() }
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.release(), s.w.Close())
}

func (s *Store) check(ctx context.Context, jobID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed {
		return os.ErrClosed
	}
	if jobID != s.w.Identity().JobID {
		return errors.New("foreign job identity")
	}
	return nil
}
func (s *Store) interrupt(point string) error {
	if s.fail != nil {
		return s.fail(point)
	}
	return nil
}

func token() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func validDigest(d string) bool {
	b, err := hex.DecodeString(d)
	return err == nil && len(b) == 32 && d == strings.ToLower(d)
}
func validLabel(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-+", c)) {
			return false
		}
	}
	return true
}
func cleanRelative(p string) (string, error) { return model.ValidateRelativePath(p) }

func normalizeIntent(in MutationIntent) (MutationIntent, error) {
	in = clone(in)
	if !validLabel(in.JobID) || !validLabel(in.StageID) || !validDigest(in.PlanDigest) || !validDigest(in.ConfigDigest) {
		return in, errors.New("job/stage and plan/config identities required")
	}
	if len(in.OwnedPaths) == 0 || len(in.OwnedPaths) > 4096 {
		return in, errors.New("bounded stage-owned file paths required")
	}
	seen := map[string]bool{}
	for i, p := range in.OwnedPaths {
		n, err := cleanRelative(p)
		if err != nil {
			return in, err
		}
		k := strings.ToLower(n)
		if seen[k] {
			return in, errors.New("duplicate owned path")
		}
		seen[k] = true
		in.OwnedPaths[i] = n
	}
	for _, p := range in.OwnedPaths {
		for _, q := range in.OwnedPaths {
			if strings.HasPrefix(strings.ToLower(p), strings.ToLower(q)+"/") {
				return in, errors.New("owned file is another file's parent")
			}
		}
	}
	check := func(name, hash string) error {
		if !validLabel(name) || !validDigest(hash) {
			return errors.New("invalid named identity")
		}
		return nil
	}
	seen = map[string]bool{}
	for _, v := range in.Inputs {
		if err := check(v.Name, v.Digest); err != nil {
			return in, err
		}
		if seen[v.Name] {
			return in, errors.New("duplicate input")
		}
		seen[v.Name] = true
	}
	for _, list := range [][]VersionedIdentity{in.Tools, in.Rules} {
		seen = map[string]bool{}
		for _, v := range list {
			if err := check(v.Name, v.Digest); err != nil {
				return in, err
			}
			if !validLabel(v.Version) || seen[v.Name] {
				return in, errors.New("invalid version or duplicate identity")
			}
			seen[v.Name] = true
		}
	}
	seen = map[string]bool{}
	for _, p := range in.Predecessors {
		if !validLabel(p.StageID) || !validDigest(p.Digest) || seen[p.Digest] {
			return in, errors.New("invalid or duplicate predecessor")
		}
		seen[p.Digest] = true
	}
	sort.Strings(in.OwnedPaths)
	sort.Slice(in.Inputs, func(i, j int) bool { return in.Inputs[i].Name < in.Inputs[j].Name })
	sort.Slice(in.Tools, func(i, j int) bool { return in.Tools[i].Name < in.Tools[j].Name })
	sort.Slice(in.Rules, func(i, j int) bool { return in.Rules[i].Name < in.Rules[j].Name })
	sort.Slice(in.Predecessors, func(i, j int) bool { return in.Predecessors[i].Digest < in.Predecessors[j].Digest })
	return in, nil
}

// Begin durably records intent before creating scratch or granting file access.
// After an interruption, Begin always allocates a distinct scratch directory.
func (s *Store) Begin(ctx context.Context, intent MutationIntent) (*Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx, intent.JobID); err != nil {
		return nil, err
	}
	if s.state.Discarded {
		return nil, errors.New("job is discarded")
	}
	if s.active != nil {
		return nil, errors.New("transaction already active")
	}
	in, err := normalizeIntent(intent)
	if err != nil {
		return nil, err
	}
	recovery, err := s.inspect(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range in.Predecessors {
		found := false
		for _, c := range recovery.Checkpoints {
			if c.Valid && c.Checkpoint.Digest == p.Digest && c.Checkpoint.Intent.StageID == p.StageID {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("predecessor %s is missing or invalid", p.StageID)
		}
	}
	id, err := token()
	if err != nil {
		return nil, err
	}
	scratch := "scratch/" + id
	next := clone(s.state)
	next.Stages = append(next.Stages, stageRecord{ID: id, Scratch: scratch, Promotion: "checkpoints/" + id, Intent: in})
	if err := s.writeJournal(next); err != nil {
		return nil, err
	}
	if err := s.interrupt("mutation-before-mkdir"); err != nil {
		return nil, err
	}
	if err := s.w.MkdirAll(scratch); err != nil {
		return nil, err
	}
	if err := s.interrupt("mutation-after-mkdir"); err != nil {
		return nil, err
	}
	tx := &Transaction{store: s, id: id, scratch: scratch, intent: in}
	s.active = tx
	return tx, nil
}

func (tx *Transaction) usable() error {
	if tx.store.closed {
		return os.ErrClosed
	}
	if tx.done || tx.store.state.Discarded || tx.store.active != tx {
		return errors.New("transaction no longer permits mutation")
	}
	return nil
}
func (tx *Transaction) owned(name string) (string, error) {
	n, err := cleanRelative(name)
	if err != nil {
		return "", err
	}
	for _, p := range tx.intent.OwnedPaths {
		if n == p {
			return tx.scratch + "/" + n, nil
		}
	}
	return "", errors.New("path not declared in durable intent")
}

// ScratchPath returns a declared provider path only after successful Begin.
// Providers must finish and close all mutation before Commit or Discard.
func (tx *Transaction) ScratchPath(name string) (string, error) {
	s := tx.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := tx.usable(); err != nil {
		return "", err
	}
	n, err := tx.owned(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(tx.store.w.Path(), filepath.FromSlash(n)), nil
}
func (tx *Transaction) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	s := tx.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := tx.usable(); err != nil {
		return nil, err
	}
	n, err := tx.owned(name)
	if err != nil {
		return nil, err
	}
	if err := s.w.MkdirAll(filepath.ToSlash(filepath.Dir(n))); err != nil {
		return nil, err
	}
	return s.w.OpenFile(n, flag, perm)
}
