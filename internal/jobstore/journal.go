//go:build windows

package jobstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	platform "uupbuilder/internal/platform/windows"
)

const maxJournal = 16 << 20

type stageRecord struct {
	ID         string                `json:"id"`
	Scratch    string                `json:"scratch"`
	Promotion  string                `json:"promotion"`
	Intent     MutationIntent        `json:"intent"`
	MountPaths []string              `json:"mount_paths,omitempty"`
	Mounts     []platform.OwnedMount `json:"mounts,omitempty"`
	Candidates []OutputIdentity      `json:"candidates,omitempty"`
	Committed  bool                  `json:"committed"`
}
type checkpointRecord struct {
	Checkpoint Checkpoint `json:"checkpoint"`
	Directory  string     `json:"directory"`
}
type journal struct {
	Version     int                `json:"version"`
	JobID       string             `json:"job_id"`
	Generation  uint64             `json:"generation"`
	Stages      []stageRecord      `json:"stages"`
	Checkpoints []checkpointRecord `json:"checkpoints"`
	Discarded   bool               `json:"discarded"`
}
type envelope struct {
	SHA256 string          `json:"sha256"`
	Record json.RawMessage `json:"record"`
}

func clone[T any](v T) T {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}
func strictDecode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing journal data")
	}
	return nil
}
func hashBytes(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }

func (s *Store) readJournal() error {
	f, err := s.w.OpenFile(journalPath, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxJournal+1))
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if len(b) > maxJournal {
		return errors.New("journal too large")
	}
	var e envelope
	if err := strictDecode(b, &e); err != nil {
		return fmt.Errorf("invalid journal: %w", err)
	}
	if !validDigest(e.SHA256) || hashBytes(e.Record) != e.SHA256 {
		return errors.New("journal checksum mismatch")
	}
	var j journal
	if err := strictDecode(e.Record, &j); err != nil {
		return err
	}
	if err := s.validateJournal(j); err != nil {
		return err
	}
	s.state = j
	return nil
}

func (s *Store) validateJournal(j journal) error {
	if j.Version != 1 || j.JobID != s.Identity().JobID || j.Generation == 0 {
		return errors.New("unsupported or foreign journal")
	}
	seen := map[string]bool{}
	owners := map[string]stageRecord{}
	for _, st := range j.Stages {
		b, err := hex.DecodeString(st.ID)
		if err != nil || len(b) != 16 || st.ID != strings.ToLower(st.ID) || seen[st.ID] || st.Scratch != "scratch/"+st.ID || st.Promotion != "checkpoints/"+st.ID {
			return errors.New("invalid stage ownership")
		}
		seen[st.ID] = true
		owners[st.Promotion] = st
		if st.Intent.JobID != j.JobID {
			return errors.New("foreign stage")
		}
		if _, err := normalizeIntent(st.Intent); err != nil {
			return err
		}
		for _, p := range st.MountPaths {
			n, err := cleanRelative(p)
			if err != nil || n != p || !strings.HasPrefix(p, st.Scratch+"/") {
				return errors.New("invalid mount ownership path")
			}
		}
		for _, m := range st.Mounts {
			if m.Workspace != s.Identity() || m.JobID != j.JobID || m.OperationID != st.Intent.StageID || !contains(st.MountPaths, m.RelativePath) {
				return errors.New("foreign mount capability")
			}
		}
		candidatePaths := map[string]bool{}
		for _, o := range st.Candidates {
			if err := validateOutput(o); err != nil {
				return err
			}
			if !strings.HasPrefix(o.Path, st.Promotion+"/") || !contains(st.Intent.OwnedPaths, strings.TrimPrefix(o.Path, st.Promotion+"/")) || candidatePaths[strings.ToLower(o.Path)] {
				return errors.New("foreign promotion path")
			}
			candidatePaths[strings.ToLower(o.Path)] = true
		}
	}
	seen = map[string]bool{}
	for _, c := range j.Checkpoints {
		owner, found := owners[c.Directory]
		if !found || !owner.Committed || seen[c.Directory] || !reflect.DeepEqual(owner.Intent, c.Checkpoint.Intent) || !reflect.DeepEqual(owner.Candidates, c.Checkpoint.Outputs) {
			return errors.New("checkpoint has no committed owner")
		}
		seen[c.Directory] = true
		if err := validateCheckpoint(c); err != nil {
			return err
		}
	}
	for _, st := range j.Stages {
		if st.Committed && !seen[st.Promotion] {
			return errors.New("committed stage has no checkpoint")
		}
	}
	return nil
}
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Publication is one W1 handle-relative native rename bracketed by file flushes.
// Keep the exact write-capable file object open until after its renamed metadata
// is flushed. On Windows File.Sync calls FlushFileBuffers; Microsoft's File
// Caching contract requires flushing metadata after a namespace change:
// https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching
// Even barrier/close errors after replacement retain the new in-memory record
// while withholding success (and therefore any subsequent mutation grant).
func (s *Store) writeJournal(next journal) (resultErr error) {
	next.Generation = s.state.Generation + 1
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	data, err := json.Marshal(envelope{SHA256: hashBytes(b), Record: b})
	if err != nil {
		return err
	}
	if len(data) > maxJournal {
		return errors.New("journal limit exceeded")
	}
	if err := s.interrupt("journal-before-write"); err != nil {
		return err
	}
	id, err := token()
	if err != nil {
		return err
	}
	tmp := "journal-" + id + ".tmp"
	f, err := s.w.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer s.w.Remove(tmp)
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		return err
	}
	if err := s.interrupt("journal-after-write"); err != nil {
		return err
	}
	if err := s.interrupt("journal-before-replace"); err != nil {
		return err
	}
	if err := s.w.Replace(tmp, journalPath, s.state.Generation != 0); err != nil {
		return err
	}
	s.state = next
	if err := s.interrupt("journal-after-replace"); err != nil {
		return err
	}
	// The handle came from rooted W1 O_WRONLY creation (GENERIC_WRITE), not
	// from a path reopen or a directory/volume flush. It still identifies the
	// published object even though its original temporary name no longer does.
	if s.flushPublished != nil {
		err = s.flushPublished(f)
	} else {
		err = f.Sync()
	}
	if err != nil {
		return fmt.Errorf("flush published journal metadata: %w", err)
	}
	return nil
}
