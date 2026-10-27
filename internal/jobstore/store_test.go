//go:build windows

package jobstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	platform "uupbuilder/internal/platform/windows"
)

var testContext = context.Background()

// This fixture is explicitly test-only. Production has no assumed-unmounted
// implementation: a provider must supply a complete actual OS inventory.
type mountInventory struct {
	snapshot MountSnapshot
	err      error
}

func (m *mountInventory) Inspect(context.Context, string) (MountSnapshot, error) {
	return m.snapshot, m.err
}

func digest(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
func intent(stage string) MutationIntent {
	return MutationIntent{JobID: "job", PlanDigest: digest("plan"), ConfigDigest: digest("config"), StageID: stage,
		Inputs: []NamedDigest{{Name: "source", Digest: digest("source")}},
		Tools:  []VersionedIdentity{{Name: "tool", Version: "1", Digest: digest("tool")}},
		Rules:  []VersionedIdentity{{Name: "rules", Version: "1", Digest: digest("rules")}}, OwnedPaths: []string{"image.wim"}}
}
func newStore(t *testing.T) (*Store, *mountInventory) {
	t.Helper()
	inspector := &mountInventory{snapshot: MountSnapshot{Complete: true}}
	s, err := Create(t.TempDir(), "job", inspector)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, inspector
}
func writeOutput(t *testing.T, tx *Transaction, name, data string) OutputIdentity {
	t.Helper()
	f, err := tx.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(data)
	err = errors.Join(err, f.Close())
	if err != nil {
		t.Fatal(err)
	}
	return OutputIdentity{Path: name, Size: int64(len(data)), SHA256: digest(data), Role: "image"}
}
func commitStage(t *testing.T, s *Store, in MutationIntent, data string) Checkpoint {
	t.Helper()
	tx, err := s.Begin(testContext, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(testContext, []OutputIdentity{writeOutput(t, tx, "image.wim", data)}); err != nil {
		t.Fatal(err)
	}
	r, err := s.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	return r.Checkpoints[len(r.Checkpoints)-1].Checkpoint
}
func readOwned(t *testing.T, s *Store, relative string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.Identity().Path, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestIntentPersistsBeforeMutation(t *testing.T) {
	s, _ := newStore(t)
	s.fail = func(point string) error {
		if point == "journal-before-replace" {
			return errors.New("journal unavailable")
		}
		return nil
	}
	if tx, err := s.Begin(testContext, intent("assemble")); err == nil || tx != nil {
		t.Fatal("exposed mutation before durable intent")
	}
	s.fail = nil
	tx, err := s.Begin(testContext, intent("assemble"))
	if err != nil {
		t.Fatal(err)
	}
	journal := readOwned(t, s, journalPath)
	if !strings.Contains(journal, "assemble") {
		t.Fatal("intent absent before mutation permission")
	}
	writeOutput(t, tx, "image.wim", "partial")
	oldPath, err := tx.ScratchPath("image.wim")
	if err != nil {
		t.Fatal(err)
	}
	id := s.Identity()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(id, &mountInventory{snapshot: MountSnapshot{Complete: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	r, err := reopened.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Interrupted) != 1 || r.Interrupted[0].Intent.StageID != "assemble" || len(r.Checkpoints) != 0 {
		t.Fatalf("lost interrupted intent: %#v", r)
	}
	newTx, err := reopened.Begin(testContext, intent("assemble"))
	if err != nil {
		t.Fatal(err)
	}
	newPath, _ := newTx.ScratchPath("image.wim")
	if oldPath == newPath {
		t.Fatal("restart reused interrupted mutable scratch")
	}
}

func TestCheckpointIncludesRulesToolsAndPredecessors(t *testing.T) {
	s, _ := newStore(t)
	base := commitStage(t, s, intent("base"), "base")
	in := intent("service")
	in.Predecessors = []PredecessorIdentity{{StageID: "base", Digest: base.Digest}}
	got := commitStage(t, s, in, "serviced")
	if got.Intent.Tools[0].Digest != digest("tool") || got.Intent.Rules[0].Version != "1" || got.Intent.Predecessors[0].Digest != base.Digest || got.Intent.ConfigDigest != digest("config") || got.Intent.Inputs[0].Digest != digest("source") {
		t.Fatalf("identity binding lost: %#v", got)
	}
	for _, change := range []struct {
		name string
		edit func(*MutationIntent)
	}{
		{"rule", func(i *MutationIntent) { i.Rules[0].Digest = digest("new rule") }},
		{"tool", func(i *MutationIntent) { i.Tools[0].Digest = digest("new tool") }},
		{"config", func(i *MutationIntent) { i.ConfigDigest = digest("new config") }},
		{"input", func(i *MutationIntent) { i.Inputs[0].Digest = digest("new source") }},
		{"plan", func(i *MutationIntent) { i.PlanDigest = digest("new plan") }},
	} {
		t.Run(change.name, func(t *testing.T) {
			other, _ := newStore(t)
			original := commitStage(t, other, intent("base"), "same")
			changed := intent("base")
			change.edit(&changed)
			next := commitStage(t, other, changed, "same")
			if original.Digest == next.Digest {
				t.Fatal("identity change reused checkpoint digest")
			}
		})
	}
	bad := intent("bad")
	bad.Predecessors = []PredecessorIdentity{{StageID: "base", Digest: digest("not a checkpoint")}}
	if _, err := s.Begin(testContext, bad); err == nil {
		t.Fatal("accepted unknown predecessor")
	}
	// Public snapshots and caller intent slices must not mutate durable identity.
	got.Intent.Tools[0].Digest = digest("corrupt snapshot")
	r, err := s.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	if r.Checkpoints[1].Checkpoint.Intent.Tools[0].Digest != digest("tool") {
		t.Fatal("snapshot aliases store")
	}
}

func TestPartialStageCannotChangeCommittedOutput(t *testing.T) {
	s, _ := newStore(t)
	cp := commitStage(t, s, intent("base"), "pristine")
	in := intent("service")
	in.Predecessors = []PredecessorIdentity{{StageID: "base", Digest: cp.Digest}}
	tx, err := s.Begin(testContext, in)
	if err != nil {
		t.Fatal(err)
	}
	output := writeOutput(t, tx, "image.wim", "partial")
	s.fail = func(point string) error {
		if point == "promotion-after-copy" {
			return errors.New("interrupted promotion")
		}
		return nil
	}
	if err := tx.Commit(testContext, []OutputIdentity{output}); err == nil {
		t.Fatal("injected interruption ignored")
	}
	if got := readOwned(t, s, cp.Outputs[0].Path); got != "pristine" {
		t.Fatalf("committed output modified: %q", got)
	}
	s.fail = nil
	r, err := s.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Checkpoints) != 1 || !r.Checkpoints[0].Valid {
		t.Fatalf("partial output became reusable: %#v", r)
	}
	// Even a provider handle retained across commit cannot change the copied checkpoint.
	s2, _ := newStore(t)
	tx2, _ := s2.Begin(testContext, intent("base"))
	out := writeOutput(t, tx2, "image.wim", "original")
	f, err := tx2.OpenFile("image.wim", os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := tx2.Commit(testContext, []OutputIdentity{out}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("changed!"), 0); err != nil {
		t.Fatal(err)
	}
	r2, _ := s2.InspectRecovery(testContext, "job")
	if !r2.Checkpoints[0].Valid {
		t.Fatal("retained scratch handle modified checkpoint")
	}
}

func TestAtomicJournalFailurePreservesPreviousRecord(t *testing.T) {
	for _, point := range []string{"journal-before-write", "journal-after-write", "journal-before-replace", "journal-after-replace", "mutation-before-mkdir", "mutation-after-mkdir", "promotion-before-copy", "promotion-after-copy", "promotion-before-journal", "promotion-after-journal"} {
		t.Run(point, func(t *testing.T) {
			s, inspector := newStore(t)
			cp := commitStage(t, s, intent("base"), "pristine")
			oldJournal := readOwned(t, s, journalPath)
			in := intent("next")
			in.Predecessors = []PredecessorIdentity{{StageID: "base", Digest: cp.Digest}}
			triggered := false
			injection := func(p string) error {
				if p == point && !triggered {
					triggered = true
					return errors.New("bounded interruption")
				}
				return nil
			}
			if strings.HasPrefix(point, "journal-") || strings.HasPrefix(point, "mutation-") {
				s.fail = injection
			}
			tx, err := s.Begin(testContext, in)
			if err == nil {
				out := writeOutput(t, tx, "image.wim", "validated")
				s.fail = injection
				err = tx.Commit(testContext, []OutputIdentity{out})
			}
			if err == nil || !triggered {
				t.Fatalf("did not inject %s: %v", point, err)
			}
			if strings.HasPrefix(point, "journal-") && point != "journal-after-replace" && readOwned(t, s, journalPath) != oldJournal {
				t.Fatal("failed journal changed previous record")
			}
			id := s.Identity()
			s.Close()
			reopened, err := Open(id, inspector)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			r, err := reopened.InspectRecovery(testContext, "job")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Checkpoints) < 1 || len(r.Checkpoints) > 2 || !r.Checkpoints[0].Valid || readOwned(t, reopened, cp.Outputs[0].Path) != "pristine" {
				t.Fatalf("no atomic old/new state: %#v", r)
			}
			if len(r.Checkpoints) == 2 && !r.Checkpoints[1].Valid {
				t.Fatal("partly promoted new checkpoint")
			}
		})
	}
}

func TestDiscardPreservesExternalSourcesAndUnownedMounts(t *testing.T) {
	s, inspector := newStore(t)
	outside := filepath.Join(t.TempDir(), "driver.inf")
	if err := os.WriteFile(outside, []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}
	cp := commitStage(t, s, intent("base"), "owned")
	in := intent("next")
	tx, err := s.Begin(testContext, in)
	if err != nil {
		t.Fatal(err)
	}
	writeOutput(t, tx, "image.wim", "partial")
	mount, err := tx.ClaimMount("mount")
	if err != nil {
		t.Fatal(err)
	}
	inspector.snapshot.Mounts = []MountObservation{{Path: filepath.Join(t.TempDir(), "unrelated-mount"), State: MountMounted}, {Path: filepath.Join(s.Identity().Path, filepath.FromSlash(mount.RelativePath)), State: MountMounted}}
	if err := s.Discard(testContext, "job"); err == nil {
		t.Fatal("discard removed an actually mounted directory")
	}
	if readOwned(t, s, cp.Outputs[0].Path) != "owned" {
		t.Fatal("unsafe discard partly removed checkpoint")
	}
	inspector.snapshot.Mounts = inspector.snapshot.Mounts[:1]
	if err := s.Discard(testContext, "job"); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "source" {
		t.Fatalf("source removed: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(s.Identity().Path, filepath.FromSlash(cp.Outputs[0].Path))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned output retained: %v", err)
	}
	if _, err := s.Begin(testContext, intent("after-discard")); err == nil {
		t.Fatal("discarded job restarted")
	}
}

func TestRecoveryInspectsRealState(t *testing.T) {
	s, inspector := newStore(t)
	base := commitStage(t, s, intent("base"), "base")
	in := intent("service")
	in.Predecessors = []PredecessorIdentity{{StageID: "base", Digest: base.Digest}}
	commitStage(t, s, in, "serviced")
	independent := commitStage(t, s, intent("independent"), "separate")
	if err := os.WriteFile(filepath.Join(s.Identity().Path, filepath.FromSlash(base.Outputs[0].Path)), []byte("fake"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := s.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	if r.Checkpoints[0].Valid || r.Checkpoints[1].Valid || !r.Checkpoints[2].Valid || r.Checkpoints[2].Checkpoint.Digest != independent.Digest {
		t.Fatalf("invalidation did not follow exact predecessors: %#v", r)
	}
	if !strings.Contains(r.Checkpoints[0].Reason, "output") || !strings.Contains(r.Checkpoints[1].Reason, "predecessor") {
		t.Fatalf("missing diagnoses: %#v", r)
	}
	bad := intent("after-corruption")
	bad.Predecessors = []PredecessorIdentity{{StageID: "base", Digest: base.Digest}}
	if _, err := s.Begin(testContext, bad); err == nil {
		t.Fatal("reused corrupt predecessor")
	}
	inspector.snapshot.Complete = false
	r, err = s.InspectRecovery(testContext, "job")
	if err != nil {
		t.Fatal(err)
	}
	if r.CanResume || len(r.Preserved) == 0 {
		t.Fatal("unknown mount state hidden")
	}
	if err := s.Discard(testContext, "job"); err == nil {
		t.Fatal("discard trusted unknown mounts")
	}
	if _, err := s.InspectRecovery(testContext, "foreign"); err == nil {
		t.Fatal("foreign job accepted")
	}
}

func TestRecoveryPrivateOwnershipAndWriterExclusion(t *testing.T) {
	s, inspector := newStore(t)
	cp := commitStage(t, s, intent("base"), "owned")
	id := s.Identity()
	if other, err := Open(id, inspector); err == nil {
		other.Close()
		t.Fatal("two writers acquired same workspace")
	}
	id.Token = strings.Repeat("0", 32)
	if other, err := Open(id, inspector); err == nil {
		other.Close()
		t.Fatal("forged workspace capability accepted")
	}
	if strings.Contains(readOwned(t, s, journalPath), s.Identity().Token) {
		t.Fatal("private workspace token leaked into journal checkpoint data")
	}
	if !strings.HasPrefix(cp.Outputs[0].Path, "checkpoints/") {
		t.Fatal("checkpoint did not leave scratch")
	}
}

// Keep the accepted W1 claim type at this boundary; do not replace its native
// identity with a path-only jobstore duplicate.
var _ platform.OwnedMount
