package jobstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	platform "uupbuilder/internal/platform/windows"
)

// Removing any journal/transaction/held-identity check must make these fail.
func TestDirectoryClaimCheckLiveRejectsUnresolvedForeignAndClosed(t *testing.T) {
	for _, kind := range []string{"live", "foreign-record", "foreign-intent", "foreign-durable-intent", "committed", "foreign-scratch", "closed-writer", "root-identity", "inactive-writer", "missing-journal", "unresolved", "released", "closed-tree", "closed-store"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := newStore(t)
			in := intent("native-trial")
			in.Inputs = append(in.Inputs, NamedDigest{Name: "preservation-proof", Digest: digest("proof")})
			tx, e := s.Begin(testContext, in)
			if e != nil {
				t.Fatal(e)
			}
			c, e := tx.ClaimDirectory(testContext, digest("proof"))
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "foreign-durable-intent":
				s.state.Stages[s.stageIndex(tx.id)].Intent.ConfigDigest = digest("foreign")
			case "committed":
				s.state.Stages[s.stageIndex(tx.id)].Committed = true
			case "foreign-scratch":
				s.state.Stages[s.stageIndex(tx.id)].Scratch = "foreign"
			case "closed-writer":
				s.lock.Close()
			case "foreign-intent":
				tx.intent.Inputs[0].Digest = digest("foreign")
			case "root-identity":
				c.record.Identity.FileIndex++
			case "inactive-writer":
				s.active = nil
			case "foreign-record":
				c.record.SourceDigest = digest("foreign")
			case "missing-journal":
				s.state.Stages[s.stageIndex(tx.id)].Directories = nil
			case "unresolved":
				c.record.Identity = platform.FileIdentity{}
			case "released":
				if e = c.Release(testContext); e != nil {
					t.Fatal(e)
				}
			case "closed-tree":
				c.tree.Close()
			case "closed-store":
				s.Close()
			}
			e = c.CheckLive(testContext)
			if (e == nil) != (kind == "live") {
				t.Fatalf("%s: %v", kind, e)
			}
		})
	}
	if e := (&DirectoryClaim{}).CheckLive(context.Background()); e == nil {
		t.Fatal("zero claim")
	}
}

func TestDirectoryClaimDurableRefusalAndCheckedRelease(t *testing.T) {
	s, _ := newStore(t)
	in := intent("preservation")
	in.Inputs = append(in.Inputs, NamedDigest{Name: "preservation-proof", Digest: digest("proof")})
	tx, e := s.Begin(testContext, in)
	if e != nil {
		t.Fatal(e)
	}
	if c, e := tx.ClaimDirectory(testContext, digest("foreign")); c != nil || e == nil {
		t.Fatal("foreign source claim", e)
	}
	c, e := tx.ClaimDirectory(testContext, digest("proof"))
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.InspectRecovery(testContext, "job")
	if e != nil || len(r.Preserved) == 0 {
		t.Fatal("active directory escaped generic guard", r, e)
	}
	if e = c.Tree().CreateFile(testContext, "owned", []byte("fixture")); e != nil {
		t.Fatal(e)
	}
	if e = c.Release(testContext); e == nil {
		t.Fatal("nonempty release succeeded")
	}
	if e = c.Tree().Cleanup(testContext); !errors.Is(e, platform.ErrTreePreserved) {
		t.Fatal("file-containing cleanup falsely complete", e)
	}
	if e = c.Release(testContext); e == nil {
		t.Fatal("preserved file-containing scope released")
	}
	if e = s.Close(); !errors.Is(e, platform.ErrTreePreserved) {
		t.Fatal("preserved store Close falsely clean", e)
	}
	// A separate fresh directory-only claim exercises actual safe release;
	// test TempDir teardown of the preserved first tree is not cleanup proof.
	emptyStore, inventory := newStore(t)
	emptyTx, e := emptyStore.Begin(testContext, in)
	if e != nil {
		t.Fatal(e)
	}
	c, e = emptyTx.ClaimDirectory(testContext, digest("proof"))
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Tree().Cleanup(testContext); e != nil {
		t.Fatal(e)
	}
	inventory.snapshot.Complete = false
	if e = c.Release(testContext); e == nil {
		t.Fatal("incomplete resource inventory release")
	}
	inventory.snapshot.Complete = true
	if e = c.Release(testContext); e != nil {
		t.Fatal(e)
	}
	if e = c.Release(testContext); e != nil {
		t.Fatal("idempotent release", e)
	}
}

func TestDirectoryClaimReleasedPathCannotAdoptReplacement(t *testing.T) {
	s, _ := newStore(t)
	in := intent("preservation")
	in.Inputs = append(in.Inputs, NamedDigest{Name: "preservation-proof", Digest: digest("proof")})
	tx, e := s.Begin(testContext, in)
	if e != nil {
		t.Fatal(e)
	}
	c, e := tx.ClaimDirectory(testContext, digest("proof"))
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(s.Identity().Path, filepath.FromSlash(c.Tree().Identity().RelativePath))
	if e = c.Release(testContext); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	r, e := s.InspectRecovery(testContext, "job")
	if e != nil || len(r.Preserved) == 0 {
		t.Fatal("released path adopted foreign replacement", e, r.Preserved)
	}
	if e = s.Discard(testContext, "job"); e == nil {
		t.Fatal("discard accepted foreign replacement")
	}
	if _, e = os.Stat(path); e != nil {
		t.Fatal("foreign replacement removed", e)
	}
}

func TestDirectoryClaimEarlyJournalFailureAndCancellation(t *testing.T) {
	s, _ := newStore(t)
	in := intent("preservation")
	in.Inputs = append(in.Inputs, NamedDigest{Name: "preservation-proof", Digest: digest("proof")})
	tx, e := s.Begin(testContext, in)
	if e != nil {
		t.Fatal(e)
	}
	s.fail = func(p string) error {
		if p == "journal-before-replace" {
			return errors.New("write refused")
		}
		return nil
	}
	if c, e := tx.ClaimDirectory(testContext, digest("proof")); c != nil || e == nil {
		t.Fatal(c, e)
	}
	s.fail = nil
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if c, e := tx.ClaimDirectory(ctx, digest("proof")); c != nil || e != context.Canceled {
		t.Fatal(c, e)
	}
	if _, e := os.Stat(s.Identity().Path); e != nil {
		t.Fatal(e)
	}
}

func TestDirectoryClaimPartialCreationRetainsExactCustody(t *testing.T) {
	s, _ := newStore(t)
	in := intent("preservation")
	in.Inputs = append(in.Inputs, NamedDigest{Name: "preservation-proof", Digest: digest("proof")})
	tx, e := s.Begin(testContext, in)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	s.fail = func(p string) error {
		if p == "journal-before-replace" {
			calls++
			if calls == 2 {
				return errors.New("identity journal refused")
			}
		}
		return nil
	}
	c, e := tx.ClaimDirectory(testContext, digest("proof"))
	if c == nil || c.Tree() == nil || e == nil {
		t.Fatal("partial created scope lost", c, e)
	}
	s.fail = nil
	if e = c.Release(testContext); e == nil {
		t.Fatal("unjournaled native identity released")
	}
	r, e := s.InspectRecovery(testContext, "job")
	if e != nil || len(r.Preserved) == 0 {
		t.Fatal("partial claim unreported", r, e)
	}
	if e = c.Tree().RemoveEmpty(testContext); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e == nil {
		t.Fatal("unreleased partial custody close reported clean")
	}
}
