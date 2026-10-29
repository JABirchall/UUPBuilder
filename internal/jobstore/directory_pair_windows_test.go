package jobstore

import (
	"errors"
	"testing"
)

func fixedPairIntent() MutationIntent {
	in := intent("fixed-source-contract-apply")
	in.PlanDigest = digest("proof")
	in.ConfigDigest = digest("profile")
	in.Inputs = nil
	for _, name := range []string{"preservation-proof", "generated-wim", "original-manifest", "original-index", "original-oracle", "original-references", "original-recipe"} {
		v := digest(name)
		if name == "preservation-proof" {
			v = digest("proof")
		}
		in.Inputs = append(in.Inputs, NamedDigest{Name: name, Digest: v})
	}
	in.Tools = []VersionedIdentity{{Name: "installed-wimgapi.dll", Version: "measured-fixed-apply", Digest: digest("provider")}}
	in.Rules = []VersionedIdentity{{Name: "fixed-apply-profile", Version: "1", Digest: in.ConfigDigest}}
	in.OwnedPaths = []string{"unused-component-output"}
	return in
}

// The fixed two-role capability must compose without weakening ClaimDirectory
// or permitting a third/unrelated scope through the ordinary resource guard.
func TestFixedSourceApplyPairDurableRolesAndRefusals(t *testing.T) {
	s, _ := newStore(t)
	tx, e := s.Begin(testContext, fixedPairIntent())
	if e != nil {
		t.Fatal(e)
	}
	d, c, e := tx.ClaimFixedSourceApplyDirectories(testContext, digest("proof"))
	if e != nil || d == nil || c == nil {
		t.Fatal(d, c, e)
	}
	if d.Role() != "destination" || c.Role() != "wimgapi-cache" || d.Tree().Identity().Root == c.Tree().Identity().Root || d.IntentDigest() != c.IntentDigest() {
		t.Fatal("roles/identity lost")
	}
	if e = errors.Join(d.CheckLive(testContext), c.CheckLive(testContext)); e != nil {
		t.Fatal(e)
	}
	if a, b, e := tx.ClaimFixedSourceApplyDirectories(testContext, digest("proof")); e == nil || a != nil || b != nil {
		t.Fatal("repeated pair allowed", e)
	}
	if third, e := tx.ClaimDirectory(testContext, digest("proof")); e == nil || third != nil {
		t.Fatal("third claim allowed", e)
	}
	other, _ := newStore(t)
	tx, e = other.Begin(testContext, fixedPairIntent())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.ClaimDirectory(testContext, digest("proof")); e != nil {
		t.Fatal(e)
	}
	if second, e := tx.ClaimDirectory(testContext, digest("proof")); e == nil || second != nil {
		t.Fatal("ordinary single behavior weakened", e)
	}
}

func TestFixedSourceApplyPairWrongInputAndSecondFailurePreserve(t *testing.T) {
	for _, kind := range []string{"proof", "intent", "durable-intent", "closed-writer", "second-before-create", "second-intent-journal", "second-identity-journal"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := newStore(t)
			in := fixedPairIntent()
			if kind == "intent" {
				in.Rules[0].Digest = digest("foreign")
			}
			tx, e := s.Begin(testContext, in)
			if e != nil {
				t.Fatal(e)
			}
			proof := digest("proof")
			if kind == "proof" {
				proof = digest("foreign")
			}
			if kind == "closed-writer" {
				s.lock.Close()
			}
			if kind == "durable-intent" {
				s.state.Stages[s.stageIndex(tx.id)].Intent.ConfigDigest = digest("foreign-durable")
			}
			boom := errors.New("second scope failure")
			calls := 0
			s.fail = func(point string) error {
				if kind == "second-before-create" && point == "directory-before-create" {
					calls++
					if calls == 2 {
						return boom
					}
				}
				if point == "journal-before-replace" && (kind == "second-intent-journal" || kind == "second-identity-journal") {
					calls++
					if kind == "second-intent-journal" && calls == 3 || kind == "second-identity-journal" && calls == 4 {
						return boom
					}
				}
				return nil
			}
			d, c, e := tx.ClaimFixedSourceApplyDirectories(testContext, proof)
			s.fail = nil
			if e == nil {
				t.Fatal("failure accepted")
			}
			if kind == "proof" || kind == "intent" || kind == "durable-intent" || kind == "closed-writer" {
				if d != nil || c != nil {
					t.Fatal("invalid input acquired scope")
				}
				return
			}
			if !errors.Is(e, boom) || d == nil || d.Tree() == nil || d.CheckLive(testContext) != nil {
				t.Fatal("first custody lost", d, e)
			}
			if kind == "second-intent-journal" {
				if c != nil {
					t.Fatal("uncommitted creation intent published")
				}
			} else if c == nil || c.Role() != "wimgapi-cache" {
				t.Fatal("partial second custody lost", c)
			}
			if kind == "second-identity-journal" && (c.Tree() == nil || c.CheckLive(testContext) == nil) {
				t.Fatal("partial identity accepted/lost")
			}
			if e = s.Close(); e == nil {
				t.Fatal("unresolved pair reported clean")
			}
		})
	}
}
