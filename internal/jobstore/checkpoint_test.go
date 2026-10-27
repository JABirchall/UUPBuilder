//go:build windows

package jobstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointIdentityStableAndBindsPredecessor(t *testing.T) {
	s, _ := newStore(t)
	first := commitStage(t, s, intent("base"), "same")
	second := commitStage(t, s, intent("base"), "same")
	if first.Digest != second.Digest {
		t.Fatal("random storage path changed semantic checkpoint identity")
	}
	if first.Outputs[0].Path == second.Outputs[0].Path {
		t.Fatal("new checkpoint reused writable storage")
	}
	in := intent("service")
	in.Predecessors = []PredecessorIdentity{{StageID: "base", Digest: first.Digest}}
	service1 := commitStage(t, s, in, "unchanged output")
	other := commitStage(t, s, intent("base"), "different base")
	in.Predecessors[0].Digest = other.Digest
	service2 := commitStage(t, s, in, "unchanged output")
	if service1.Digest == service2.Digest {
		t.Fatal("predecessor change reused checkpoint identity")
	}
}

func TestCheckpointRejectsFalseOutputsAndUndeclaredMutation(t *testing.T) {
	for _, kind := range []string{"size", "hash", "role", "undeclared", "traversal", "directory"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := newStore(t)
			tx, err := s.Begin(testContext, intent("base"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.OpenFile("../outside", os.O_CREATE|os.O_WRONLY, 0600); err == nil {
				t.Fatal("transaction exposed traversal")
			}
			if _, err := tx.OpenFile("not-declared", os.O_CREATE|os.O_WRONLY, 0600); err == nil {
				t.Fatal("transaction exposed undeclared mutation")
			}
			out := OutputIdentity{Path: "image.wim", Size: 4, SHA256: digest("data"), Role: "image"}
			if kind == "directory" {
				p, _ := tx.ScratchPath("image.wim")
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				out = writeOutput(t, tx, "image.wim", "data")
			}
			switch kind {
			case "size":
				out.Size++
			case "hash":
				out.SHA256 = digest("wrong")
			case "role":
				out.Role = ""
			case "undeclared":
				out.Path = "other.wim"
			case "traversal":
				out.Path = "../image.wim"
			}
			if err := tx.Commit(testContext, []OutputIdentity{out}); err == nil {
				t.Fatal("false or non-file output accepted")
			}
			r, err := s.InspectRecovery(testContext, "job")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Checkpoints) != 0 {
				t.Fatal("invalid output became reusable")
			}
		})
	}
}

func TestCheckpointCannotResolveOutputWithInvalidAncestry(t *testing.T) {
	s, _ := newStore(t)
	base := commitStage(t, s, intent("base"), "base")
	in := intent("service")
	in.Predecessors = []PredecessorIdentity{{StageID: "base", Digest: base.Digest}}
	child := commitStage(t, s, in, "child")
	if _, err := s.AbsoluteOutputPath(testContext, child.Outputs[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Identity().Path, filepath.FromSlash(base.Outputs[0].Path)), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AbsoluteOutputPath(testContext, child.Outputs[0]); err == nil {
		t.Fatal("output resolver reused checkpoint whose predecessor changed")
	}
}

func TestCheckpointPromotionRechecksAncestryAndCopiedBytes(t *testing.T) {
	for _, kind := range []string{"ancestor", "candidate"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := newStore(t)
			base := commitStage(t, s, intent("base"), "base")
			in := intent("service")
			in.Predecessors = []PredecessorIdentity{{StageID: "base", Digest: base.Digest}}
			child := commitStage(t, s, in, "child")
			in = intent("next")
			in.Predecessors = []PredecessorIdentity{{StageID: "service", Digest: child.Digest}}
			tx, err := s.Begin(testContext, in)
			if err != nil {
				t.Fatal(err)
			}
			out := writeOutput(t, tx, "image.wim", "next")
			s.fail = func(point string) error {
				if point == "promotion-after-copy" {
					path := base.Outputs[0].Path
					if kind == "candidate" {
						path = s.state.Stages[len(s.state.Stages)-1].Candidates[0].Path
					}
					if err := os.WriteFile(filepath.Join(s.Identity().Path, filepath.FromSlash(path)), []byte("changed during copy"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			if err := tx.Commit(testContext, []OutputIdentity{out}); err == nil {
				t.Fatal("promotion did not revalidate ancestry and copied output before publication")
			}
			s.fail = nil
			r, err := s.InspectRecovery(testContext, "job")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Checkpoints) != 2 {
				t.Fatal("invalid promotion became reusable")
			}
		})
	}
}
