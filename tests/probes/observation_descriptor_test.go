package probes

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestObservationDescriptorFreezesIdentityAndRejectsCommands(t *testing.T) {
	c, cfg, _, _ := observationFixture(t)
	encoded, err := json.Marshal(ObservationDescriptor{c, cfg})
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadObservation(bytes.NewReader(encoded), cfg.FixtureRoot, cfg.WorkspaceParent)
	if err != nil || got.Case.Digest() != c.Digest() || got.Runtime.FixtureRoot != cfg.FixtureRoot {
		t.Fatalf("descriptor=%+v err=%v", got, err)
	}
	for _, bad := range []string{strings.Replace(string(encoded), `"runtime":{`, `"runtime":{"commands":["cmd.exe"],`, 1), string(encoded) + "{}", strings.Repeat(" ", (1<<20)+1)} {
		if _, err := LoadObservation(strings.NewReader(bad), cfg.FixtureRoot, cfg.WorkspaceParent); err == nil {
			t.Fatal("command/unbounded/trailing descriptor accepted")
		}
	}
}

func TestObservationCheckedInDescriptorsRemainBoundAndPending(t *testing.T) {
	for _, name := range []string{"compdb-observation.json", "foundation-observation.json"} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile("../../testdata/compatibility/" + name)
			if err != nil {
				t.Fatal(err)
			}
			var d ObservationDescriptor
			if err := json.Unmarshal(b, &d); err != nil {
				t.Fatal(err)
			}
			if d.Runtime.CaseDigest != d.Case.Digest() {
				t.Fatalf("descriptor must bind exact Case.Digest: %s", d.Case.Digest())
			}
			if _, err := LoadObservation(bytes.NewReader(b), t.TempDir(), t.TempDir()); err != nil {
				t.Fatal(err)
			}
			if d.Case.ValidateReady() == nil {
				t.Fatal("metadata observation declared gate-ready")
			}
		})
	}
}
