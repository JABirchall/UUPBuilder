package probes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// These descriptors/ports are explicitly synthetic; binding them never supplies
// native capability evidence or independently expected real image outputs.
func privateBindingsJSON(t *testing.T, c Case, cfg RuntimeConfig) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"schema_version": 1, "bindings": []any{map[string]any{
		"case_id": c.ID, "fixture_root": cfg.FixtureRoot, "workspace_parent": cfg.WorkspaceParent, "runtime": cfg,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRuntimeBindingsLoadExplicitPrivateRoots(t *testing.T) {
	for _, recipe := range []string{ExpandCompDBCABV1, ObserveWIMLZMSV1} {
		t.Run(recipe, func(t *testing.T) {
			c, cfg, _, _ := observationFixture(t)
			if recipe == ObserveWIMLZMSV1 {
				c, cfg, _, _ = wimObservationFixture(t)
			}
			got, err := LoadRuntimeBindings(bytes.NewReader(privateBindingsJSON(t, c, cfg)))
			if err != nil || !reflect.DeepEqual(got[c.ID], cfg) {
				t.Fatalf("private roots/typed recipe lost: %+v / %v", got, err)
			}
		})
	}
}

func TestRuntimeBindingsRejectInvalidPrivateDocuments(t *testing.T) {
	c, cfg, _, _ := observationFixture(t)
	valid := string(privateBindingsJSON(t, c, cfg))
	mutations := map[string]func(string) string{
		"unknown field":      func(s string) string { return strings.Replace(s, `"runtime":{`, `"runtime":{"command":"cmd.exe",`, 1) },
		"asserted readiness": func(s string) string { return strings.Replace(s, `"runtime":{`, `"runtime":{"ready":true,`, 1) },
		"excluded root in public runtime": func(s string) string {
			return strings.Replace(s, `"runtime":{`, `"runtime":{"fixture_root":"C:/fake",`, 1)
		},
		"duplicate key": func(s string) string {
			return strings.Replace(s, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
		},
		"ambiguous field spelling": func(s string) string { return strings.Replace(s, `"case_digest":`, `"Case_Digest":`, 1) },
		"unknown schema":           func(s string) string { return strings.Replace(s, `"schema_version":1`, `"schema_version":2`, 1) },
		"empty bindings":           func(string) string { return `{"schema_version":1,"bindings":[]}` },
		"trailing JSON":            func(s string) string { return s + `{}` },
		"malformed":                func(s string) string { return s[:len(s)-1] },
		"oversized":                func(s string) string { return s + strings.Repeat(" ", 1<<20) },
		"invalid UTF8":             func(s string) string { return s + string([]byte{0xff}) },
		"deep nesting":             func(string) string { return strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if got, err := LoadRuntimeBindings(strings.NewReader(mutate(valid))); err == nil || got != nil {
				t.Fatalf("invalid document accepted: %+v / %v", got, err)
			}
		})
	}
	for _, name := range []string{"empty id", "unsafe id", "bad digest", "relative root", "relative workspace", "unknown recipe", "duplicate artifact", "aliased input path", "traversal", "unknown component", "empty recipe identity"} {
		t.Run(name, func(t *testing.T) {
			c, cfg, _, _ := observationFixture(t)
			switch name {
			case "empty id":
				c.ID = ""
			case "unsafe id":
				c.ID = "case\nname"
			case "bad digest":
				cfg.CaseDigest = "not-a-hash"
			case "relative root":
				cfg.FixtureRoot = "relative"
			case "relative workspace":
				cfg.WorkspaceParent = "relative"
			case "unknown recipe":
				cfg.Recipe = "service-future-image-v1"
			case "duplicate artifact":
				cfg.Components[1].ID = cfg.Components[0].ID
			case "aliased input path":
				cfg.Inputs = append(cfg.Inputs, FileBinding{"another", "FIXTURE.cab"})
			case "traversal":
				cfg.Inputs[0].Path = "../fixture.cab"
			case "unknown component":
				cfg.Components[0].Path = "cmd.exe"
			case "empty recipe identity":
				cfg.Extraction.Identity.BuildID = ""
			}
			if got, err := LoadRuntimeBindings(bytes.NewReader(privateBindingsJSON(t, c, cfg))); err == nil || got != nil {
				t.Fatalf("invalid binding accepted: %+v / %v", got, err)
			}
		})
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(valid), &envelope); err != nil {
		t.Fatal(err)
	}
	entry := envelope["bindings"].([]any)[0]
	envelope["bindings"] = []any{entry, entry}
	duplicate, _ := json.Marshal(envelope)
	if got, err := LoadRuntimeBindings(bytes.NewReader(duplicate)); err == nil || got != nil {
		t.Fatalf("duplicate case accepted: %+v / %v", got, err)
	}
	var alias map[string]any
	entryBytes, _ := json.Marshal(entry)
	_ = json.Unmarshal(entryBytes, &alias)
	alias["case_id"] = strings.ToUpper(c.ID)
	envelope["bindings"] = []any{entry, alias}
	ambiguous, _ := json.Marshal(envelope)
	if got, err := LoadRuntimeBindings(bytes.NewReader(ambiguous)); err == nil || got != nil {
		t.Fatalf("case alias accepted: %+v / %v", got, err)
	}
}

type bindingsReadFailure struct{}

func (bindingsReadFailure) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestRuntimeBindingsPropagateReadFailure(t *testing.T) {
	if got, err := LoadRuntimeBindings(bindingsReadFailure{}); got != nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read error lost: %+v / %v", got, err)
	}
}

func TestProviderGateBindsExactFrozenCase(t *testing.T) {
	c, cfg, ports, calls := observationFixture(t)
	loaded, err := LoadRuntimeBindings(bytes.NewReader(privateBindingsJSON(t, c, cfg)))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := bindProviderRuntimes([]Case{c}, []Case{c}, loaded)
	if err != nil || bound[c.ID].CaseDigest != c.Digest() {
		t.Fatalf("exact frozen case not bound: %+v / %v", bound, err)
	}
	ctx := WithRuntime(context.Background(), bound[c.ID])
	snapshot := ctx.Value(runtimeKey{}).(RuntimeConfig)
	// Exercise the real runner with synthetic external ports. It must retain
	// the component-only limitation even after successful binding and extraction.
	e, err := executeRuntime(ctx, c, nil, snapshot, ports)
	if err == nil || *calls != 2 || e.Status != Unverified || ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
		t.Fatalf("binding promoted component evidence: %+v / %v", e, err)
	}
	altered := c
	altered.Source.BuildLabel = "altered-generation"
	if _, err := bindProviderRuntimes([]Case{altered}, []Case{altered}, loaded); err == nil {
		t.Fatal("altered frozen case accepted")
	}
}

func TestProviderGateRejectsBindingsBeforeAnyLaunch(t *testing.T) {
	for _, name := range []string{"missing", "unknown", "case digest", "altered selected case", "missing component", "missing expected output", "unimplemented generation", "duplicate frozen case", "ambiguous binding id", "missing dependency"} {
		t.Run(name, func(t *testing.T) {
			c, cfg, _, _ := observationFixture(t)
			cases, selected := []Case{c}, []Case{c}
			bindings := map[string]RuntimeConfig{c.ID: cfg}
			switch name {
			case "missing":
				delete(bindings, c.ID)
			case "unknown":
				bindings["unknown"] = cfg
			case "case digest":
				cfg.CaseDigest = unitHash
				bindings[c.ID] = cfg
			case "altered selected case":
				selected[0].Source.BuildLabel = "changed"
			case "missing component":
				cfg.Components = cfg.Components[:1]
				bindings[c.ID] = cfg
			case "missing expected output":
				cases[0].Expected = nil
				selected[0] = cases[0]
				cfg.CaseDigest = cases[0].Digest()
				bindings[c.ID] = cfg
			case "unimplemented generation":
				cfg.Recipe = "future-servicing-v1"
				bindings[c.ID] = cfg
			case "duplicate frozen case":
				cases = append(cases, c)
			case "ambiguous binding id":
				bindings[strings.ToUpper(c.ID)] = cfg
			case "missing dependency":
				cases[0].DependencyClosureComplete = true
				cases[0].Components[0].Dependencies = []string{"absent-runtime"}
				selected[0] = cases[0]
				cfg.CaseDigest = cases[0].Digest()
				bindings[c.ID] = cfg
			}
			if got, err := bindProviderRuntimes(cases, selected, bindings); err == nil || got != nil {
				t.Fatalf("bad gate binding accepted: %+v / %v", got, err)
			}
		})
	}
}

func TestProviderGateBoundCorruptFixtureCannotLaunch(t *testing.T) {
	c, cfg, ports, calls := observationFixture(t)
	loaded, err := LoadRuntimeBindings(bytes.NewReader(privateBindingsJSON(t, c, cfg)))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := bindProviderRuntimes([]Case{c}, []Case{c}, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.FixtureRoot, "fixture.cab"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := WithRuntime(context.Background(), bound[c.ID])
	e, err := executeRuntime(ctx, c, nil, ctx.Value(runtimeKey{}).(RuntimeConfig), ports)
	if err == nil || *calls != 0 || len(e.Invocations) != 0 || e.Status != Unverified {
		t.Fatalf("binding bypassed fixture custody: calls=%d evidence=%+v / %v", *calls, e, err)
	}
	if len(e.Blockers) == 0 || e.Blockers[len(e.Blockers)-1].Code != "fixture-verification-failed" {
		t.Fatalf("wrong refusal: %+v", e.Blockers)
	}
}

// This named regression preserves already-correct validator behavior. It is
// synthetic structural coverage, not a claim of real servicing inspection.
func TestServiceProofRequiresChangedImageAndInspection(t *testing.T) {
	for _, failure := range []string{"unchanged", "missing inspection", "missing configuration result"} {
		t.Run(failure, func(t *testing.T) {
			c, e := unitRecord()
			switch failure {
			case "unchanged":
				c.Expected[1].BeforeSHA256 = c.Expected[1].SHA256
			case "missing inspection":
				e.Verifications[1].Assertions = nil
			case "missing configuration result":
				c.Expected[1].Assertions = append(c.Expected[1].Assertions, "input-locale-en-GB-inspected")
			}
			e.CaseDigest = c.Digest()
			if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
				t.Fatal("false servicing proof accepted")
			}
		})
	}
}

func TestProviderProofRejectsUnprovenGeneration(t *testing.T) {
	file, err := os.Open("../../testdata/compatibility/required-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	f, err := LoadCases(file)
	if err != nil {
		t.Fatal(err)
	}
	// The checked-in P cases have no independently expected full outputs or
	// implemented full-operation recipe. A private binding cannot invent either.
	c := f.Cases[0]
	_, cfg, _, _ := observationFixture(t)
	cfg.CaseDigest = c.Digest()
	if got, err := bindProviderRuntimes(f.Cases, []Case{c}, map[string]RuntimeConfig{c.ID: cfg}); err == nil || got != nil {
		t.Fatalf("pending generation promoted: %+v / %v", got, err)
	}
}
