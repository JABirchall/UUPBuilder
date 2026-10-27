//go:build windows && providerproof

package probes

import (
	"context"
	"os"
	"testing"
)

// This explicitly requested real observation can pass its narrow byte/semantic
// checks while its returned Evidence remains unverified for Gate P/S. Missing
// roots/material/host/provider errors fail the test rather than skip them.
func TestProviderObservesCompDBExtraction(t *testing.T) {
	root, parent := os.Getenv("P1_OBSERVATION_ROOT"), os.Getenv("P1_OBSERVATION_WORKSPACE_PARENT")
	f, err := os.Open("../../testdata/compatibility/compdb-observation.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := LoadObservation(f, root, parent)
	if err != nil {
		t.Fatal(err)
	}
	e, runErr := RunCase(WithRuntime(context.Background(), d.Runtime), d.Case, nil)
	t.Logf("actual component observation: status=%s kind=%s invocations=%d outputs=%d verifications=%d retained=%s error=%v", e.Status, e.ExecutionKind, len(e.Invocations), len(e.Outputs), len(e.Verifications), e.RetainedWorkspace, runErr)
	if runErr == nil || e.Status != Unverified || e.ExecutionKind != "component-runtime" || len(e.Invocations) != 2 || len(e.Outputs) != 1 || len(e.Verifications) != 1 {
		t.Fatalf("real component observation incomplete: %+v / %v", e, runErr)
	}
	if e.Verifications[0].SHA256 != d.Case.Expected[0].SHA256 || e.Verifications[0].ObservedTarget != d.Case.Target {
		t.Fatal("real expected bytes/target not established")
	}
	if ValidateEvidence([]Case{d.Case}, []Evidence{e}) == nil {
		t.Fatal("metadata observation opened source/provider gate")
	}
}

func TestProviderObservesFoundationLZMS(t *testing.T) {
	f, err := os.Open("../../testdata/compatibility/foundation-observation.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := LoadObservation(f, os.Getenv("P1_OBSERVATION_ROOT"), os.Getenv("P1_OBSERVATION_WORKSPACE_PARENT"))
	if err != nil {
		t.Fatal(err)
	}
	e, runErr := RunCase(WithRuntime(context.Background(), d.Runtime), d.Case, nil)
	t.Logf("actual source observation: status=%s kind=%s nativeInvocations=%d processInvocations=%d outputs=%d verifications=%d retained=%s error=%v", e.Status, e.ExecutionKind, len(e.NativeInvocations), len(e.Invocations), len(e.Outputs), len(e.Verifications), e.RetainedWorkspace, runErr)
	if runErr == nil || e.Status != Unverified || e.ExecutionKind != "component-runtime" || len(e.NativeInvocations) != 1 || len(e.NativeInvocations[0].Calls) != 2 || len(e.Invocations) != 1 || len(e.Outputs) != 1 || len(e.Verifications) != 1 {
		t.Fatalf("actual source observation incomplete: %+v / %v", e, runErr)
	}
	if e.Verifications[0].SHA256 != d.Case.Expected[0].SHA256 || e.Verifications[0].ObservedTarget != d.Case.Target {
		t.Fatal("actual normalized package bytes/identity not established")
	}
	if ValidateEvidence([]Case{d.Case}, []Evidence{e}) == nil {
		t.Fatal("bounded source observation opened source/provider gate")
	}
}
