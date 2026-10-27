package probes

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"uupbuilder/internal/model"
)

func wimObservationFixture(t *testing.T) (Case, RuntimeConfig, runtimePorts, *int) {
	c, cfg, p, calls := observationFixture(t)
	body, metadata, solid := syntheticWIM([]byte(syntheticPackage))
	if err := os.WriteFile(filepath.Join(cfg.FixtureRoot, "fixture.cab"), body, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha1.Sum(body)
	c.Inputs[0].Role = "payload"
	c.Inputs[0].Size = int64(len(body))
	c.Inputs[0].Digest = model.Digest{Algorithm: model.DigestSHA1, Value: hex.EncodeToString(h[:])}
	c.SourceFamily = "synthetic-wim-lzms-observation"
	c.Components = c.Components[1:]
	c.Algorithms = []string{"wim-v0xe00-lzms-solid"}
	c.Expected[0].SHA256 = syntheticPackageHash
	c.Expected[0].Algorithms = append([]string(nil), c.Algorithms...)
	cfg.CaseDigest = c.Digest()
	cfg.Components = cfg.Components[1:]
	cfg.Recipe = ObserveWIMLZMSV1
	cfg.Extraction = CompDBExtraction{}
	cfg.WIM = WIMExtraction{InputID: "cab", ExpectationID: "xml", CabinetID: "cabinet", CertutilID: "certutil", Member: "update.mum", Identity: PackageIdentity{"Synthetic-Foundation", "1.0.0.0", "arm64", "0123456789abcdef", "neutral"}}
	p.run = func(ctx context.Context, w proofWorkspace, req directRequest, emit model.Emit) (processResult, error) {
		*calls++
		want := []string{"-hashfile", filepath.Join(w.Path(), "outputs", "update.mum"), "SHA256"}
		if filepath.Base(req.Executable) != "certutil.exe" || !reflect.DeepEqual(req.Arguments, want) {
			return processResult{}, errors.New("wrong source recipe inspector argv")
		}
		return processResult{PID: 102, Stdout: syntheticPackageHash}, nil
	}
	decompress := syntheticLZMS(metadata, solid)
	p.decompress = func(ctx context.Context, path string, input []byte, size int) ([]byte, error) {
		if filepath.Base(path) != "cabinet.dll" {
			return nil, errors.New("wrong native provider binding")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 30*time.Second {
			return nil, errors.New("native probe deadline missing")
		}
		return decompress(ctx, input, size)
	}
	return c, cfg, p, calls
}

func TestRuntimeWIMBindsActualNativeCallsAndIndependentPackageInspection(t *testing.T) {
	c, cfg, p, calls := wimObservationFixture(t)
	e, err := executeRuntime(context.Background(), c, nil, cfg, p)
	if err == nil || e.Status != Unverified || e.ExecutionKind != "synthetic-runtime" || len(e.NativeInvocations) != 1 || len(e.Invocations) != 1 || len(e.Verifications) != 1 || len(e.Outputs) != 1 || *calls != 1 {
		t.Fatalf("source observation missing: %+v calls=%d err=%v", e, *calls, err)
	}
	native := e.NativeInvocations[0]
	if native.ID != "native-cabinet-lzms" || native.ComponentID != "cabinet" || len(native.Calls) != 2 || e.Outputs[0].ProducedBy != native.ID || native.Calls[1].OutputSHA256 == "" || native.Calls[0].Error != "" {
		t.Fatalf("actual native source custody incomplete: %+v", native)
	}
	if e.Verifications[0].SHA256 != syntheticPackageHash || e.Verifications[0].ObservedTarget != "arm64" || contains(e.Verifications[0].Assertions, "files-and-metadata-inspected") {
		t.Fatalf("package semantics fabricated or omitted: %+v", e.Verifications)
	}
	if ValidateEvidence([]Case{c}, []Evidence{e}) == nil {
		t.Fatal("synthetic/native source component observation opened gate")
	}
}

func TestRuntimeWIMRejectsPackageIdentityMismatchAfterRealParsing(t *testing.T) {
	c, cfg, p, _ := wimObservationFixture(t)
	cfg.WIM.Identity.Version = "9.9.9.9"
	e, err := executeRuntime(context.Background(), c, nil, cfg, p)
	if err == nil || e.Status != Failed || len(e.Verifications) != 0 || len(e.Outputs) != 1 {
		t.Fatalf("wrong package identity accepted: %+v err=%v", e, err)
	}
}
