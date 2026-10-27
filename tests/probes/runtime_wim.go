package probes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

type processInvoker func(string, Operation, string, []string, []string) (processResult, error)

func runWIMObservation(ctx context.Context, c Case, config RuntimeConfig, w proofWorkspace, ports runtimePorts, expected Expectation, inputPath, cabinetPath string, invoke processInvoker, e *Evidence, custody *[]RetainedArtifact) error {
	if ports.decompress == nil {
		return errors.New("fixed native LZMS decompression port unavailable")
	}
	file, err := w.OpenFile(inputPath, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(contextReader{ctx, file}, (1<<20)+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	if len(body) > 1<<20 {
		return errors.New("WIM source exceeds 1 MiB observation cap")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	native := NativeInvocation{ID: "native-cabinet-lzms", Operation: Extract, ComponentID: config.WIM.CabinetID, APIs: []string{"CreateDecompressor", "Decompress", "CloseDecompressor"}, StartedAt: time.Now().UTC()}
	decompress := func(ctx context.Context, input []byte, size int) ([]byte, error) {
		h := sha256.Sum256(input)
		call := NativeCall{InputSHA256: hex.EncodeToString(h[:]), InputBytes: len(input), ExpectedOutputBytes: size, StartedAt: time.Now().UTC()}
		out, err := ports.decompress(ctx, cabinetPath, input, size)
		call.FinishedAt = time.Now().UTC()
		call.OutputBytes = len(out)
		if len(out) > 0 {
			h := sha256.Sum256(out)
			call.OutputSHA256 = hex.EncodeToString(h[:])
		}
		call.Error = publicDiagnosticNullable(err)
		native.Calls = append(native.Calls, call)
		return out, err
	}
	observation, extractErr := extractObservedWIM(probeCtx, body, config.WIM.Member, decompress)
	outputPath := "outputs/update.mum"
	if extractErr == nil {
		extractErr = retainOutputBytes(w, outputPath, observation.Content)
	}
	native.FinishedAt = time.Now().UTC()
	if extractErr == nil {
		native.Algorithms = []string{"wim-v0xe00-lzms-solid"}
	}
	log, logErr := retainJSON(w, "logs/native-cabinet-lzms.json", "log-native-cabinet-lzms", "log", struct {
		Invocation  NativeInvocation `json:"invocation"`
		Observation WIMObservation   `json:"observation"`
		Error       string           `json:"error,omitempty"`
	}{native, observation, errorText(extractErr)})
	native.Log = log
	if logErr == nil {
		*custody = append(*custody, RetainedArtifact{log, "logs/native-cabinet-lzms.json", log.Digest.Value})
	}
	e.NativeInvocations = append(e.NativeInvocations, native)
	if err := errors.Join(extractErr, logErr); err != nil {
		return err
	}
	output, err := measureOutput(ctx, w, outputPath, expected.OutputID)
	if err != nil {
		return err
	}
	e.Outputs = append(e.Outputs, Output{output, native.ID})
	*custody = append(*custody, RetainedArtifact{output, outputPath, output.Digest.Value})
	if output.Digest.Value != expected.SHA256 || observation.ExpectedSHA256 != expected.SHA256 {
		return errors.New("actual/source-embedded/frozen expected normalized payload digests differ")
	}
	result, err := invoke("certutil", Inspect, config.WIM.CertutilID, []string{"-hashfile", filepath.Join(w.Path(), filepath.FromSlash(outputPath)), "SHA256"}, []string{"-hashfile", "$workspace/" + outputPath, "SHA256"})
	if err != nil {
		return err
	}
	independent, err := parseCertutilSHA256(result.Stdout)
	if err != nil {
		return err
	}
	file, err = w.OpenFile(outputPath, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	identity, inspectErr := inspectPackage(ctx, file)
	closeErr = file.Close()
	if err := errors.Join(inspectErr, closeErr); err != nil {
		return err
	}
	after, err := measureOutput(ctx, w, outputPath, expected.OutputID)
	if err != nil {
		return err
	}
	if identity != config.WIM.Identity || identity.Architecture != c.Target || after.Digest.Value != expected.SHA256 || independent != expected.SHA256 {
		return errors.New("independent normalized package bytes/identity differ from frozen expected result")
	}
	assertions := []string{"content-inspected", "package-target-identity-inspected", "source-explicit-sha256-inspected"}
	report, err := retainJSON(w, "reports/inspection.json", "inspection-report", "verification-report", struct {
		Output            Artifact        `json:"output"`
		Identity          PackageIdentity `json:"identity"`
		Observation       WIMObservation  `json:"source_observation"`
		IndependentSHA256 string          `json:"independent_sha256"`
		Assertions        []string        `json:"assertions"`
		Limits            string          `json:"limits"`
	}{output, identity, observation, independent, assertions, "Observed one bounded WIM0xe00 single-part/single-image/flat-metadata/single-solid LZMS variant. All WIM content SHA1 identities checked; selected member matches explicit embedded SHA256. No source signature validation, image-role/metadata preservation/servicing/media/full-family/full-host proof."})
	if err != nil {
		return err
	}
	e.Verifications = append(e.Verifications, Verification{ExpectationID: expected.ID, OutputID: expected.OutputID, InvocationID: "certutil", SHA256: independent, Assertions: assertions, ObservedTarget: identity.Architecture, Report: report})
	*custody = append(*custody, RetainedArtifact{report, "reports/inspection.json", report.Digest.Value})
	e.Blockers = append(e.Blockers, Blocker{"required-assertions-unverified", "Normalized package metadata observation does not establish full files/metadata/image-role extraction proof."})
	return nil
}

func retainOutputBytes(w proofWorkspace, path string, b []byte) error {
	f, err := w.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(b)
	syncErr := f.Sync()
	return errors.Join(writeErr, syncErr, f.Close())
}
func publicDiagnosticNullable(err error) string {
	if err == nil {
		return ""
	}
	return publicDiagnostic(err)
}
