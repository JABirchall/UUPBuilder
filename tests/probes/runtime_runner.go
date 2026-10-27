package probes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"uupbuilder/internal/model"
)

func (config RuntimeConfig) digest() string {
	b, _ := json.Marshal(config)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func validateRuntime(c Case, config RuntimeConfig) (Expectation, error) {
	if err := c.Validate(); err != nil {
		return Expectation{}, err
	}
	if err := c.Source.Validate(); err != nil {
		return Expectation{}, err
	}
	if config.CaseDigest != c.Digest() {
		return Expectation{}, errors.New("runtime case digest mismatch")
	}
	if !filepath.IsAbs(config.FixtureRoot) || !filepath.IsAbs(config.WorkspaceParent) {
		return Expectation{}, errors.New("explicit absolute fixture/workspace roots required")
	}
	var inputID, expectationID, member, producerID, inspectorID string
	requiredFiles := map[string]string{}
	inputCap := int64(4 << 20)
	switch config.Recipe {
	case ExpandCompDBCABV1:
		x := config.Extraction
		if config.WIM != (WIMExtraction{}) || x.Identity.Architecture != c.Target || textRequired("CompDB type", x.Identity.Type) != nil || textRequired("CompDB BuildID", x.Identity.BuildID) != nil || textRequired("CompDB OSVersion", x.Identity.OSVersion) != nil {
			return Expectation{}, errors.New("incomplete/misbound CompDB recipe identity")
		}
		inputID, expectationID, member, producerID, inspectorID = x.InputID, x.ExpectationID, x.Member, x.ExpandID, x.CertutilID
		requiredFiles[producerID] = "expand.exe"
		requiredFiles[inspectorID] = "certutil.exe"
	case ObserveWIMLZMSV1:
		x := config.WIM
		inputCap = 1 << 20
		if config.Extraction != (CompDBExtraction{}) || x.Member != "update.mum" || x.Identity.Architecture != c.Target {
			return Expectation{}, errors.New("unimplemented/misbound bounded WIM package recipe")
		}
		for _, value := range []string{x.Identity.Name, x.Identity.Version, x.Identity.PublicKeyToken, x.Identity.Language} {
			if err := textRequired("expected package identity", value); err != nil {
				return Expectation{}, err
			}
		}
		inputID, expectationID, member, producerID, inspectorID = x.InputID, x.ExpectationID, x.Member, x.CabinetID, x.CertutilID
		requiredFiles[producerID] = "cabinet.dll"
		requiredFiles[inspectorID] = "certutil.exe"
	default:
		return Expectation{}, errors.New("unsupported closed probe recipe")
	}
	if producerID == inspectorID {
		return Expectation{}, errors.New("producer and independent inspector identities must differ")
	}
	if len(c.Inputs) != 1 || c.Inputs[0].Size <= 0 || c.Inputs[0].Size > inputCap {
		return Expectation{}, errors.New("one source fixture within recipe input cap required")
	}
	if config.Recipe == ObserveWIMLZMSV1 && c.Inputs[0].Role != "payload" {
		return Expectation{}, errors.New("WIM observation requires actual payload fixture")
	}
	if _, err := model.ValidateRelativePath(member); err != nil {
		return Expectation{}, err
	}
	if strings.ContainsAny(member, "/\\") || (config.Recipe == ExpandCompDBCABV1 && !strings.EqualFold(filepath.Ext(member), ".xml")) {
		return Expectation{}, errors.New("one explicit closed recipe member required")
	}
	if len(c.Operations) != 1 || c.Operations[0] != Extract || len(c.Expected) != 1 || c.Expected[0].ID != expectationID || c.Expected[0].Operation != Extract {
		return Expectation{}, errors.New("recipe covers exactly one bounded extraction expectation")
	}
	if len(config.Inputs) != len(c.Inputs) || len(config.Components) != len(c.Components) {
		return Expectation{}, errors.New("complete artifact path bindings required")
	}
	seen := map[string]bool{}
	inputFound := false
	for _, binding := range config.Inputs {
		if _, err := model.ValidateRelativePath(binding.Path); err != nil {
			return Expectation{}, err
		}
		if seen[binding.ID] {
			return Expectation{}, errors.New("duplicate artifact binding")
		}
		seen[binding.ID] = true
		found := false
		for _, input := range c.Inputs {
			found = found || input.ID == binding.ID
		}
		if !found {
			return Expectation{}, errors.New("unknown input binding")
		}
		inputFound = inputFound || binding.ID == inputID
	}
	if !inputFound {
		return Expectation{}, errors.New("CAB input not bound")
	}
	files := map[string]string{}
	for _, binding := range config.Components {
		if seen[binding.ID] {
			return Expectation{}, errors.New("duplicate or colliding artifact binding")
		}
		seen[binding.ID] = true
		if !oneOf(binding.Path, "expand.exe", "certutil.exe", "cabinet.dll") {
			return Expectation{}, errors.New("only closed native system component names allowed")
		}
		for _, path := range files {
			if path == binding.Path {
				return Expectation{}, errors.New("duplicate native component file")
			}
		}
		found := false
		for _, component := range c.Components {
			if component.Artifact.ID == binding.ID {
				found = true
				if (strings.HasSuffix(binding.Path, ".exe") && component.Artifact.Role != "executable") || (strings.HasSuffix(binding.Path, ".dll") && component.Artifact.Role != "dll") {
					return Expectation{}, errors.New("system component role mismatch")
				}
			}
		}
		if !found {
			return Expectation{}, errors.New("unknown component binding")
		}
		files[binding.ID] = binding.Path
	}
	for id, name := range requiredFiles {
		if files[id] != name {
			return Expectation{}, errors.New("closed producer/inspector component binding mismatch")
		}
	}
	wantCount := 2
	if config.Recipe == ExpandCompDBCABV1 {
		wantCount = 3
	}
	if len(files) != wantCount {
		return Expectation{}, errors.New("closed native component set required")
	}
	return c.Expected[0], nil
}

func executeRuntime(ctx context.Context, c Case, emit model.Emit, config RuntimeConfig, ports runtimePorts) (e Evidence, runErr error) {
	// Copy the complete coordinator-owned DTO before any external callback.
	// JSON round-trip preserves future Case fields without sharing nested slices.
	frozen, _ := json.Marshal(c)
	var copied Case
	_ = json.Unmarshal(frozen, &copied)
	c = copied
	config.Inputs = append([]FileBinding(nil), config.Inputs...)
	config.Components = append([]FileBinding(nil), config.Components...)
	e = Evidence{CaseID: c.ID, CaseDigest: c.Digest(), RuntimeDigest: config.digest(), Status: Unverified, ExecutionKind: "not-executed", Blockers: append([]Blocker(nil), c.Pending...)}
	stop := func(code string, err error, failed bool) (Evidence, error) {
		e.Blockers = append(e.Blockers, Blocker{code, publicDiagnostic(err)})
		if failed {
			e.Status = Failed
		}
		return e, err
	}
	if ctx == nil {
		return stop("context-required", errors.New("context required"), false)
	}
	if err := ctx.Err(); err != nil {
		return stop("cancelled", err, false)
	}
	host, err := ports.observe()
	e.Host = host
	if err != nil {
		return stop("host-observation-unverified", err, false)
	}
	if host.OS != c.Host.OS || host.Host.NativeArchitecture != c.Host.NativeArchitecture || host.Host.ProcessArchitecture != c.Host.ProcessArchitecture || host.Host.WindowsBuild < c.Host.MinimumBuild {
		return stop("host-requirement-mismatch", errors.New("observed host does not satisfy exact native case"), false)
	}
	expected, err := validateRuntime(c, config)
	if err != nil {
		return stop("runtime-binding-invalid", err, false)
	}
	w, err := ports.createWorkspace(config.WorkspaceParent, c.ID)
	if err != nil {
		return stop("workspace-unverified", err, false)
	}
	e.RetainedWorkspace = w.Path()
	var custody []RetainedArtifact
	var locked []*os.File
	defer func() {
		for _, file := range locked {
			runErr = errors.Join(runErr, file.Close())
		}
		e.Blockers = deduplicateBlockers(e.Blockers)
		var owner any
		if ports.privateWorkspace != nil {
			owner = ports.privateWorkspace(w)
		}
		_, persistErr := retainJSON(w, "run.json", "run-record", "verification-report", struct {
			Schema    int                `json:"schema"`
			Case      Case               `json:"case"`
			Runtime   RuntimeConfig      `json:"runtime"`
			Evidence  Evidence           `json:"evidence"`
			Custody   []RetainedArtifact `json:"custody"`
			Workspace any                `json:"workspace,omitempty"`
			Error     string             `json:"error,omitempty"`
		}{1, c, config, e, custody, owner, errorText(runErr)})
		closeErr := w.Close()
		if finalErr := errors.Join(persistErr, closeErr); finalErr != nil {
			e.Status = Failed
			e.Blockers = append(e.Blockers, Blocker{"retention-failed", publicDiagnostic(finalErr)})
			runErr = errors.Join(runErr, finalErr)
		}
		if emit != nil {
			emit(model.Event{JobID: c.ID, StageID: "provider-proof", Kind: model.EventError, Message: "component observation retained; feasibility gates remain unverified", Timestamp: time.Now().UTC()})
		}
	}()
	fs, err := ports.fileSystem(w.Path())
	if err != nil {
		return stop("workspace-unverified", err, false)
	}
	e.Host.Host.FileSystem = fs
	if fs.Name != "NTFS" || !fs.Local {
		return stop("workspace-unverified", errors.New("local NTFS observation workspace required"), false)
	}
	for _, dir := range []string{"inputs", "components", "outputs", "logs", "reports"} {
		if err := w.MkdirAll(dir); err != nil {
			return stop("retention-failed", err, false)
		}
	}
	hostReport, err := retainJSON(w, "host.json", "host-report", "host-report", struct {
		OS        string     `json:"os"`
		Host      model.Host `json:"host"`
		Workspace string     `json:"workspace"`
	}{e.Host.OS, e.Host.Host, "fresh-owned-local-NTFS"})
	if err != nil {
		return stop("retention-failed", err, false)
	}
	e.Host.Report = hostReport
	custody = append(custody, RetainedArtifact{hostReport, "host.json", hostReport.Digest.Value})
	root, err := os.OpenRoot(config.FixtureRoot)
	if err != nil {
		return stop("fixture-unavailable", err, false)
	}
	defer root.Close()
	inputPaths := map[string]string{}
	for i, input := range c.Inputs {
		binding := ""
		for _, b := range config.Inputs {
			if b.ID == input.ID {
				binding = b.Path
			}
		}
		extension := ".cab"
		if config.Recipe == ObserveWIMLZMSV1 {
			extension = ".esd"
		}
		path := fmt.Sprintf("inputs/%d%s", i, extension)
		retained, err := retainFixture(ctx, root, w, binding, path, input)
		if err != nil {
			return stop("fixture-verification-failed", err, false)
		}
		custody = append(custody, retained)
		inputPaths[input.ID] = path
		e.Inputs = append(e.Inputs, input)
	}
	executables := map[string]string{}
	for _, component := range c.Components {
		name := ""
		for _, b := range config.Components {
			if b.ID == component.Artifact.ID {
				name = b.Path
			}
		}
		file, absolute, err := ports.openComponent(name, c.Host.NativeArchitecture)
		if err != nil {
			return stop("component-unverified", err, false)
		}
		locked = append(locked, file)
		retained, err := retainFile(ctx, file, w, "components/"+name, component.Artifact)
		if err != nil {
			return stop("component-verification-failed", err, false)
		}
		custody = append(custody, retained)
		e.Components = append(e.Components, component)
		executables[component.Artifact.ID] = absolute
	}
	e.ExecutionKind = ports.kind
	if ports.kind != "component-runtime" && ports.kind != "synthetic-runtime" {
		return stop("adapter-kind-invalid", errors.New("unknown probe execution kind"), false)
	}
	e.Blockers = append(e.Blockers, Blocker{"component-observation-only", "Bounded metadata extraction or payload/resource normalization observations do not establish complete source-family, Windows image servicing, dependency closure or bootable-media proof."})
	e.Blockers = append(e.Blockers, Blocker{"dependency-closure-unverified", "Static pinned system files do not establish the full loaded dependency closure."})
	x := config.Extraction
	// This pinned expand version preserves the staged basename for the single
	// selected member. The logical XML identity comes from bytes/inspection,
	// never from its physical .cab suffix. Do not search for arbitrary outputs.
	outputPath := "outputs/0.cab"
	invoke := func(id string, op Operation, component string, args, publicArgs []string) (processResult, error) {
		probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		started := time.Now().UTC()
		result, runErr := ports.run(probeCtx, w, directRequest{id, executables[component], args}, emit)
		finished := time.Now().UTC()
		log, logErr := retainJSON(w, "logs/"+id+".json", "log-"+id, "log", struct {
			Request directRequest `json:"request"`
			Result  processResult `json:"result"`
			Error   string        `json:"error,omitempty"`
		}{directRequest{id, executables[component], args}, result, errorText(runErr)})
		inv := Invocation{ID: id, Operation: op, ComponentID: component, Arguments: publicArgs, StartedAt: started, FinishedAt: finished, Log: log}
		if logErr == nil {
			custody = append(custody, RetainedArtifact{log, "logs/" + id + ".json", log.Digest.Value})
		}
		if result.PID != 0 {
			exit := int(result.Exit)
			inv.ExitCode = &exit
		}
		e.Invocations = append(e.Invocations, inv)
		if result.Cancelled && runErr == nil {
			runErr = context.Canceled
		}
		if result.Exit != 0 && runErr == nil {
			runErr = fmt.Errorf("process exited %d", result.Exit)
		}
		return result, errors.Join(runErr, logErr)
	}
	if config.Recipe == ObserveWIMLZMSV1 {
		if err := runWIMObservation(ctx, c, config, w, ports, expected, inputPaths[config.WIM.InputID], executables[config.WIM.CabinetID], invoke, &e, &custody); err != nil {
			return stop("source-observation-failed", err, !errors.Is(err, context.Canceled))
		}
		return e, errors.New("bounded source/algorithm observation complete; Gate P/S remain unverified")
	}
	cabFile, err := w.OpenFile(inputPaths[x.InputID], os.O_RDONLY, 0)
	if err != nil {
		return stop("cab-preflight-failed", err, false)
	}
	cabBytes, readErr := io.ReadAll(io.LimitReader(contextReader{ctx, cabFile}, (4<<20)+1))
	closeCabErr := cabFile.Close()
	if err := errors.Join(readErr, closeCabErr); err != nil {
		return stop("cab-preflight-failed", err, false)
	}
	if len(cabBytes) > 4<<20 {
		return stop("cab-preflight-failed", errors.New("CAB input exceeds 4 MiB observation cap"), false)
	}
	declaredSize, err := inspectCompDBCAB(cabBytes, x.Member)
	if err != nil {
		return stop("cab-preflight-failed", err, false)
	}
	// Legacy expand parses extended-prefix paths differently. Fixed relative
	// arguments resolve beneath W1's locked owned cwd; no namespace is stripped.
	_, err = invoke("expand", Extract, x.ExpandID, []string{filepath.FromSlash(inputPaths[x.InputID]), "-F:" + x.Member, "outputs"}, []string{"$workspace/" + inputPaths[x.InputID], "-F:" + x.Member, "$workspace/outputs"})
	if err != nil {
		return stop("producer-failed", err, !errors.Is(err, context.Canceled))
	}
	// Measure the actual output before invoking the separate byte inspector.
	output, err := measureOutput(ctx, w, outputPath, expected.OutputID)
	if err != nil {
		return stop("output-inspection-failed", err, true)
	}
	e.Outputs = append(e.Outputs, Output{output, "expand"})
	custody = append(custody, RetainedArtifact{output, outputPath, output.Digest.Value})
	if output.Size != int64(declaredSize) {
		return stop("output-size-mismatch", errors.New("actual extracted member differs from CAB-declared size"), true)
	}
	if !strings.EqualFold(output.Digest.Value, expected.SHA256) {
		return stop("output-digest-mismatch", errors.New("produced XML differs from independently frozen expected bytes"), true)
	}
	result, err := invoke("certutil", Inspect, x.CertutilID, []string{"-hashfile", filepath.Join(w.Path(), filepath.FromSlash(outputPath)), "SHA256"}, []string{"-hashfile", "$workspace/" + outputPath, "SHA256"})
	if err != nil {
		return stop("independent-inspector-failed", err, !errors.Is(err, context.Canceled))
	}
	independent, err := parseCertutilSHA256(result.Stdout)
	if err != nil {
		return stop("independent-inspection-invalid", err, true)
	}
	file, err := w.OpenFile(outputPath, os.O_RDONLY, 0)
	if err != nil {
		return stop("output-inspection-failed", err, true)
	}
	identity, inspectErr := inspectCompDB(ctx, file)
	closeErr := file.Close()
	if err := errors.Join(inspectErr, closeErr); err != nil {
		return stop("semantic-inspection-failed", err, !errors.Is(err, context.Canceled))
	}
	after, err := measureOutput(ctx, w, outputPath, expected.OutputID)
	if err != nil {
		return stop("output-inspection-failed", err, true)
	}
	if identity != x.Identity || identity.Architecture != c.Target || independent != expected.SHA256 || after.Digest.Value != output.Digest.Value {
		return stop("independent-result-mismatch", errors.New("independent digest/CompDB target/type/build identity differs from frozen expectation"), true)
	}
	assertions := []string{"content-inspected", "compdb-target-type-build-inspected"}
	report, err := retainJSON(w, "reports/inspection.json", "inspection-report", "verification-report", struct {
		Output            Artifact       `json:"output"`
		IndependentSHA256 string         `json:"independent_sha256"`
		Identity          CompDBIdentity `json:"identity"`
		Assertions        []string       `json:"assertions"`
		Limits            string         `json:"limits"`
	}{output, independent, identity, assertions, "Certutil establishes bytes only; Go inspected CompDB XML. No independent CAB decoder, payload/image/servicing/algorithm/dependency proof."})
	if err != nil {
		return stop("retention-failed", err, true)
	}
	e.Verifications = append(e.Verifications, Verification{ExpectationID: expected.ID, OutputID: expected.OutputID, InvocationID: "certutil", SHA256: independent, Assertions: assertions, ObservedTarget: identity.Architecture, Report: report})
	custody = append(custody, RetainedArtifact{report, "reports/inspection.json", report.Digest.Value})
	for _, assertion := range expected.Assertions {
		if !contains(assertions, assertion) {
			e.Blockers = append(e.Blockers, Blocker{"required-assertions-unverified", "Recipe did not establish all expected image extraction assertions."})
			break
		}
	}
	return e, errors.New("component observation complete; Gate P/S remain unverified")
}

func measureOutput(ctx context.Context, w proofWorkspace, path, id string) (Artifact, error) {
	f, err := w.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return Artifact{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Artifact{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return Artifact{}, errors.New("one regular XML output within 4 MiB required")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(contextReader{ctx, f}, (4<<20)+1))
	if err != nil {
		return Artifact{}, err
	}
	if n != info.Size() {
		return Artifact{}, errors.New("output size changed while inspecting")
	}
	return Artifact{id, "output", model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(h.Sum(nil))}, n, "owned-run:" + path}, nil
}

func retainJSON(w proofWorkspace, path, id, role string, value any) (Artifact, error) {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return Artifact{}, err
	}
	b = append(b, '\n')
	f, err := w.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return Artifact{}, err
	}
	_, writeErr := f.Write(b)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return Artifact{}, err
	}
	sum := sha256.Sum256(b)
	return Artifact{id, role, model.Digest{Algorithm: model.DigestSHA256, Value: hex.EncodeToString(sum[:])}, int64(len(b)), "owned-run:" + path}, nil
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Filesystem errors expose private absolute locators in their outer message.
// Public evidence records the native cause; full diagnostics stay in run logs.
func publicDiagnostic(err error) string {
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		return pathError.Op + ": " + pathError.Err.Error()
	}
	var linkError *os.LinkError
	if errors.As(err, &linkError) {
		return linkError.Op + ": " + linkError.Err.Error()
	}
	return err.Error()
}
func deduplicateBlockers(blockers []Blocker) []Blocker {
	seen := map[string]bool{}
	unique := make([]Blocker, 0, len(blockers))
	for _, b := range blockers {
		if !seen[b.Code] {
			unique = append(unique, b)
			seen[b.Code] = true
		}
	}
	return unique
}
