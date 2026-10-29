package probes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"golang.org/x/sys/windows"
	"uupbuilder/internal/jobstore"
	platform "uupbuilder/internal/platform/windows"
)

type controlNative struct {
	r                          controlRequest
	sha                        string
	store                      *jobstore.Store
	w, provider, apply, bundle *platform.Workspace
	session                    *platform.SessionRunner
	locks                      []*os.File
	tx                         *jobstore.Transaction
	claim                      platform.OwnedMount
	paths                      controlPaths
	initial                    []controlMount
	baseline, after            controlObservation
	beforePin, afterPin        controlPin
	beforeLock                 *os.File
	afterLock                  *os.File
	observer                   controlObserver
	restoreEnv                 func() error
}

func openControl(ctx context.Context, request, sha string) (n *controlNative, err error) {
	f, err := controlReadLock(request, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 32<<10+1))
	if err != nil {
		return nil, err
	}
	r, err := decodeControl(b, sha)
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil || !sameControlPath(self, r.Runner) || !sameControlPath(request, filepath.Join(r.Bundle.Path, "request.json")) {
		return nil, errors.New("request/runner is outside sealed bundle")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil || !sameControlPath(r.Tool, filepath.Join(system, "dism.exe")) {
		return nil, errors.New("wrong actual native system tool path")
	}
	n = &controlNative{r: r, sha: sha}
	created := n
	defer func() {
		if err != nil {
			created.close()
		}
	}()
	for i, item := range []struct {
		id  platform.WorkspaceIdentity
		dst **platform.Workspace
	}{{r.Bundle, &n.bundle}, {r.Store, &n.w}, {r.Provider, &n.provider}, {r.Apply, &n.apply}} {
		*item.dst, err = platform.OpenWorkspace(item.id)
		if err != nil {
			return nil, err
		}
		// Keep role roots from being renamed/replaced while native argv is in
		// use. Child provider/apply directories are pinned below.
		lock, e := controlReadLock(item.id.Path, true)
		if e != nil {
			return nil, e
		}
		n.locks = append(n.locks, lock)
		got, e := controlDirectoryID(lock)
		if e != nil || got != r.ScopeIDs[i] {
			return nil, errors.Join(e, errors.New("sealed role directory identity changed"))
		}
	}
	for _, path := range []string{filepath.Join(n.provider.Path(), "tmp"), filepath.Join(n.provider.Path(), "logs"), filepath.Join(n.apply.Path(), "image")} {
		lock, e := controlReadLock(path, true)
		if e != nil {
			return nil, e
		}
		n.locks = append(n.locks, lock)
		if _, e = controlDirectoryID(lock); e != nil {
			return nil, e
		}
	}
	a, locks, err := measureControl(ctx, r)
	n.locks = append(n.locks, locks...)
	if err != nil {
		return nil, err
	}
	if err = validateControl(r, a, true); err != nil {
		return nil, err
	}
	n.restoreEnv, err = controlTemp(n.provider.Path())
	if err != nil {
		return nil, err
	}
	n.store, err = jobstore.Open(r.Store, nil)
	if err != nil {
		return nil, err
	}
	n.session, err = platform.NewSessionRunner(n.w)
	if err != nil {
		return nil, err
	}
	return n, nil
}
func (n *controlNative) close() error {
	var err error
	if n.session != nil {
		err = errors.Join(err, n.session.Close())
	}
	if n.beforeLock != nil {
		err = errors.Join(err, n.beforeLock.Close())
	}
	if n.afterLock != nil {
		err = errors.Join(err, n.afterLock.Close())
	}
	closeControlFiles(n.locks)
	for _, w := range []*platform.Workspace{n.w, n.provider, n.apply, n.bundle} {
		if w != nil {
			err = errors.Join(err, w.Close())
		}
	}
	if n.store != nil {
		err = errors.Join(err, n.store.Close())
	}
	if n.restoreEnv != nil {
		err = errors.Join(err, n.restoreEnv())
	}
	return err
}
func controlIntent(r controlRequest, sha string) jobstore.MutationIntent {
	return jobstore.MutationIntent{JobID: r.Store.JobID, PlanDigest: controlHash([]byte(controlProfile)), ConfigDigest: sha, StageID: "desktop-control", Inputs: []jobstore.NamedDigest{{Name: "apply-scope", Digest: controlHash([]byte(controlPath(r.Apply.Path)))}, {Name: "mct-media-input-esd-index9", Digest: controlSourceSHA}}, Tools: []jobstore.VersionedIdentity{{Name: "installed-dism", Version: r.Facts.Tool.Versions.NumericFileVersion, Digest: r.Facts.Tool.SHA256}, {Name: "private-runner", Version: "1", Digest: r.Facts.Runner.SHA256}}, Rules: []jobstore.VersionedIdentity{{Name: controlProfile, Version: "1", Digest: controlHash([]byte(controlProfile))}}, OwnedPaths: []string{"after.wim", "before.wim", "control.json", "working.wim"}}
}
func selectControlRecovery(r jobstore.RecoveryPlan, claims []platform.OwnedMount, request controlRequest, sha string) (string, platform.OwnedMount, error) {
	if len(r.Interrupted) != 1 || len(r.Checkpoints) != 0 || r.Discarded || len(claims) != 1 {
		return "", platform.OwnedMount{}, errors.New("ambiguous/noninterrupted control recovery")
	}
	st := r.Interrupted[0]
	if !reflect.DeepEqual(st.Intent, controlIntent(request, sha)) {
		return "", platform.OwnedMount{}, errors.New("interrupted intent differs from exact sealed control")
	}
	c := claims[0]
	if c.Workspace != request.Store || c.JobID != request.Store.JobID || c.OperationID != "desktop-control" || c.RelativePath != st.ScratchPath+"/mount" {
		return "", platform.OwnedMount{}, errors.New("no exact genuine durable control claim")
	}
	return st.ScratchPath, c, nil
}
func (n *controlNative) setPaths(scratch string, claim platform.OwnedMount) error {
	n.claim = claim
	if err := n.w.RestoreMount(claim); err != nil {
		return err
	}
	n.paths = controlPaths{Source: controlPath(n.r.Source), Before: filepath.Join(scratch, "before.wim"), Working: filepath.Join(scratch, "working.wim"), After: filepath.Join(scratch, "after.wim"), Mount: controlPath(filepath.Join(n.w.Path(), filepath.FromSlash(claim.RelativePath))), Apply: controlPath(filepath.Join(n.apply.Path(), "image")), Provider: controlPath(n.provider.Path())}
	_, err := controlPathBound(n.paths)
	return err
}
func (n *controlNative) command(ctx context.Context, op string) (string, error) {
	switch op {
	case "m0", "d0", "q0", "x0", "q1", "u0", "r0":
		if err := n.w.ValidateMount(n.claim); err != nil {
			return "", err
		}
	}
	args, err := controlArguments(op, n.paths)
	if err != nil {
		return "", err
	}
	// Sync the actual path/argv before each action, keeping recovery concrete.
	if err = controlJSON(n.provider, "next.json", map[string]any{"utc": time.Now().UTC(), "request_sha256": n.sha, "operation": op, "executable": n.r.Tool, "argv": args, "cancellation": "wait-for-exit"}, false); err != nil {
		return "", err
	}
	stopObservation := n.observer.observe(ctx, n.provider)
	result, err := n.session.Run(ctx, platform.Invocation{Executable: n.r.Tool, Arguments: args, Workspace: n.w, JobID: n.r.Store.JobID, OperationID: op, Cancellation: platform.CancelWait}, nil)
	err = errors.Join(err, stopObservation())
	writeErr := controlJSON(n.provider, "logs/"+op+"-result.json", map[string]any{"request_sha256": n.sha, "operation": op, "result": result, "error": publicDiagnosticNullable(err)}, false)
	if result.ExitCode != 0 || result.Cancelled {
		err = errors.Join(err, errors.New("native command failed/cancelled; output alone is not proof"))
	}
	out, encodingErr := normalizeControlOutput(result.Stdout)
	return out, errors.Join(err, writeErr, encodingErr)
}
func (n *controlNative) inventory(ctx context.Context) ([]controlMount, error) {
	s, e := n.command(ctx, "ri")
	if e != nil {
		return nil, e
	}
	return parseControlMounts(s)
}
func controlEmpty(w *platform.Workspace, path string) error {
	f, e := w.OpenFile(path, os.O_RDONLY, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	names, e := f.Readdirnames(1)
	if e != nil && !errors.Is(e, io.EOF) {
		return e
	}
	if len(names) != 0 {
		return errors.New("apply directory is not empty")
	}
	return nil
}
func (n *controlNative) receipt(state string) error {
	// Contains no private capability tokens. Actual WIM hashes are observed
	// only after their producing operation has completed.
	b, e := json.Marshal(map[string]any{"state": state, "profile": controlProfile, "request_sha256": n.sha, "paths": n.paths, "initial_mounts": n.initial, "baseline": n.baseline, "reapplied": n.after, "before": n.beforePin, "after": n.afterPin, "provider_acceptance": "unverified"})
	if e != nil {
		return e
	}
	f, e := n.tx.OpenFile("control.json", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	return errors.Join(e, f.Close())
}
func (n *controlNative) step(ctx context.Context, op string) error {
	if op == "p0" {
		if e := controlEmpty(n.apply, "image"); e != nil {
			return e
		}
	}
	s, err := n.command(ctx, op)
	if err != nil {
		return err
	}
	switch op {
	case "i0":
		n.initial, err = parseControlMounts(s)
		if err == nil {
			if err = controlScopesUnmounted(n.initial, []string{n.w.Path(), n.bundle.Path(), n.provider.Path(), n.apply.Path()}); err != nil {
				return err
			}
			err = controlJSON(n.provider, "initial.json", map[string]any{"request_sha256": n.sha, "mounts": n.initial}, true)
		}
	case "s0":
		err = assertControlImageInfo(s, 9)
	case "e0":
		n.beforeLock, err = controlReadLock(n.paths.Before, false)
		if err == nil {
			n.beforePin, err = controlPinFile(n.beforeLock, false, false)
		}
	case "b0":
		if err = assertControlImageInfo(s, 1); err != nil {
			return err
		}
		f, e := n.tx.OpenFile("working.wim", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		err = controlCopy(f, n.beforeLock)
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
		w, e := controlReadLock(n.paths.Working, false)
		if e != nil {
			return e
		}
		pin, e := controlPinFile(w, false, false)
		w.Close()
		if e != nil {
			return e
		}
		if !controlSameBytes(pin, n.beforePin) {
			return errors.New("working copy differs from immutable baseline")
		}
	case "m0":
		mounts, e := n.inventory(ctx)
		if e != nil {
			return e
		}
		if e = controlOwnedMount(mounts, n.paths); e != nil {
			return e
		}
		if e = controlUnrelated(n.initial, mounts, n.paths.Mount); e != nil {
			return e
		}
		n.baseline, err = inspectControlTree(n.w, n.claim.RelativePath)
		if err == nil {
			err = assertControlBaseline(n.baseline)
		}
	case "d0":
		f, e := controlFields(s)
		if e != nil {
			return e
		}
		if f["Current Edition"] != "Professional" {
			return errors.New("native actual edition conflicts with frozen identity")
		}
	case "q0":
		err = assertControlIntl(s, false)
	case "q1":
		err = assertControlIntl(s, true)
	case "u0":
		mounts, e := n.inventory(ctx)
		if e != nil {
			return e
		}
		for _, m := range mounts {
			if sameControlPath(m.Path, n.paths.Mount) {
				return errors.New("owned mount remains registered after commit")
			}
		}
		err = controlUnrelated(n.initial, mounts, n.paths.Mount)
	case "e1":
		f, e := controlReadLock(n.paths.After, false)
		if e != nil {
			return e
		}
		n.afterLock = f
		n.afterPin, err = controlPinFile(f, false, false)
		if err == nil && n.beforePin.SHA256 == n.afterPin.SHA256 {
			err = errors.New("servicing/export produced unchanged bytes")
		}
	case "a0":
		err = assertControlImageInfo(s, 1)
	case "p0":
		n.after, err = inspectControlTree(n.apply, "image")
		if err == nil {
			err = assertControlChange(n.baseline, n.after, n.beforePin, n.afterPin)
		}
	case "i1":
		mounts, e := parseControlMounts(s)
		if e != nil {
			return e
		}
		if e = controlUnrelated(n.initial, mounts, n.paths.Mount); e != nil {
			return e
		}
		for _, m := range mounts {
			if sameControlPath(m.Path, n.paths.Mount) {
				return errors.New("owned mount unexpectedly present")
			}
		}
	}
	if err != nil {
		return err
	}
	return n.receipt("observed-" + op)
}
func runPreparedControl(ctx context.Context, request, sha string) (err error) {
	n, err := openControl(ctx, request, sha)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, n.close()) }()
	recovery, err := n.store.InspectRecovery(ctx, n.r.Store.JobID)
	if err != nil {
		return err
	}
	if !recovery.CanResume || len(recovery.Interrupted) != 0 || len(recovery.Checkpoints) != 0 {
		return errors.New("request is not fresh; mutation resume is forbidden")
	}
	n.tx, err = n.store.Begin(ctx, controlIntent(n.r, sha))
	if err != nil {
		return err
	}
	path, err := n.tx.ScratchPath("control.json")
	if err != nil {
		return err
	}
	claim, err := n.tx.ClaimMount("mount")
	if err != nil {
		return err
	}
	if err = n.setPaths(controlPath(filepath.Dir(path)), claim); err != nil {
		return err
	}
	scratchLock, e := controlReadLock(filepath.Dir(path), true)
	if e != nil {
		return e
	}
	n.locks = append(n.locks, scratchLock)
	if err = n.receipt("intent-recorded-no-image-action"); err != nil {
		return err
	}
	if err = sequenceControl(ctx, n.step); err != nil {
		_ = n.receipt("failed-preserved-recovery-required")
		// Never infer cleanup authority from the failed operation's exit. An
		// exact owned discard is attempted only through the same recovery gate.
		cleanup := n.recoverOwned(context.Background(), true)
		return errors.Join(err, cleanup)
	}
	// Re-read source and immutable baseline through retained read-only handles.
	source, e := controlReadLock(n.r.Source, false)
	if e != nil {
		return e
	}
	sourcePin, e := controlPinFile(source, false, true)
	source.Close()
	if e != nil || sourcePin != n.r.Facts.Source {
		return errors.Join(e, errors.New("original source custody changed"))
	}
	bp, e := controlPinFile(n.beforeLock, false, false)
	if e != nil || bp != n.beforePin {
		return errors.Join(e, errors.New("immutable baseline changed"))
	}
	if err = n.receipt("control-observed-full-provider-gate-still-unverified"); err != nil {
		return err
	}
	var outputs []jobstore.OutputIdentity
	for _, name := range []string{"before.wim", "after.wim", "control.json"} {
		f, e := n.tx.OpenFile(name, os.O_RDONLY, 0)
		if e != nil {
			return e
		}
		p, e := controlPinFile(f, false, false)
		f.Close()
		if e != nil {
			return e
		}
		outputs = append(outputs, jobstore.OutputIdentity{Path: name, Size: p.Size, SHA256: p.SHA256, Role: "desktop-control"})
	}
	return n.tx.Commit(ctx, outputs)
}

func (n *controlNative) recoverOwned(ctx context.Context, discard bool) error {
	r, err := n.store.InspectRecovery(ctx, n.r.Store.JobID)
	if err != nil {
		return err
	}
	claims, err := n.store.OwnedMounts(ctx, n.r.Store.JobID)
	if err != nil {
		return err
	}
	scratch, claim, err := selectControlRecovery(r, claims, n.r, n.sha)
	if err != nil {
		return err
	}
	if err = n.w.RestoreMount(claim); err != nil {
		return err
	}
	if err = n.w.ValidateMount(claim); err != nil {
		return err
	}
	if err = n.setPaths(controlPath(filepath.Join(n.w.Path(), filepath.FromSlash(scratch))), claim); err != nil {
		return err
	}
	f, err := n.provider.OpenFile("initial.json", os.O_RDONLY, 0)
	if err != nil {
		return errors.New("initial native inventory missing; recovery preserves resources")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	f.Close()
	if err != nil || len(b) > 1<<20 {
		return errors.New("initial native inventory unreadable")
	}
	var initial struct {
		RequestSHA256 string         `json:"request_sha256"`
		Mounts        []controlMount `json:"mounts"`
	}
	if err = json.Unmarshal(b, &initial); err != nil || initial.RequestSHA256 != n.sha {
		return errors.New("initial inventory does not bind sealed request")
	}
	mounts, err := n.inventory(ctx)
	if err != nil {
		return err
	}
	if err = controlUnrelated(initial.Mounts, mounts, n.paths.Mount); err != nil {
		return err
	}
	found := false
	for _, m := range mounts {
		if sameControlPath(m.Path, n.paths.Mount) {
			found = true
		}
	}
	if !found {
		return controlJSON(n.provider, "recovery.json", map[string]any{"state": "owned-mount-not-registered-resources-retained", "request_sha256": n.sha, "paths": n.paths}, false)
	}
	if err = controlOwnedMount(mounts, n.paths); err != nil {
		return err
	}
	if err = controlJSON(n.provider, "recovery.json", map[string]any{"state": "exact-owned-mount-recovery-available", "request_sha256": n.sha, "paths": n.paths, "argv": mustControlRecoveryArguments(n.paths), "discard_requested": discard}, false); err != nil {
		return err
	}
	if !discard {
		return nil
	}
	if _, err = n.command(ctx, "r0"); err != nil {
		return err
	}
	after, err := n.inventory(ctx)
	if err != nil {
		return err
	}
	for _, m := range after {
		if sameControlPath(m.Path, n.paths.Mount) {
			return errors.New("owned mount remains after discard; preserve resources")
		}
	}
	return controlUnrelated(initial.Mounts, after, n.paths.Mount)
}
func mustControlRecoveryArguments(p controlPaths) []string {
	a, _ := controlArguments("r0", p)
	return a
}
func recoverPreparedControl(ctx context.Context, request, sha string, discard bool) (err error) {
	n, err := openControl(ctx, request, sha)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, n.close()) }()
	return n.recoverOwned(ctx, discard)
}
