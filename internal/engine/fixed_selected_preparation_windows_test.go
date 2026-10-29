package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"uupbuilder/internal/jobstore"
	"uupbuilder/internal/model"
	platform "uupbuilder/internal/platform/windows"
)

const fixedPreparationPlan = `C:\Users\owner\.codex\worktrees\uup-workflow-task7\win11_builder\.superpowers\sdd\2026-10-29-uup-builder-user-workflow-plan`
const fixedPreparationSource = `C:\Users\owner\.codex\worktrees\uup-user-workflow\win11_builder\.superpowers\sdd\2026-10-29-uup-builder-user-workflow-plan`

// Compilation supplies the audited source HEAD. This descriptive field cannot
// create launch, source or operator authority; executable hash is measured live.
var fixedPreparationSourceHead string

type fixedSelectedPreparation struct {
	ctx              context.Context
	parent           *platform.PinnedWorkspace
	executable       *platform.PinnedExecutable
	token            platform.ProcessTokenIdentity
	volume           platform.StorageVolume
	footprint        fixedDiskFootprint
	evidence         *fixedPreparationEvidence
	recordErr        error
	approved         *fixedLiveApproval
	nativeStarted    bool
	operatorApproved bool
	childResult      *fixedChildResult
}

func (p *fixedSelectedPreparation) nativeAuthorized() bool {
	return p != nil && p.approved != nil && p.approved.connection != nil && p.approved.digest == preservationDigest(p.approved.scope) && p.approved.scope.validate() == nil
}
func (p *fixedSelectedPreparation) check() error {
	if p == nil || p.ctx == nil || p.parent == nil || p.executable == nil || p.evidence == nil {
		return ErrInput
	}
	if e := p.ctx.Err(); e != nil {
		return e
	}
	if p.recordErr != nil {
		return p.recordErr
	}
	if e := p.parent.Check(os.TempDir()); e != nil {
		return e
	}
	if e := p.executable.Verify(p.ctx); e != nil {
		return e
	}
	if e := platform.CheckProcessTokenIdentity(p.token); e != nil {
		return e
	}
	v, e := platform.InspectStorage(p.parent.Identity().Workspace.Path)
	if e != nil {
		return e
	}
	return p.footprint.CheckChanged(p.volume, v)
}
func (p *fixedSelectedPreparation) record(kind string, value any) {
	if p == nil || p.evidence == nil {
		return
	}
	p.recordErr = errors.Join(p.recordErr, p.evidence.Record(kind, value))
}

func (p *fixedSelectedPreparation) refuse(t *testing.T, phase string, e error) {
	t.Helper()
	if p.childResult != nil {
		p.recordErr = errors.Join(p.recordErr, recordFixedChildFailure(p.childResult, p.evidence, phase, e))
	}
	detail := "fixed scope refused"
	if e != nil {
		detail = e.Error()
	}
	if len(detail) > 4096 {
		detail = detail[:4096]
	}
	p.record("refusal", struct {
		Phase, Detail string
		Outcome       applyOperationOutcome
	}{phase, detail, applyOutcome(e)})
	t.Fatal(phase, detail)
}
func (p *fixedSelectedPreparation) closeResource(t *testing.T, phase string, close func() error) {
	t.Helper()
	e := close()
	p.record("resource-close", struct {
		Phase   string
		Outcome applyOperationOutcome
	}{phase, applyOutcome(e)})
	if e != nil {
		t.Error(phase, e)
	}
}
func (p *fixedSelectedPreparation) journal(id platform.WorkspaceIdentity) {
	r, e := os.OpenRoot(id.Path)
	if e != nil {
		p.recordErr = errors.Join(p.recordErr, e)
		return
	}
	defer r.Close()
	f, e := r.Open("journal.json")
	if e != nil {
		p.recordErr = errors.Join(p.recordErr, e)
		return
	}
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	e = errors.Join(e, f.Close())
	if len(b) > 1<<20 || !json.Valid(b) {
		e = errors.Join(e, ErrLimit)
	}
	if e != nil {
		p.recordErr = errors.Join(p.recordErr, e)
		return
	}
	p.record("durable-journal", json.RawMessage(b))
}

type fixedTrialClaimEvidence struct {
	Returned, TreeCreated            bool
	Role, SourceDigest, IntentDigest string
	Tree                             platform.TreeIdentity
}

func fixedClaimEvidence(c *jobstore.DirectoryClaim) fixedTrialClaimEvidence {
	if c == nil {
		return fixedTrialClaimEvidence{}
	}
	v := fixedTrialClaimEvidence{Returned: true, Role: c.Role(), SourceDigest: c.SourceDigest(), IntentDigest: c.IntentDigest()}
	if c.Tree() != nil {
		v.TreeCreated = true
		v.Tree = c.Tree().Identity()
	}
	return v
}

// This entry has no elevation/native dispatch. It may only be run under a later
// separately scoped preparation approval. The ordinary test suite skips it.
func TestConfiguredFixedSelectedSourcePrepare(t *testing.T) {
	if os.Getenv("UUP_FIXED_SELECTED_PREPARE") != "fixed-selected-preparation-only" {
		t.Skip("NOT RUN: selected-source preparation requires separate scope")
	}
	if flag.Lookup("test.run").Value.String() != "^TestConfiguredFixedSelectedSourcePrepare$" || flag.Lookup("test.count").Value.String() != "1" || flag.Lookup("test.timeout").Value.String() != "0s" {
		t.Fatal("preparation must run alone, count 1, with no forced Go test timeout")
	}
	if !strings.EqualFold(filepath.Clean(os.Getenv("UUP_FIXED_SELECTED_SOURCE_ROOT")), filepath.Clean(fixedPreparationSource)) {
		t.Fatal("exact audited source locator root required")
	}
	if len(fixedPreparationSourceHead) != 40 {
		t.Fatal("compile-time source HEAD required")
	}
	if b, e := hex.DecodeString(fixedPreparationSourceHead); e != nil || len(b) != 20 {
		t.Fatal("canonical source HEAD required")
	}
	// The descriptor is metadata only. Full original identity/bytes and every
	// live producer still must be rebuilt, under the exact frozen checks below.
	sourceBytes, locatorHash, e := fixedSelectedLocatorCost(fixedPreparationSource)
	if e != nil {
		t.Fatal(e)
	}
	footprint, e := fixedPreparationFootprint(sourceBytes)
	if e != nil {
		t.Fatal(e)
	}
	volume, e := platform.InspectStorage(fixedPreparationPlan)
	if e != nil {
		t.Fatal(e)
	}
	if !volume.Capabilities.Local || !strings.EqualFold(volume.Capabilities.Name, "NTFS") {
		t.Fatal("local NTFS plan parent required")
	}
	if e = footprint.Check(volume); e != nil {
		t.Fatal("combined preflight refused before private scope/producer mutation", e)
	}
	w, e := platform.CreateWorkspace(fixedPreparationPlan, "fixed-selected-preparation")
	if w != nil {
		t.Logf("PRIVATE freshly owned preparation scope %s; retained, no recursive cleanup", w.Path())
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := w.Close(); e != nil {
			t.Error(e)
		}
	})
	pin, e := platform.PinFreshWorkspace(w)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := pin.Close(); e != nil {
			t.Error(e)
		}
	})
	sink, e := newFixedPreparationEvidence(pin, fixedEvidenceQuota)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := sink.Close(); e != nil {
			t.Error(e)
		}
	})
	p := &fixedSelectedPreparation{parent: pin, evidence: sink, volume: volume, footprint: footprint}
	// Register first so source t.Cleanup closures run before final durability.
	t.Cleanup(func() {
		v := struct {
			Failed                          bool
			NativeAuthorized, NativeInvoked bool
			Events                          applyOperationOutcome
			Parent                          platform.PreparationParentIdentity
			Retention                       string
		}{t.Failed(), p.operatorApproved, p.nativeStarted, applyOutcome(p.recordErr), pin.Identity(), "private evidence/root retained; any child records its own producer/native/claim closure and retained outcomes; no cleanup acceptance"}
		if e := sink.Final(v); e != nil {
			t.Error("final durable evidence", e)
		}
		if e := sink.Close(); e != nil {
			t.Error("durable evidence close", e)
		}
	})
	p.record("early", struct {
		SourceHead, Manifest, LocatorSHA256, SourceRoot, ProviderPolicy, PrivilegePolicy, Ancillary string
		Source                                                                                      model.SourceIdentity
		Footprint                                                                                   fixedDiskFootprint
		Volume                                                                                      platform.StorageVolume
		Parent                                                                                      platform.PreparationParentIdentity
	}{fixedPreparationSourceHead, "675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9", locatorHash, fixedPreparationSource, "installed wimgapi.dll; fixed 0x182; image 1", platform.ImagePreservationPrivilegeProfile, "DISM null log/scratch use OS-selected system-volume locations; conservative reserve, no physical quota", model.SourceIdentity{UpdateID: "3d12aa3e-806a-46c9-900e-bf7613959273", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}, footprint, volume, pin.Identity()})
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	p.executable, e = platform.OpenPinnedExecutable(context.Background(), exe)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		p.record("executable-close", applyOutcome(errors.Join(p.executable.Verify(context.Background()), p.executable.Close())))
	})
	p.record("executable", p.executable.Identity())
	p.token, e = platform.CurrentProcessTokenIdentity()
	if e != nil {
		t.Fatal(e)
	}
	p.record("process-token", p.token)
	privilege, e := platform.ObserveImagePreservationPrivileges(context.Background())
	p.record("privilege-query", struct {
		Observation platform.PrivilegeObservation
		Outcome     applyOperationOutcome
	}{privilege, applyOutcome(e)})
	if e != nil {
		t.Fatal(e)
	}
	// This process runs only this entry. Both variables are restored after all
	// producer closes; the original data worktree is never a scratch parent.
	t.Setenv("TEMP", w.Path())
	t.Setenv("TMP", w.Path())
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	t.Cleanup(stop)
	p.ctx, stop, e = fixedPreparationContext(signalCtx, time.Now().Add(2*time.Hour), nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(stop)
	if e = p.check(); e != nil {
		t.Fatal(e)
	}
	scope, e := newFixedApprovedScope(p, locatorHash)
	if e != nil {
		t.Fatal(e)
	}
	p.record("prepared-dossier", scope)
	if p.recordErr != nil {
		t.Fatal(p.recordErr)
	}
	t.Logf("PRIVATE prepared dossier scope=%s evidence=%s; WIM/live proof/future child token NOT prepared", preservationDigest(scope), w.Path())
	if !*fixedAwaitConsent {
		return
	}
	if e = runFixedApprovedParent(p, scope); e != nil {
		t.Fatal(e)
	}
}

func fixedSelectedLocatorCost(root string) (uint64, string, error) {
	r, e := os.OpenRoot(root)
	if e != nil {
		return 0, "", e
	}
	defer r.Close()
	f, e := r.Open("actual-preparation/prepared-source.json")
	if e != nil {
		return 0, "", e
	}
	b, e := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	e = errors.Join(e, f.Close())
	if e != nil || len(b) > 4<<20 {
		return 0, "", errors.Join(e, ErrLimit)
	}
	var input struct {
		Manifest model.PayloadManifest
		Files    []struct{ Identity model.PayloadIdentity }
	}
	if e = json.Unmarshal(b, &input); e != nil {
		return 0, "", e
	}
	if len(input.Files) > 1024 || input.Manifest.Digest != "675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9" || input.Manifest.Source != (model.SourceIdentity{UpdateID: "3d12aa3e-806a-46c9-900e-bf7613959273", BuildLabel: "19045.7811", Architecture: "x86", Language: "en-us"}) {
		return 0, "", ErrInput
	}
	var size uint64
	wims, cabs := 0, 0
	for _, f := range input.Files {
		name := strings.ToLower(f.Identity.Provenance.Name)
		selected := false
		if strings.HasSuffix(name, ".esd") {
			wims++
			selected = true
		} else if strings.HasSuffix(name, ".cab") && !strings.HasPrefix(name, "ssu-") && !strings.HasPrefix(name, "windows10.0-") {
			cabs++
			selected = true
		}
		if !selected {
			continue
		}
		if f.Identity.Size <= 0 {
			return 0, "", ErrInput
		}
		size, e = checkedPreparationSum(size, uint64(f.Identity.Size))
		if e != nil {
			return 0, "", e
		}
	}
	if wims != 13 || cabs != 22 || size != 2288011348 {
		return 0, "", ErrInput
	}
	h := sha256.Sum256(b)
	return size, hex.EncodeToString(h[:]), nil
}
