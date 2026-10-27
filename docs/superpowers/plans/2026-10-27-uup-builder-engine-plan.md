# UUP Builder Windows and Conversion Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Go-owned UUP reconstruction, imaging, servicing, recovery, and verified media creation across all required hosts and targets.

**Architecture:** Prove provider capabilities and source algorithms first, then build small native adapters and transactional stages. The immutable planner chooses operations; the constrained worker executes them; independent verification authorizes publication.

**Tech Stack:** Go, Windows API bindings, direct native helper invocation, pinned vendor distributions, WIM/ESD/CAB/PSF/CIX metadata, DISM providers and UDF/El Torito tooling.

**Spec:** [Accepted design](../specs/2026-10-27-uup-builder-design.md); [master contracts, settings and schedule](2026-10-27-uup-builder-multi-agent-plan.md).

**Authoritative host-proof amendment (2026-10-27):** The user accepts successful complete functionality on the available native Windows host plus Windows `386`/`amd64`/`arm64` builds as full host-architecture coverage. The [host proof policy](../../engineering/host-proof-policy.md) supersedes earlier mandatory physical-host execution clauses throughout P1/W1/W2 and the R1 handoff. Other physical host runs are optional corroboration. Keep all nine logical common pairs, actual measured host identities and separate observed/portability-accepted reporting. All functional source/target/provider/servicing/media/dependency/rights/setup checks remain required.

## Global Constraints

- Implement the conversion pipeline in Go and call individual tools directly. Do not use an upstream conversion script as the engine.
- Run on Windows 10 and later, supporting the x86 and Arm architecture families.
- Allow every build target on every supported host. Do not restrict available targets to a smaller host/target compatibility matrix.
- All remaining master constraints, ownership, `gpt-6.1-sol`/`xhigh`, and fresh-review gates apply.

## Review Focus

- A successful process exit does not prove correct images or boot media: E3–E6 independently inspect results.
- Power loss during mutation/publication cannot corrupt a committed checkpoint: J1/J2/E6 validate and recover owned data.
- A 32-bit executable on x64 Windows is not evidence for a genuine 32-bit host: P1/R1 record native host architecture and OS.
- A helper extracted successfully may still lack required DLLs/drivers/licenses or foreign-image servicing: P1/W2 prove the entire chain.
- Same-looking filenames/metadata indices do not establish image roles or compatible delta bases: M1/E1 require actual metadata and content identity.

---

## Task P1: concrete provider and source-family proof harness

**Owner:** Platform, with a separate source-census worker if a slot is available. **Depends:** G0. This is internal test infrastructure, not a new public CLI.

**Files:** Create `tests/probes/{cases,evidence,provider_windows_test,source_census_test}.go`, `testdata/compatibility/required-cases.json`, and `docs/feasibility/{toolchains,source-formats}.md`. Coordinator owns the shared case descriptor when R1 extends it.

**Interfaces:** `RunCase(ctx context.Context, c Case, emit model.Emit) (Evidence, error)`; strict `ValidateEvidence(required []Case, evidence []Evidence) error`; `ValidateArchitectureCoverage(required []Case, observed []Evidence) ([]ArchitectureCoverage, error)`. `Case` fixes actual host OS/native architecture, target, source family, operation, source/tool digests and expected verification; `Evidence` records execution/output/verification, provenance and one of passed/failed/unverified. Coverage records identify the required logical pair and actual witness with observed versus portability-accepted basis.

- [ ] Write `TestRequiredHostTargetCases` asserting all `3*3` common pairs; `TestEvidenceRejectsCrossCompileOnly`; `TestEvidenceRejectsWOW64AsNativeX86Host`; `TestEvidenceRejectsMissingDependencies`; `TestSourceCensusSeparatesUnavailableFromUnimplemented`. A missing matrix entry, fake execution, or unknown result must return an error.
- [ ] Run `go test ./tests/probes -run 'Test(Required|Evidence|SourceCensus)' -count=1`; expect relevant failing assertions before the evidence validator exists.
- [ ] Implement the harness and source census. Record exact official acquisition routes, rights/notices, full executable/DLL/driver chain, prerequisites/restart behavior, host/target constraints and tool/source digests. Probe actual extraction, foreign-architecture modification/servicing, reconstruction and ISO mastering for every required target on the available native Windows host. Inventory canonical/reference/express/PSF/CIX/encrypted/update generations from real source metadata, with expected fixture hashes and algorithms. Do not infer support from a download page, generic MSDelta API, WIM export, or a cross-build alone. Keep valid-but-unimplemented formats visible in the census.
- [ ] Run the focused unit command and tagged real probes with `go test -tags=providerproof ./tests/probes -run TestProviderPerformsCrossArchitectureServicing -count=1` on the available native host, plus all three Windows builds. Expected proof is a real modified image with independently inspected results and matching provenance; coverage of other logical hosts is portability-accepted, not unobserved execution. A missing functional source/provider/output remains unverified; unavailable other-host hardware is no longer a blocker. Gate P must pass before real mutation tasks; Gate S adds specific per-family algorithm evidence before that family can become buildable.
- [ ] Obtain both reviews and commit the harness/descriptors as `test: establish real toolchain and source-format feasibility gates`. Report concrete failed requirements without narrowing scope. Independent data/UI work may continue; broad conversion implementation cannot bury unresolved provider blockers.

## Task P1p: single-host architecture acceptance

**Owner:** Platform. **Depends:** accepted bounded P1 contracts and the user's host-proof amendment. This changes architecture acceptance without completing P1 functional proof.

**Files:** `tests/probes/architecture_coverage{,_test}.go`, current-host tagged gate selection, source-family acceptance delegation, authoritative host proof policy and focused related design/master/engine wording.

- [ ] Use TDD for complete one-host/all-target acceptance, truthful required/witness bases, strict misbound/incomplete record rejection and rejection of mixed incomplete measured hosts.
- [ ] Keep `ValidateEvidence` strict. Require every actual witness to be proof-ready, match functional counterparts exactly, and waive only the existing explicit host-only pending code for counterparts. Do not fabricate evidence, add readiness flags or infer unrelated source/target proof.
- [ ] Run focused probes, probe vet, the full ordinary suite and Windows 386/amd64/arm64 builds; preserve remaining full P1 failures. Obtain separate fresh specification and quality reviews of the checkpoint.

## Task W1: host detection, filesystem/proxy adapters and direct process runner

**Owner:** Platform. **Depends:** G0; independent of D1/D2 and P1's lengthy real-host runs.

**Files:** Create `internal/platform/windows/{host,filesystem,proxy,process,jobobject,elevation,pipe}_windows.go`, matching tests and package-level interfaces in `types.go`. This package imports no download/tools/planner/jobs packages.

**Interfaces:** `DetectHost(ctx context.Context) (model.Host, error)`; `(*ProxyResolver).Resolve(ctx context.Context, target *url.URL) (*url.URL, error)`; `(*Runner).Run(ctx context.Context, inv Invocation, emit model.Emit) (RunResult, error)`; `StartElevated(ctx context.Context, descriptor WorkerDescriptor) (WorkerConnection, error)`. `Invocation` is an absolute executable, argument slice, owned working directory, operation/job identity and declared cancellation policy; pipe/elevation DTOs contain no arbitrary command text.

- [ ] Write `TestDetectHostDistinguishesProcessAndNativeArchitecture`; `TestSystemProxyResolvesManualAndAutomaticConfiguration`; `TestInvocationPreservesUnicodeAndSpaceArguments`; `TestCancellationTouchesOnlyOwnedProcessTree`; `TestWorkspaceRejectsEscapingReparsePoint`; `TestPipeRejectsUnauthorizedPeer`; assert separate native/process arch, URL-specific native proxy decisions, exact argv, preserved unrelated processes/paths and rejected peers.
- [ ] Run `go test ./internal/platform/windows -count=1`; expect relevant contract failures using injected OS ports where real elevation is inappropriate for unit tests.
- [ ] Implement Windows 10+ host/filesystem detection, native system proxy/PAC resolution, direct absolute executable launch with hidden supporting consoles, owned process/job tracking, safe path/mount ownership primitives, access-restricted pipes and normal same-executable elevation. Read official API contracts for each architecture; never use environment-only proxy lookup for system mode or shell-built commands. Native worker operation validation is implemented in J2.
- [ ] Run the focused command and complete tagged Windows process/proxy/pipe checks on the available native host; expect exact argument/identity behavior and unrelated resources unchanged. Cross-build all three Windows host architectures. Together these satisfy host-architecture acceptance under the host proof policy, with actual observations and portability-accepted coverage reported separately.
- [ ] Obtain both reviews and commit as `feat: add Windows host proxy and constrained process adapters`.

## Task W2: verified pinned tool acquisition and provider selection

**Owner:** Platform. **Depends:** W1, D4 and P1 provider definitions; missing P1 proof remains a real mutation/release blocker.

**Files:** Create `internal/tools/{manifest,selection,acquisition,verification,manager}.go`, `internal/tools/manifests/v1.json`, matching tests and `docs/feasibility/acquisition.md`.

**Interfaces:** Produces master `Manager.Ensure`. `Requirement` fixes host, target, operations and provider manifest digest; `Toolchain` returns verified paths/versions/digests and supported operations. Consumes injected `FetchOne` port and W1 runner; source/master plans never import tool binary paths from the TUI.

- [ ] Write `TestEnsureRejectsDigestMismatch`; `TestEnsureVerifiesCompanionDLLs`; `TestSelectionUsesNativeHostAndTargetCapabilities`; `TestProviderVersionsCoexist`; `TestUnknownTargetIsNotHidden`; `TestAcquisitionNeverRequiresManualADK`; assert invalid files are never executed, complete dependencies are required, providers are isolated, and missing capability is an explicit blocker rather than a filtered target.
- [ ] Run `go test ./internal/tools -count=1`; expect relevant failures.
- [ ] Implement signed/trusted-source manifest validation, SHA-256 checks, safe extraction, versioned directories, compatible provider selection and necessary application-managed prerequisites. Prefer adequate existing DISM only after validating it. Choose concrete vendor routes proven by P1; no moving latest URLs, host DISM overwrite, full converter fallback or undocumented redistribution assumption. Record all notices and installations accurately.
- [ ] Run the focused command, then the complete tagged clean-machine acquisition probe on the available native host and all three Windows builds. Apply the host proof policy for other-host architecture coverage. Expect the pinned complete provider ready for every required target/operation, with no manual setup and no unsigned/unchecked substitution; rights/dependency/setup checks remain required.
- [ ] Obtain both reviews and commit as `feat: provision pinned native imaging toolchains`.

## Task M1: semantic source inventory and app metadata

**Owner:** Engine. **Depends:** W2 and G0; consumes fixture manifests/materialized paths and does not import `internal/source`.

**Files:** Create `internal/metadata/{inventory,composition,packages,wim,roles,sourcefamily,apps}.go`, matching tests and sanitized `internal/metadata/testdata/`.

**Interfaces:** Produces master `Inspect`, `InspectRequest`, `Inventory`, and `AppInventory`. Requests contain source identity, verified local paths and inspection providers. Inventory exposes semantic setup/OS/WinRE/image roles, architecture/language/build properties, resource references, package dependencies, app families/frameworks/licenses, customization phase and detected layout/classification.

- [ ] Write `TestRolesDoNotDependOnFilenameOrIndex`; `TestConflictingArchitectureMetadataFails`; `TestUpdateOnlyRetainsDownloadability`; `TestMissingSetupIsSourceUnavailable`; `TestUnknownLayoutIsImplementationGap`; `TestAppInventoryUsesFamiliesDependenciesAndLicenses`; assert semantic role selection under permuted names/indices, contradictory metadata rejection, and distinct unavailable/unimplemented results.
- [ ] Run `go test ./internal/metadata -count=1`; expect relevant failures.
- [ ] Implement format-specific parsers for P1's real metadata corpus with bounded parsing/decompression and provenance. Preserve original metadata references. Determine derived edition bases and app customization phase from actual source data/rules; do not invent families from file names or make three core app names universally mandatory. Expose unknown target values intact.
- [ ] Run the focused command and real small-metadata inspection against each censused family; expect correct roles and graph identities, not merely successful XML/JSON decoding.
- [ ] Obtain both reviews and commit as `feat: inspect semantic UUP source and app inventories`.

## Task J1: durable intent, ownership and immutable checkpoints

**Owner:** Jobs. **Depends:** G0 and W1; independent of M1.

**Files:** Create `internal/jobstore/{journal,checkpoint,ownership,recovery,store}.go` and matching tests. This lower-level package is deliberately separate from the upper-level `internal/jobs` controller to avoid a controller→planner→engine-adapter→controller import cycle.

**Interfaces:** `(*jobstore.Store).Begin(ctx context.Context, intent jobstore.MutationIntent) (*jobstore.Transaction, error)`; `(*jobstore.Transaction).Commit(ctx context.Context, outputs []jobstore.OutputIdentity) error`; `(*jobstore.Store).InspectRecovery(ctx context.Context, jobID string) (jobstore.RecoveryPlan, error)`; `(*jobstore.Store).Discard(ctx context.Context, jobID string) error`. Intent pins job/plan/stage/tool/rule/predecessor identities and owned paths; output identities carry actual path/size/digest/role. This storage layer does not import planner/engine/jobs.

- [ ] Write `TestIntentPersistsBeforeMutation`; `TestCheckpointIncludesRulesToolsAndPredecessors`; `TestPartialStageCannotChangeCommittedOutput`; `TestAtomicJournalFailurePreservesPreviousRecord`; `TestDiscardPreservesExternalSourcesAndUnownedMounts`; `TestRecoveryInspectsRealState`; assert atomic old/new records, immutable validated outputs, exact invalidation and preservation of unrelated resources.
- [ ] Run `go test ./internal/jobstore -run 'Test(Intent|Checkpoint|PartialStage|AtomicJournal|Discard|Recovery)' -count=1`; expect relevant failures.
- [ ] Implement atomic durable journals, stage-owned scratch areas, validated promotion, source retention and ownership-aware recovery/discard. Persist intent before invoking mutating providers. Check real files/mounts after restart; never infer completion from journal state alone or recursively remove an unresolved/unowned path.
- [ ] Run the focused command with failure injection before/after journal write, mutation and checkpoint promotion; expect either the previous valid checkpoint or validated new output, never a partly modified reusable image.
- [ ] Obtain both reviews and commit as `feat: persist transactional jobs and safe recovery ownership`.

## Tasks E1a–E1c: source-generation reconstruction adapters

**Owner:** Engine; use separate fresh tasks/reviews/commits for each row. **Depends:** M1, W2, J1 and each family's P1 algorithm evidence; E1b/E1c also depend on E1a's accepted adapter contract. These tasks may run alongside D3; they consume model manifests/materialized fixtures, never the source service. Stage transactions come from `internal/jobstore`, never `internal/jobs`.

**Files/interfaces:** Create `internal/engine/source/{adapter,registry,types}.go` in E1a. Define `Adapter.Match(inv metadata.Inventory) (Match, error)`, `Adapter.Recipe(inv metadata.Inventory, settings model.ResolvedSettings) (Recipe, error)`, and `Adapter.Normalize(ctx context.Context, req NormalizeRequest, emit model.Emit) (NormalizedSource, error)`. Recipes describe resources/operations without importing planner. Normalized outputs retain source/resource identities and validated reconstruction hashes.

| Task | Additional owned files | Named tests and exact acceptance | Commit |
| --- | --- | --- | --- |
| E1a canonical/reference | `canonical.go`, `references.go`, matching tests | `TestReferenceResolutionUsesContentIdentity`: references match digest/provenance; `TestCanonicalNormalizationPreservesResources`: output resource hashes equal fixture expectations; `TestMissingResourceCannotCommit`: no validated stage on missing input | `feat: reconstruct canonical and reference UUP sources` |
| E1b express/PSF/CIX | `express.go`, `psf.go`, `cix.go`, matching tests | `TestReconstructionMatchesExpectedSHA256`; `TestWrongDeltaBaseFailsBeforeCommit`; `TestCIXBoundsAndTraversalRejected`: known reconstructed hashes and rejected invalid base/bounds/paths | `feat: reconstruct differential UUP payloads` |
| E1c encrypted content | `encryption.go`, matching tests | `TestEncryptedSourceRequiresVerifiedMaterial`; `TestDecryptedPayloadMatchesExpectedIdentity`; `TestKeysNeverEnterReports`: no unverified output and no secret serialization | `feat: normalize supported encrypted UUP payloads` |

For each row independently:

- [ ] Write the row's tests using actual sanitized descriptors and authorized source fixtures from P1, including at least one corrupted input.
- [ ] Run `go test ./internal/engine/source -run '<row test names>' -count=1`, replacing the pattern with the exact names in that row; expect relevant missing algorithm/validation failures.
- [ ] Implement that row's adapter with the published/proven algorithm and narrow verified helper/API if required. Generic expansion/MSDelta invocation is not proof of PSF/CIX support. Add newly discovered ISO-capable source families as explicit tasks with their own filenames, fixture hashes, algorithms and review gates; do not silently classify them out of scope.
- [ ] Rerun the exact row test command and the family's tagged real reconstruction probe; expect byte/hash-equivalent normalized resources and no committed partial output.
- [ ] Obtain both reviews and commit only that row's files using its listed subject. The coordinator alone changes the shared adapter registry after E1a.

## Task E2: immutable complete plan and applicability graph

**Owner:** Engine. **Depends:** D1, D3, E1 registry/required recipes and J1 contracts.

**Files:** Create `internal/planner/{types,resolve,dependencies,applicability,space,freeze}.go`, matching tests and versioned policy fixtures.

**Interfaces:** Produces master `Planner.Resolve`, `Request`, `ReadyPlan` and setting applicability. `ReadyPlan` exposes deep-copy getters for selected/effective settings, ordered operations, tool requirements, estimates, source manifest and digest; a canonical serialized snapshot excludes signed locators and secrets. Consumes D3 resolution and E1 recipes.

- [ ] Write `TestExplicitUnsupportedPolicyFailsBeforeMutation`; `TestBasesNeedNotRemainFinalIndices`; `TestReadyPlanDeepCopiesMutableInputs`; `TestPlanDigestIncludesRulesToolsAndPredecessors`; `TestScratchAccountingExceeds4GiBOn386`; `TestHostDoesNotRemoveTargetChoices`; assert explicit settings are preserved or diagnosed, immutable copies, deterministic identities and exact `int64` estimates.
- [ ] Run `go test ./internal/planner -count=1`; expect relevant failures.
- [ ] Implement dependency closure, base/output edition distinction, capability resolution of `auto`, exact explicit-policy validation, preflight estimates/filesystem/permissions/locks, tool requirements and immutable operation graph. Build availability may report an implementation blocker while every target stays visible. Bind the effective plan to the reviewed draft revision.
- [ ] Run focused tests plus source/planner contract tests; expect unchanged frozen plans after caller mutation and no operation graph for an invalid explicit policy.
- [ ] Obtain both reviews and commit as `feat: create immutable UUP conversion and applicability plans`.

## Task E3: base images, setup tree, boot WIM and WinRE

**Owner:** Engine. **Depends:** E2, E1, J1, W2; Gate P and relevant Gate S evidence passed.

**Files:** Create `internal/engine/{types,assembly,bootwim,winre,mediatree}.go`, matching tests and real-image integration descriptors.

**Interfaces:** `(*Assembler).Assemble(ctx context.Context, req AssemblyRequest, emit model.Emit) (BaseImages, error)`. Request carries a ReadyPlan, normalized resources, verified providers and stage transaction; BaseImages identifies immutable edition/setup/recovery outputs with inspected metadata.

- [ ] Write `TestSetupAndBootMatchSourceIdentity`; `TestAssemblyPreservesACLStreamsLinksAndReparsePoints`; `TestForeignTargetExecutablesNeverLaunched`; `TestZeroExitWrongImageRejected`; assert matching build/arch/language/edition roles, preserved Windows metadata, no attempted target process execution, and no committed wrong image.
- [ ] Run `go test ./internal/engine -run 'Test(Setup|Assembly|Foreign|ZeroExit)' -count=1`; expect relevant failures.
- [ ] Implement real wimlib/provider-based assembly and matching source-family setup/boot/WinRE construction with stage ownership. Inspect results before commit. Never replace missing source boot files with an unrelated build or approximate imaging by ordinary file copying.
- [ ] Run focused tests and tagged real assembly for required source families/targets; expect inspected valid images with matching resource identity and filesystem metadata. Real foreign-architecture cases use host-compatible providers.
- [ ] Obtain both reviews and commit as `feat: assemble verified installation and boot images`.

## Task E4: update ordering and edition specialization

**Owner:** Engine. **Depends:** E3, E2 and P1 generation rules.

**Files:** Create `internal/planner/{servicing,editions}.go`, `internal/engine/service/{types,executor,updates,editions,cleanup}.go`, `internal/engine/rules/{registry,updates,editions}.go`, and matching tests/fixtures.

**Interfaces:** `planner.BuildServicePlan(inv metadata.Inventory, settings model.ResolvedSettings) (planner.ServicePlan, error)`; `(*service.Executor).Execute(ctx context.Context, req service.ServiceRequest, emit model.Emit) (service.ServicedImages, error)`. ServicePlan is a dependency-ordered typed graph; Execute uses W2 providers and J1 transactions. E4 adds typed service operations to E2's operation graph without a planner-to-executor import cycle.

- [ ] Write `TestCheckpointUpdatesRequirePredecessors`; `TestExternalUpdatesRemainOutsideImages`; `TestEditionDerivationPreservesDifferences`; `TestCleanupResetBaseFollowGenerationRules`; `TestFinalEditionInventoryMatchesPlan`; assert mandatory update order, exact integrate/external/omit behavior, correct final edition identities and post-cleanup inventory.
- [ ] Run `go test ./internal/planner ./internal/engine/service ./internal/engine/rules -count=1`; expect relevant failures.
- [ ] Implement provenance-backed generation rules for servicing stack/cumulative/checkpoint/MSU expansion, enablement packages, valid edition derivation and shared-base servicing, cleanup/reset-base and retained references/temporary bases. Split materially different new generation rule sets into separately reviewed commits with explicit fixtures; no blanket build-number guesses or ignored explicit choices.
- [ ] Rerun focused tests and real update/edition fixtures; expect independently inspected matching packages and output editions. A zero exit code without required packages fails.
- [ ] Obtain both reviews and commit as `feat: service updates and derive validated image editions`.

## Task E5: apps, features, drivers and recovery policies

**Owner:** Engine. **Depends:** E4's service graph; may extend independent executor files after that contract is accepted.

**Files:** Create `internal/planner/{apps,drivers,features}.go`, `internal/engine/service/{apps,features,drivers,recovery,bootfiles}.go`, `internal/engine/rules/{apps,features,recovery}.go`, matching tests/fixtures. Modify only the agreed E4 executor registration points.

**Interfaces:** `PlanApps(inv metadata.Inventory, settings model.ResolvedSettings) ([]Operation, error)`, `PlanDrivers(inv metadata.Inventory, settings model.ResolvedSettings) ([]Operation, error)` and `PlanFeatures(inv metadata.Inventory, settings model.ResolvedSettings) ([]Operation, error)` in planner; `Operation` is E2's typed operation. Service adapters consume those operations through E4's executor.

- [ ] Write `TestAppClosureIncludesFrameworksAndLicenses`; `TestUnavailableCustomAppFails`; `TestLegacyRemovalUsesDeclaredCustomizationPhase`; `TestNoneModeCannotPretendUnsupportedRemoval`; `TestDriversKeepOSWinPEWinREDistinct`; `TestNetFxAndRecoveryFollowApplicability`; `TestInstalledInventoryMatchesRequestedApps`; assert family/dependency/license closure, supported mode semantics, exact driver targets and requested effective feature/recovery outcomes.
- [ ] Run `go test ./internal/planner ./internal/engine/service ./internal/engine/rules -count=1`; expect relevant failures.
- [ ] Implement app provisioning/removal where supported, presets/custom/default/none and stub/full policy, generation-specific Edge policy, feature sources, driver target groups and WinRE/boot-file updates. Keep per-edition differences and preserve requested unsupported choices as diagnostics. Inspect materialized legacy provisioned-app inventory before applying that source family's validated policy.
- [ ] Run focused tests and actual representative provisioned/installed-image checks; expect requested apps/features/drivers and matching recovery resources, not only logged commands.
- [ ] Obtain both reviews and commit as `feat: specialize image apps features drivers and recovery`.

## Task E6: export, boot catalogs, independent validation and publication

**Owner:** Engine. **Depends:** E3–E5, J1, W2.

**Files:** Create `internal/engine/output/{types,export,bcd,bootcatalog,master,verify,publish,report}.go` and matching tests/integration descriptors.

**Interfaces:** `Prepare(ctx context.Context, req OutputRequest) (PreparedArtifact, error)`; `Verify(ctx context.Context, req VerificationRequest) (VerifiedArtifact, error)`; `Publish(ctx context.Context, artifact VerifiedArtifact, destination string) (model.Artifact, error)`. Only Verify can construct a VerifiedArtifact accepted by Publish. Requests carry frozen plan identity, stage transaction, matching images/media and verified providers.

- [ ] Write `TestFormatsPreserveEditionOrder`; `TestARM64UsesMatchingUEFIPath`; `TestBootCatalogMatchesFirmware`; `TestLargeInstallImageRemainsReadable`; `TestZeroExitMissingSetupFailsVerification`; `TestWrongAppInventoryFailsVerification`; `TestPublicationCopyDigestMismatchKeepsLocalArtifact`; `TestCrashAfterPublishRecoversByDigest`; `TestUnrelatedDestinationNotOverwritten`; `TestReportRedactsSignedURLsAndCredentials`; assert correct final indices/firmware/resources, independent image/media checks, safe publication and redaction.
- [ ] Run `go test ./internal/engine/output -count=1`; expect relevant failures.
- [ ] Implement WIM/ESD/SWM export, ordering/split limits, explicit offline BCD updates, target-correct BIOS/UEFI boot resources and UDF/El Torito mastering. Independently inspect image/source/edition/app results and ISO structures; do not trust mastering status alone. Publish from a verified temporary artifact with SHA-256 and a redacted report; validate remote copies and recover a completed publication by identity after a crash. Image-only/directory output follows equivalent checks.
- [ ] Run focused tests and actual large-file/firmware cases; expect readable validated media with the correct target, settings and digest. Representative boot/Setup/application evidence is completed in R1.
- [ ] Obtain both reviews and commit as `feat: verify and publish bootable Windows media`.

## Task J2: constrained elevated worker and real job controller

**Owner:** Jobs plus coordinator for executable wiring. **Depends:** J1, W1, E2 and E3–E6 callable stage adapters.

**Files:** Create `internal/jobs/{controller,state,events,cancel,resume}.go`, `internal/worker/{protocol,validate,dispatch,entry}.go`, matching tests; coordinator modifies `internal/app/wire.go` and `cmd/uupbuilder/main.go` for private same-executable worker mode. Lower-level Windows files stay W1-owned.

**Interfaces:** Produces all master `Controller` methods and `JobView`; `worker.Run(ctx context.Context, descriptor Descriptor) error`. Descriptor fixes job/plan identity, allowed operation graph and restricted pipe endpoint; no generic executable/command strings are accepted from the caller. Consume E2 frozen plans, J1 store, W1 elevation/pipe/process ports and typed stage handlers.

- [ ] Write `TestWorkerRejectsAlteredFrozenPlan`; `TestWorkerRejectsUnknownOperationOrPeer`; `TestControllerRunsOnlyOneConversion`; `TestIntentPrecedesStageInvocation`; `TestWorkerLossRestartsCleanStage`; `TestVerifiedDownloadsSurviveRecovery`; `TestPauseOnlyAffectsDownloads`; `TestCancelDoesNotClearUnownedMounts`; `TestCompletionRequiresVerifiedArtifact`; assert restricted work, durable ordering, safe cleanup, preserved inputs and backend-authenticated completion.
- [ ] Run `go test ./internal/jobs ./internal/worker -count=1`; expect relevant failures.
- [ ] Implement real state transitions, durable intent/checkpoints, event subscriptions with coalesced noncritical progress, and the validated elevated worker. UI delivery is not the journal. Pause only downloads; cancellation requests a safe stop, then verifies owned resources and records incomplete mutation. Recover by actual files/mounts and predecessor validation. Do not indiscriminately kill servicing tools or clean global mounts. Frozen plans cannot be edited by later TUI drafts.
- [ ] Run focused tests and tagged process-loss/elevation/mount recovery checks on real Windows hosts; expect surviving verified downloads, clean restarted mutation, unrelated state preserved, and successful completion only after E6 verification/publication.
- [ ] Obtain both reviews and commit as `feat: coordinate native jobs and recover safe elevated operations`.

## Engine-lane handoff

Deliver exact producer contracts, real provider/source evidence, successful/failed/unverified coverage, actual image checks and remaining blockers. Distinguish observed and portability-accepted host coverage under the host proof policy. P1/S gates and R1 functional evidence cannot be satisfied by mocks, skipped tests or cross-compilation alone. All available targets remain discoverable regardless of a temporary engineering gap.
