# UUP Builder Remaining Work Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This document reviews existing implementation and plans the remaining work; it does not execute that work.

**Goal:** Complete the missing application wiring, proven source conversion, managed providers, editors, job execution and verified ISO-file output while reusing the implemented foundations.

**User scope update — 2026-10-29:** The [authoritative scope amendment](../../engineering/2026-10-29-scope-amendment.md) removes recovery/WinRE work, all of original R17 Review/Start/progress/terminal work, and bootability testing. The deliverable is a Windows ISO file; no USB/DVD/disk-writing workflow or standalone image/directory output is requested. Normal source-matching Windows Setup/image files remain inside the ISO. This update supersedes conflicting older design/contract/plan requirements; excluded work is not marked passed.

**Architecture:** Keep the existing configuration, catalog, download, source-orchestration, Windows, journal, and browsing packages. Close the provider and source-algorithm gates, supply production metadata discovery, and add an immutable planner whose typed stages run through the same executable's constrained elevated worker. Only independently verified outputs may complete a conversion job.

**Tech Stack:** Go 1.27.0; the currently pinned Bubble Tea v2, Bubbles v2, Lip Gloss v2, go-toml/v2, and x/sys dependencies; Windows 10+ APIs; individually managed imaging/servicing/mastering providers.

**Spec:** [Accepted design](../specs/2026-10-27-uup-builder-design.md), [shared contracts](../../engineering/contracts.md), and the authoritative [host proof policy](../../engineering/host-proof-policy.md).

**Reviewed plans:** [Data](2026-10-27-uup-builder-data-plan.md), [engine](2026-10-27-uup-builder-engine-plan.md), [Workspace](2026-10-27-uup-builder-workspace-plan.md), and [master](2026-10-27-uup-builder-multi-agent-plan.md). Their remaining product requirements apply subject to the 2026-10-29 scope amendment. This document replaces their bootstrap-from-zero schedule for the remaining work.

**Review baseline:** 2026-10-28, `N:/win11_builder`, branch `feat/uup-builder`, HEAD `3311c280cbdd5e7574de04fcc3c94ddaa7fdcfc9`. Assessment covers the current checkout, including the two supplied untracked plan files. Other worktrees are not counted as integrated product functionality. Existing untracked guidance files are preserved.

## Global Constraints

- Go implementation with a Charm TUI.
- One executable for the user to download and run. Helpers may be extracted or downloaded behind the scenes, with the app managing their complete lifecycle.
- Use TOML for application configuration.
- Treat the existing files in this directory as guidance. Do not consume, copy into the product, modify, or execute them as application resources.
- Implement the conversion pipeline in Go and call individual tools directly. Do not use an upstream conversion script as the engine.
- Cover all builds available in UUP Dump.
- Run on Windows 10 and later, supporting the x86 and Arm architecture families.
- Allow every build target on every supported host. Do not restrict available targets to a smaller host/target compatibility matrix.
- One job builds one architecture and one language, with one or more editions. Run one conversion job at a time, with parallel network transfers.
- Preserve schema version `1`, default config path `%LOCALAPPDATA%/UUPBuilder/config.toml`, `parallel_files=4`, `retries=5`, and `split_size_mib=3800` unless a separately reviewed schema migration requires a change.
- Preserve the current Go `1.27.0` baseline and dependency pins. Change dependencies only for an identified missing operation, with primary-source justification.
- Complete functionality on the available native Windows host plus Windows `386`/`amd64`/`arm64` builds satisfies host-architecture acceptance. Keep all nine logical common pairs and distinguish actual observations from portability acceptance; other physical host hardware is optional.
- Failed/skipped/unconfigured functional checks remain failed or unverified. Unit fixtures, static candidate pins, and cross-builds do not establish conversion support.
- Deliver an ISO file. Recovery/WinRE, original R17 Review/Start/progress/terminal work, bootability/Setup execution tests, physical-media writing and standalone image/directory outputs are excluded. Existing schema-1 settings remain readable; excluded choices must not be represented as implemented. Keep active-operation ownership, safe cancellation and necessary owned-resource cleanup.

## Review Focus

1. A proven provider for one image generation is selected for another: R3/R5/R10 must bind source generation, target, operations, rule identity, and dependency closure instead of trusting a version or machine header.
2. Legacy app inventory becomes available only after materialization: R6/R10/R13/R16 must preserve requested choices and insert an explicit validation barrier before customization, without claiming that unknown apps are absent.
3. A valid-looking media tree loses Windows security/stream/link metadata: R7/R11 must inspect preservation after reconstruction and apply/capture, including corrupt and incomplete references.
4. Elevation uses the wrong workspace or plan: R15 must bind the private capability, authenticated peer, frozen plan digest, and actual predecessor identities before mutation. Restart recovery is excluded.
5. A successful helper or publication copy produces wrong/truncated media: R14/R15/R18 must verify contents and destination digests, retain the last valid local artifact, and refuse conversion completion.

## What is already implemented

"Implemented" below means the named component has substantive code and relevant passing tests. It does not mean that component is connected to a finished application or that all release evidence exists.

| Original task | Current status and evidence | Remaining work |
| --- | --- | --- |
| G0 | Implemented bootstrap: module/dependencies, shared identities/settings/events/path validation, argument and config-path boundary. See [model](../../../internal/model/source.go), [entry](../../../internal/app/wire.go), and [contracts](../../engineering/contracts.md). | `app.Run` currently parses arguments and returns; it does not load config or launch the TUI. R1/R15 complete the reduced application composition. |
| D1 | Implemented strict typed TOML, defaults, path resolution, useful diagnostics, normalized atomic save and backups. [Config code](../../../internal/config/types.go), [save](../../../internal/config/persist.go), complete fixture and failure-injection tests exist. | Application startup and interactive load/save/editing: R1/R2/R16. |
| D2 | Implemented catalog/language/edition/file endpoints, sparse-object/array normalization, revision preservation, cache/staleness, response bounds and bounded retries. [Client](../../../internal/catalog/client.go). Fresh live discovery passed. | Successful separate-app-set evidence is absent for the probed selections; current-source live refresh was rate-limited. R6/R18 close applicable evidence without inventing API support. |
| D4 | Implemented streamed resumable transfers, size/source-digest/SHA-256 verification, content/provenance cache keys, URL refresh callback, pause/resume, workspace leases and native system proxy. [Manager](../../../internal/download/manager.go). | Wire owned lifetimes into active jobs; restart recovery is excluded. The real dense >4 GiB transfer check remains release evidence to run: R15/R18. |
| D3 | Implemented immutable unions/digests, replayable queries, safe locator refresh, base/app-set orchestration, classification diagnostics, and [source/download callback binding](../../../internal/app/source.go). [Resolver](../../../internal/source/resolver.go). | `Discover` and `DiscoverApps` have no production implementation; native read-only inspection is injected. No connected real semantic resolution or app policy closure. R6/R13/R16. |
| W1 | Implemented Windows host/filesystem detection, URL-specific system/PAC proxy, direct runner, owned process cancellation, workspace containment, elevation bootstrap and authenticated pipes. [Platform contracts](../../../internal/platform/windows/types.go). Ordinary and tagged process/pipe checks passed. | Real elevated worker dispatch and operation authorization remain R15 work. Restart recovery and further console campaigns are excluded; clean-machine provider checks remain R18. |
| P1 | Implemented strict case/evidence/census validators, retained bounded CAB/WIM/LZMS/ISO observations, and independent ISO/UDF/El Torito inspectors in [probes](../../../tests/probes/cases.go). | Full Gate P has zero passing host/target pairs; Gate S has zero passing families. Census is sampled. Required cases remain pending and runtime-unconfigured. R3/R4. |
| P1p | Implemented the accepted one-host architecture coverage evaluator with strict witnesses and tests. [Coverage](../../../tests/probes/architecture_coverage.go). All three Windows builds passed during this review. | Functional proof still has to pass before the policy can supply accepted coverage. Do not repeat the completed policy implementation. |
| W2 | Partial: pinned trusted candidate manifest, selection diagnostics, manager leases, byte verification, and a private tested ZIP materializer. [Manager](../../../internal/tools/manager.go), [acquisition status](../../feasibility/acquisition.md). | Every valid `Ensure` call returns an empty toolchain and `BlockedError`/`ErrUnverified`. Production acquisition, prerequisites, execution, capability acceptance and complete notices are missing. R3/R5. |
| M1 | Partial: bounded static CompDB/CBS/WIM XML/Appx/license parsers, provenance/evidence checks, graph/role/app types and classification. [Inventory](../../../internal/metadata/inventory.go), [fixture limitations](../../../internal/metadata/testdata/README.md). | Production CAB/WIM/Appx inspection, source-backed semantic roles/base rules, actual UUP apps/licenses/defaults and complete generation coverage. Raw local CompDB test was skipped because its corpus was not supplied. R4/R6/R13. |
| J1 | Implemented durable intent, immutable validated checkpoints, journal failure handling, ownership, native mount inspection and conservative discard/recovery. [Store](../../../internal/jobstore/store.go). | Reuse intent/checkpoints for active stages and owned cleanup: R15. New restart discovery/recovery is excluded. |
| U1 | Implemented six-area navigation, real asynchronous discovery, stale-response rejection, exact source selection, invalidation, mouse/keyboard and compact golden views. [Model](../../../internal/tui/model.go). | R1 now launches the real model; R2 supplies Conversion/TOML actions. R16a app-editor work is next. Dedicated Review/Progress/recovery/terminal work is excluded. |
| E1a/E1b/E1c | Missing product adapters: there is no `internal/engine/source` package. Research parsers and source capsules are component observations. | Canonical/reference, differential, encrypted-delivery and newly discovered family adapters: R4/R7/R8/R9. |
| E2 | Missing: no `internal/planner`. | Immutable plans, policy applicability, dependency closure and preflight: R10, extended by R12/R13. |
| E3/E4/E5/E6 | Missing: no production `internal/engine`. | Internal ISO contents, servicing/editions, customization, ISO verification/publication: R11-R14; no WinRE or boot-execution work. |
| J2 | Missing: no `internal/jobs` or `internal/worker`. | Real controller, same-executable worker and active frozen-job state: R15; no restart recovery. |
| U2/U3 | Missing feature implementations and application integration. | Editors: R2/R16, with early R16a preview. Original R17 is removed. |
| R1 release | Missing: no `tests/integration`, release script, release documentation, or verification workflow. | R18; all functional proof remains required. |

The existing plans' unchecked boxes are not a reliable progress ledger. Their statements that no Go project exists are historical. Re-running G0/D1/D2/D4/J1/U1 from scratch would duplicate working code. Conversely, counting W2 or M1 as complete because their packages exist would hide functional gaps.

## Verification performed for this review

| Command/check | Fresh result on 2026-10-28 | What it establishes |
| --- | --- | --- |
| `go test ./... -count=1` | PASS: 12 tested packages; CLI package has no tests. | Ordinary component tests pass. Optional/tagged cases are separate. |
| `go vet ./...` | PASS. | Current static checks are clean. |
| `GOOS=windows CGO_ENABLED=0 GOARCH=<386/amd64/arm64> go build ./...` | PASS for all three architectures. | Build portability, with functional acceptance still gated. |
| `go test -tags=windowsintegration ./internal/platform/windows -count=1` | PASS. | The current platform integration checks run successfully on this host. |
| `go test -tags=liveapi ./internal/catalog ./internal/source -run 'TestLive(DiscoveryContract\|AppSetsAndLinkRefresh)$' -count=1 -v` | Mixed: catalog discovery PASS; legacy ARM64 refresh PASS for 46 payloads; current amd64 refresh FAIL with HTTP 429 `USER_RATE_LIMITED`. | Real API discovery and one refresh path work. Current-source refresh was not verified successfully in this review. Neither selection advertised APP/APP_MOMENT. No native semantic discovery or conversion was tested. |
| `go test -tags=providerproof ./tests/probes -run '^TestProviderPerformsCrossArchitectureServicing$' -count=1 -v` | FAIL/UNVERIFIED for amd64-host to x86/amd64/arm64; zero provider invocations. Observed Windows build 19045, native/process amd64. | Current full-gate descriptors do not supply runnable accepted proof. Blockers include adapter/provider closure/rights/source fixtures/expected outputs/algorithms/prerequisites/clean host, historical policy stop, and `runtime-unconfigured`. |
| `go test ./internal/metadata -run '^TestLocalOriginalCompDBCorpus$' -count=1 -v` | SKIP: `M1_COMPDB_CORPUS` not supplied. | No fresh original-corpus proof. A successful package exit with this skip is not corpus acceptance. |

Not run: actual dense >4 GiB transfer, race toolchain, new image mutations, actual boot/Setup, clean-machine provisioning, or legacy console sessions. Their absence is recorded as missing evidence, not a newly discovered implementation bug. The HTTP 429 is an observed upstream response after bounded retries; this review does not establish that the retry implementation is defective and makes no retry-policy change.

## Existing blockers and corrections to the execution plan

1. **Servicing is still unproved.** The [toolchain ledger's latest mounted-reader case](../../feasibility/toolchains.md#latest-mounted-reader-and-servicing-boundary) passed bounded source reads and authentication, but Get-Intl failed with exit `87`/`0x80070057` during PE attach/OSVersion initialization. The healthy registered read-only mount did not resolve that failure. The internal predicate is unknown; this does not prove a permanent architecture or Windows-version incompatibility. Another identical WinRE retry is not a useful next task.
2. **Provider acquisition is not operational.** The schema-1 catalogue contains candidates and mandatory pending blockers. Its private ZIP materializer cannot provision Microsoft MSI/CAB/prerequisite chains and is unreachable from `Ensure`. Remove a blocker only when its actual requirement is satisfied; do not replace refusal with a readiness boolean.
3. **Source orchestration is not semantic discovery.** Implement real producers for the resolver's existing callbacks and metadata's `ReadOnlyProvider`. The live source test itself explicitly excludes native semantic discovery/conversion.
4. **The source taxonomy is larger than three adapter names.** The [census](../../feasibility/source-formats.md#familyalgorithm-requirements) distinguishes baseless/base-dependent differential sources, encrypted ESD versus ESRP, checkpoint MSU, apps/FoD, legacy layouts and unknown/specialized families. Each applicable generation needs actual algorithms and fixtures.
5. **Use actual producer types.** The old Workspace task refers to `config.Apps`, which does not exist; configuration uses `model.AppSettings`. The old download plan describes path-root options, while actual `download.Options` borrows two distinct `*windows.Workspace` capabilities. Do not add duplicate settings/workspace DTOs to make old prose compile.
6. **Publish usable milestones without lowering the final scope.** Startup/editor work can proceed before provider research completes. A first proven canonical conversion is an integration milestone; every valid ISO-capable family still has to be implemented before final release.

## Immediate execution priority — TUI first

R1 and R2 are implemented and reviewed. A real native preview is available for user testing now. The user confirmed its behavior but requested the earlier purple Workspace style and supplied the reference screenshot. Do R16s visual fidelity first, then R16a and concrete UI feedback before returning to R3-R15 backend work; R16b waits only for its actual data producers. Native-control fix work is retained in place while this priority runs. Do not reinstate removed R17 or build fake backend/app data to make the preview look complete.

## File boundaries and execution order

| Work | Files/responsibility | Dependencies |
| --- | --- | --- |
| R1 startup | `internal/app/{wire,interactive}.go`, tests | Existing D1/D2/U1/W1 |
| R2 conversion/config editors | `internal/tui/{conversion,fields,config_actions}.go`, tests | R1 and existing D1/U1 |
| R16s visual fidelity NOW | Charm Workspace palette, panels, controls, spacing and preview | Completed R1/R2; accepted reference screenshot/HTML; no backend wait |
| R3 provider proof | `tests/probes` runtime/case adapters, provider fixture descriptors, `docs/feasibility` | R3a uses existing P1/W1/J1; R3b also consumes R4a fixture contracts |
| R4 source corpus/algorithms | Source census, sanitized descriptors and per-family proof recipes | R4a uses existing census; R4b uses R3a's narrow runtime and operation prerequisites |
| R5 operational tools | Extend `internal/tools`, pinned manifest v2, acquisition/setup routes | R3's accepted provider definitions and operation proof |
| R6 production source discovery | `internal/source`, `internal/metadata`, new `internal/metadata/providers` | R4's descriptors and R5's read-only providers |
| R7 canonical/reference adapters | New `internal/engine/source` | R3/R4 proof for these families, R5/R6/J1 |
| R8 differential adapters | `internal/engine/source/{express,psf,cix}.go` and generation files | R7 adapter contract; R4 proof for each variant |
| R9 encrypted adapters | `internal/engine/source/{encryption,esrp}.go` | R7 adapter contract; R4 proof for each encryption variant |
| R10 planner | New `internal/planner` | R6/R7/J1; register R8/R9 as accepted, without delaying the first canonical slice |
| R11 assembly | New root `internal/engine` stage adapters | R10/R7 and applicable R8/R9; Gates P/S for selected family |
| R12 updates/editions | Planner servicing graph, `internal/engine/service` and `rules` | R11 and R4 generation rules |
| R13 apps/features/drivers | Planner and service/rule extensions; no recovery/WinRE | R12, R6 semantic policies |
| R14 outputs | New `internal/engine/output`; reusable media inspector | R11-R13 |
| R15 jobs/worker | New `internal/jobs`, `internal/worker`; app private-mode wiring | R10-R14; existing W1/D4/J1 |
| R16a TUI next | App editor/view states and interactive preview | Existing U1/R1/R2 and typed inventory contracts; no backend wait |
| R16b app data later | Bind the same editor to actual policies/inventory | R6/R13 producers |
| R17 removed by user | No Review/Start/progress/recovery/terminal project | No remaining dependency |
| R18 release | Reduced conversion/content evidence and executable bundles | Remaining tasks/families; R17, recovery and boot tests excluded |

Keep the existing acyclic boundaries: download never imports source; metadata never imports source/planner; engine/source recipes do not import planner; engine stages use jobstore, not jobs; planner never imports service executors/output; the app composes callbacks. Product packages must not import `tests/probes`. If a research inspector becomes reusable product code, move its implementation to a focused internal package and keep probe tests exercising that package.

The proof work has four explicit review checkpoints so it does not form a scheduling cycle: **R3a** runnable bindings/control diagnostics and **R4a** independently grounded fixture/algorithm contracts can proceed together; **R3b** closes the full provider gate using R3a/R4a; **R4b** closes each source-family algorithm proof using R4a and the applicable R3a operation prerequisites. R5 requires R3b for operational providers, and each product adapter requires its own R4b proof. A reviewed harness/descriptor commit does not mark the remaining native proof complete. Production conversion stages remain behind the applicable full gates.

For future delegated execution, preserve the master plan's requested `gpt-6.1-sol`/`xhigh` settings, at most three children plus coordinator, isolated writable ownership, and separate fresh specification/quality reviews. This review does not dispatch implementers. Reuse a suitable existing worktree; create isolation only when execution requires it. Dependency/shared-contract changes belong to the coordinator.

For each task below, run the named tests before implementing and establish the expected behavioral failure, then implement and rerun the same focused command. A missing dependency/tool/corpus is an environment prerequisite, not a red behavior test. After verification, obtain the required reviews and commit only that task's explicit owned files. Preserve other work and original guidance files.

---

## Task R1: launch the existing Workspace from the executable

Status: implemented and independently reviewed; see the SDD ledger.

**Files:** Modify `internal/app/wire.go` and `entry_test.go`; create `internal/app/interactive.go` and `interactive_test.go`. Extend `cmd/uupbuilder/main.go` only if signal/shutdown wiring requires it.

**Interfaces:** Keep `app.Run(context.Context, []string) error`. Add `app.RunInteractive(ctx context.Context, opts Options) error`, with `Options{ConfigPath string, Config config.Config, Dependencies tui.Dependencies}`. The real implementation creates `tui.New`, runs Bubble Tea with context cancellation, and defers `Model.Close`. Extend Options with planner/controller ports only after those producers exist in R10/R15.

- [x] Write `TestEntryLaunchesWorkspaceWithLoadedConfig` (`launchCalls == 1`, selected revision and resolved paths equal the TOML); `TestMissingDefaultConfigUsesBrowsingDefaultsWithoutSaving` (`writes == 0`); `TestExplicitMissingConfigReturnsUsefulError` (`errors.Is(err, os.ErrNotExist)` and `launchCalls == 0`); `TestMalformedConfigNeverLaunchesOrOverwrites`; and `TestInteractiveCancellationClosesDiscovery`. Update the bootstrap-only test that currently accepts an explicit nonexistent config path.
- [x] Run `go test ./internal/app -count=1`; expect failures because Run currently never launches or loads anything.
- [x] Use defaults only for a missing implicit default file; use strict `config.Load` for existing/explicit files. Resolve default relative paths against the config directory. Keep first-run browsing valid without calling `Config.Request` before an image is selected. Do not create config/cache/tool directories just by validating invalid arguments. Startup performs ordinary browsing without elevation.
- [x] Rerun the focused tests and `go test ./internal/tui -count=1`; exercise the real executable in a Windows console and confirm discovery and shutdown. Conversion actions remain unavailable with an accurate reason until their actual producers are connected.
- [x] Review and commit as `feat: launch Workspace with typed configuration`.

## Task R2: implement conversion settings and TOML actions

**Files:** Create `internal/tui/{conversion,fields,config_actions}.go` and matching tests; modify `model.go`, `messages.go`, `layout.go` at delegated area/update points; add focused editor goldens.

**Interfaces:** `NewConversionModel(cfg config.Config, applicability []model.SettingApplicability) ConversionModel`; `(ConversionModel).Apply(cfg config.Config) (config.Config, []model.Diagnostic)`. Reuse `config.Load`, `Save` and `SaveResult`; use `model.AppSettings` for app configuration, never a second `config.Apps` type. The app-specific controls are completed by R16.

- [x] Write `TestConversionEditorCoversTypedSettings` (every editable conversion/output/driver/download/storage field appears); `TestExplicitUnsupportedSettingIsNotReset` (`requested == original`); `TestAutoShowsEffectiveValue`; `TestConfigLoadFailureRetainsDraft` (`after == before` by deep comparison); `TestSaveReportsBackupAndNormalization`; and `TestConfigPathChangeInvalidatesReviewedDraft` (`afterRevision > beforeRevision`).
- [x] Run `go test ./internal/tui -run 'Test(Conversion|Explicit|Auto|Config|Save)' -count=1`; expect missing editor/action failures.
- [x] Implement typed grouped controls for updates/servicing/cleanup, checkpoint/cumulative/MSU/enablement/reference policies, temporary bases/edition order, boot/WinRE/NetFx3, OS/WinPE/WinRE/shared driver targets, WIM/ESD/SWM/output naming, proxy/concurrency/retries, scratch/cache/retention. Keep requested and effective values distinct. Increment draft revision on successful changes; failed load/save retains the draft. Surface backup path and normalization. Create a selected save directory only as part of the actual save action.
- [x] Run `go test ./internal/config ./internal/tui -count=1`; inspect long names, validation errors and compact layouts. R16b/R15 later bind applicability to the exact draft revision without a dedicated R17 screen project.
- [x] Review and commit as `feat: add conversion editors and TOML actions`.

## Task R3: close the concrete native provider proof gap

**Files:** Extend `tests/probes/{runtime,runtime_runner,runtime_windows,provider_windows_test}.go`; add `tests/probes/servicing_windows.go` and tests, `tests/probes/runtime_bindings.go` and tests; update `testdata/compatibility/required-cases.json` and `docs/feasibility/toolchains.md`/`acquisition.md`.

**Interfaces:** Preserve `RunCase`, `ValidateEvidence`, `ValidateArchitectureCoverage`, `Case` and `Evidence`. Extend `RuntimeConfig` with typed extraction/reconstruction/servicing/mastering/inspection recipes and fixed Go dispatch; add `LoadRuntimeBindings(io.Reader) (map[string]RuntimeConfig, error)` for private per-case bindings. The private binding format explicitly maps fixture/workspace roots and artifact IDs into RuntimeConfig; do not decode its public JSON form and expect the existing `json:"-"` roots to be populated. Bindings identify existing frozen cases; they contain no arbitrary executable command text and cannot assert success. The tagged provider test reads the private binding file named by `UUP_PROVIDER_RUNTIME` and passes `WithRuntime(ctx, binding)` into `RunCase`; its current unconfigured call cannot close the gate.

- [ ] Add `TestProviderGateBindsExactFrozenCase` (`binding.CaseDigest == c.Digest()` and altered bindings are rejected); `TestServiceProofRequiresChangedImageAndInspection` (`beforeSHA256 != afterSHA256`, required package/configuration result observed); `TestProviderProofRejectsUnprovenGeneration`; and corrupt/dependency-missing cases. Preserve existing rejection of cross-build-only, WOW64 and mixed incomplete hosts.
- [ ] Run `go test ./tests/probes -run 'Test(ProviderGate|ServiceProof|ProviderProof|Evidence|ArchitectureCoverage)' -count=1`; expect the new behavior tests to fail.
- [ ] Diagnose the recorded Get-Intl failure with a written hypothesis and a supported source/provider control, varying one condition per diagnostic. Establish a supported desktop-image baseline and source/reference/servicing-stack closure for the remaining ISO operations. Do not schedule another WinRE attempt. A query is only a diagnostic: remaining proof requires a real offline modification, validated image output, independent inspection, reconstruction and ISO-content checks; boot/Setup execution and recovery are excluded. Retain the original failures; do not infer an unsupported target from them.
- [ ] Establish exact acquisition routes, trusted package/component pins, actual operation-specific dependencies, notices/use/distribution terms, application-managed prerequisites and restart behavior. Resolve historical policy stops through an allowed concrete route; keep unresolved requirements explicit. Use narrow host-native providers directly, without a converter-script fallback.
- [ ] Review and commit R3a's runnable harness/control checkpoint before R3b uses R4a's reviewed fixtures. Keep the full gate pending until its actual operation outputs pass.
- [ ] Rerun focused tests; then run the configured `providerproof` gate for every required target on the available native host plus all three Windows builds. Pass requires real invocations and inspected outputs, zero unresolved functional prerequisites, strict per-record validation and observed/portability-accepted coverage. Keep independent UI/data work moving if this task remains blocked.
- [ ] Review and commit as `test: establish runnable full native provider proof`.

## Task R4: establish complete source-family fixtures and algorithm decisions

**Files:** Extend `tests/probes/source_census_test.go`, case/census descriptors and family-specific probe files; create sanitized `testdata/source-families/*.json` and `docs/feasibility/source-family-contracts.md`; update `source-formats.md`. Large authorized sources and secret material stay in private ignored storage.

**Interfaces:** Reuse `SourceCensus`, `SourceFamily`, `Expectation`, `SourceCensus.ValidateBuildable(family string, required []Case, evidence []Evidence) error` and `RunCase`. Each family descriptor records exact update/revision/target/language, payload and base/reference identities, compression/container/index variant, reconstruction algorithm/version, source/ISO-content roles, independent expected output hashes/content assertions and acquisition provenance. It must also identify positive, corrupt, wrong-base and missing-resource fixtures.

- [ ] Add `TestFamilyDescriptorRequiresIndependentOutput`, `TestCensusDoesNotTreatSamplingAsCompleteness`, `TestDeltaVariantsRequireTheirOwnAlgorithmProof`, and `TestEncryptedESDAndESRPAreDistinct`. Assertions reject a payload hash reused as an invented reconstructed expectation, omitted applicable families, and a proof for one container/base mode being reused for another.
- [ ] Run `go test ./tests/probes -run 'Test(Family|Census|DeltaVariants|EncryptedESD|SourceCensus)' -count=1`; expect new contract failures.
- [ ] Inventory an actual catalog snapshot across legacy/current client, Server/LTSC/specialized sources, target architectures, languages and update generations. Inspect raw metadata, not titles alone. Cover canonical/reference WIM/ESD, baseless and base-dependent express, actual PSF/CIX versions, encrypted ESD, ESRP, traditional PSFX and checkpoint MSU, apps/FoD/separate images, legacy composition and any additional discovered layout. Keep update-only/unavailable sources distinct from missing implementation.
- [ ] Review and commit R4a's independently grounded initial canonical/control fixture contracts before R3b consumes them. Additional family contracts can follow independently; each receives its own reviewed fixture/algorithm checkpoint before R4b execution.
- [ ] For each applicable family, write its concrete reconstruction/generation recipe and expected hashes into the descriptor before its product adapter task starts. Run the corresponding actual proof with R3 providers; `ValidateBuildable` must accept only that proven family/variant. Do not substitute generic MSDelta support for PSF/CIX/base/encryption proof. Missing real corpus means that family remains an explicit research blocker; do not invent hashes or algorithms to make this plan appear executable.
- [ ] Run the focused tests and family proof cases; record source-family/target coverage and residual unknowns. Split additional formats into explicit adapter tasks with exact files/tests before marking the census complete.
- [ ] Review and commit as `test: define source-family reconstruction contracts`.

## Task R5: make verified provider acquisition operational

**Files:** Extend `internal/tools/{manifest,selection,manager,acquisition,verification}.go` and tests; add `internal/tools/{capabilities,setup}.go`, `manifests/v2.json`, route-specific acquisition files and matching tests; update acquisition/notices documentation.

**Interfaces:** Keep `Manager.Ensure(ctx, Requirement, Emit) (Toolchain, error)`. Extend `Options` with `Runner windows.ProcessRunner`. Add `Requirement.Source model.SourceIdentity`, `SourceFamily string`, and `RuleDigest string` for source-specific operations. Schema 2 has reviewed capability records binding these inputs, native provider closure, operations and prerequisites to R3/R4 proof. Product capability data is trusted with the manifest; it does not import probe packages or accept user-supplied evidence/readiness flags. Schema 1 remains a non-operational candidate catalogue.

- [ ] Add `TestEnsureReturnsOnlyProvenOperationalToolchain` (`len(chain.Files()) > 0` only for a matching accepted tuple); `TestEnsureRejectsSourceGenerationMismatch`; `TestEnsureAcquiresCompleteMicrosoftChain`; `TestEnsureRechecksCachedCompanionsAndPrerequisites`; `TestSetupRestartAndCancellationAreExplicit`; and `TestCandidateManifestCannotAuthorizeExecution`. Preserve digest, notice, extraction-containment, version-coexistence and unknown-target tests.
- [ ] Run `go test ./internal/tools -count=1`; expect operational success tests to fail against the current refusal-only manager.
- [ ] Implement the exact vendor ZIP/MSI/CAB/system-provider routes accepted in R3, complete companions/notices and required setup. Use the existing FetchOne/workspace/runner boundaries and trusted fixed package pins. Validate adequate installed providers rather than overwriting host DISM. Recheck bytes/prerequisites before exposing immutable tool paths; serialize setup where required. Cancellation/restart/repair is an explicit result, never an operational toolchain.
- [ ] Rerun focused tests and the actual clean-machine acquisition probe. A passing synthetic ZIP test cannot replace successful application-managed provisioning for required operations/targets. Run all three Windows builds.
- [ ] Review and commit as `feat: provision proven operational imaging providers`.

## Task R6: supply production semantic metadata and app discovery

**Files:** Create `internal/source/{discovery,app_discovery}.go`, `internal/metadata/providers/{cab,wim,appx}.go` and tests; extend `metadata/{inventory,roles,apps,sourcefamily}.go` and source tests; extend `internal/app/source.go` at its composition point.

**Interfaces:** Add `source.Discovery` with `Metadata(ctx context.Context, selection model.Selection) (MetadataPlan, error)` and `Apps(ctx context.Context, selection model.Selection, inv metadata.Inventory, sets []SourceSet) (AppDiscovery, error)`. Add `source.NewDiscovery(catalog Catalog, providers DiscoveryProviders) (*Discovery, error)`. Define `ProviderFactory func(model.SourceIdentity, model.PayloadManifest) (metadata.ReadOnlyProvider, error)` and `DiscoveryProviders` with `CAB`, `WIM`, `Appx` factory fields. These factories capture the R5 tool/runner lifetime and construct source-scoped providers, so every returned semantic assertion can bind the exact source and container manifest. Wire discovery methods into the existing resolver callbacks, retaining `NewSourceManager` refresh binding.

Extend producer-owned app evidence with `AppPackage.PackageFamilyName string`. Define `LicenseRequirement` values `required`, `not-required`, `unknown`; `AppPolicy` contains `Family AppFamily`, `PackageFamilyName string`, `Required bool`, `Default bool`, `LicenseRequirement LicenseRequirement`, and `Evidence Evidence`. Define `AppInventoryEvidence` with `Phase AppPhase`, `Empty bool`, and `Evidence Evidence`; nil evidence means inventory completeness is unexamined. Add `AppInventory.Policies []AppPolicy`, `AppInventory.Completeness *AppInventoryEvidence`, and corresponding `ProviderResult.AppPolicies`/`AppCompleteness` producer fields. Validate source/document binding, contradictions and agreement with inspected packages; a completeness flag without actual source inspection cannot establish semantics. R13/R16 consume these exact types.

- [ ] Add `TestProductionDiscoveryReadsBoundContainerMetadata`, `TestProductionRolesSurviveRenamesAndIndexPermutation`, `TestProductionAppFamilyLicenseAndPhaseAreSourceBound`, `TestProvenEmptyAppsDifferFromUnexamined`, `TestNoLicenseRequiredNeedsEvidence`, `TestUnknownLayoutRetainsDownloadableManifest`, and `TestRefreshCannotChangeDiscoveredRevision`. Assert exact source/manifest bindings, actual member hashes, stable verified package-family names and preserved requested unsupported choices.
- [ ] Run `go test ./internal/source ./internal/metadata/... ./internal/app -count=1`; expect missing production-producer and policy failures.
- [ ] Implement bounded read-only CAB/member, WIM/resource/image and APPX/MSIX/bundle inspection with verified providers; retain original document identity and source roles. Bind composition package/resource graphs and derived edition bases through R4 rules. Match license and family identities from actual data. Replace unconditional unresolved-policy gaps only when the corresponding source evidence/rule resolves them; an actually empty app inventory or a license not required must be representable without pretending unexamined input is complete.
- [ ] Preserve frozen available payload manifests even when semantic discovery is incomplete or the source is update-only, so the later explicit download-only action can work. Use advertised APP/APP_MOMENT only where supported; otherwise declare and later perform source-specific post-materialization app inspection. Do not infer families from filenames or claim API app-set success for an unadvertised selector.
- [ ] Run focused tests and actual representative small-metadata walks. Re-run live API checks serially with bounded pacing and respect Retry-After; record rate limits/failures. Do not weaken bounded retries merely to obtain a green live run. Native discovery/app/source-generation acceptance needs real source material, separately from endpoint success.
- [ ] Review and commit as `feat: discover real semantic UUP and app metadata`.

## Task R7: implement canonical and reference source normalization

**Files:** Create `internal/engine/source/{adapter,registry,types,canonical,references}.go` and matching tests. Consume R4's real descriptors instead of copying research artifacts into product resources.

**Interfaces:** Define `Adapter.Match(metadata.Inventory) (Match, error)`, `Adapter.Recipe(metadata.Inventory, model.ResolvedSettings) (Recipe, error)`, and `Adapter.Normalize(context.Context, NormalizeRequest, model.Emit) (NormalizedSource, error)`. `NewRegistry(adapters ...Adapter) (*Registry, error)` rejects conflicting matches. `Recipe` fixes adapter/family/rule identities, required payload/resource identities and native operation requirements; it imports no planner. `NormalizeRequest` carries manifest, semantic inventory, `download.Materialized`, verified `tools.Toolchain`, effective settings and `*jobstore.Transaction`. `NormalizedSource` returns source/manifest/rule identity and inspected output/resource identities.

- [ ] Add `TestReferenceResolutionUsesContentIdentity`, `TestCanonicalNormalizationPreservesResources`, `TestMissingResourceCannotCommit`, `TestReferenceVariantMatchesDescriptor`, and `TestCanonicalPreservesACLStreamsLinksAndReparsePoints`. For each R4 fixture assert `actualSHA256 == descriptor.ExpectedSHA256`; missing/wrong resources yield no checkpoint, and permuted filenames cannot change matching.
- [ ] Run `go test ./internal/engine/source -run 'Test(Reference|Canonical|MissingResource)' -count=1`; expect missing implementation failures after the minimal test package exists.
- [ ] Implement exact proven canonical compression/image and non-standalone reference variants. Resolve the entire resource graph by immutable identity, apply/export/capture through accepted providers, and preserve Windows metadata. Reject unimplemented variants explicitly. A research Foundation package, located stream hashes or a successful WIM export alone is not full desktop normalization.
- [ ] Rerun focused tests and actual complete source reconstruction fixtures with independent output/content/security checks. Return stage-owned results only after inspection. The stage caller commits validated outputs; never mutate an earlier committed checkpoint.
- [ ] Review and commit as `feat: normalize canonical and reference UUP sources`.

## Task R8: implement the proven differential source variants

**Files:** Create `internal/engine/source/{express,psf,cix}.go`, variant-specific files named by R4 and matching tests. Modify only the coordinator-owned adapter registration points.

**Interfaces:** Implement R7's `Adapter` contract. Each variant fixes its own adapter/rule identity and accepts only its R4 container/index/base-mode contract; downstream normalized outputs keep the same `NormalizedSource` representation.

- [ ] Add `TestReconstructionMatchesExpectedSHA256` (`got == fixture.ExpectedSHA256` for every accepted variant); `TestWrongDeltaBaseFailsBeforeCommit`; `TestCIXBoundsAndTraversalRejected`; `TestBaselessProofDoesNotAuthorizeBaseDependentDelta`; and `TestForwardReverseAndNullModesUseDeclaredBases`. Corrupt indices, oversized lengths, missing base resources and hash mismatch produce no reusable stage.
- [ ] Run `go test ./internal/engine/source -run 'Test(Reconstruction|WrongDelta|CIX|Baseless|ForwardReverse)' -count=1`; establish relevant failures for the selected variant.
- [ ] Implement only the concrete versioned algorithms established in R4, including complete base closure and output identity checks. Generic archive expansion, generic MSDelta availability or empty-base success cannot authorize unrelated PSF/CIX behavior. Use a narrow helper only with R3/R5 acquisition, native dependency and use/distribution proof.
- [ ] Run the exact focused tests and the actual reconstruction proof for that variant. Repeat this test/review/commit cycle separately for materially different baseless, base-dependent and later container generations; keep all remaining applicable variants visible as incomplete tasks.
- [ ] Review and commit accepted variants individually as `feat: reconstruct <proven-variant> UUP sources`.

## Task R9: implement encrypted ESD and ESRP delivery separately

**Files:** Create `internal/engine/source/{encryption,esrp}.go`, matching tests and sanitized descriptors. Add the runtime key-provider field to R7's request through coordinator review.

**Interfaces:** Both paths implement R7's adapter contract with distinct rules. Add `KeyProvider.WithKey(ctx context.Context, identity model.EncryptionIdentity, use func([]byte) error) error` and `NormalizeRequest.Keys KeyProvider`; the provider validates the expected fingerprint and scopes key use to the callback. Keys are not fields of manifests, ReadyPlan, checkpoints or public DTOs.

- [ ] Add `TestEncryptedSourceRequiresVerifiedMaterial`, `TestDecryptedPayloadMatchesExpectedIdentity` (`plaintextSHA256 == descriptor.ExpectedSHA256`), `TestESRPOffsetsAndFinalBlocksMatchFixture`, `TestWrongKeyFingerprintNeverCommits`, and `TestKeysNeverEnterReports` (serialized plan/journal/report excludes the fixture secret and signed locators).
- [ ] Run `go test ./internal/engine/source -run 'Test(Encrypted|Decrypted|ESRP|WrongKey|Keys)' -count=1`; establish variant-specific behavioral failures.
- [ ] Implement the two actual formats from their independent R4 ciphertext/key/plaintext fixtures, including range/chunk/segment boundaries and integrity checks. Obtain runtime material through the proven acquisition contract. Do not treat ESRP delivery decryption as proof for encrypted ESD segments or persist plaintext secrets in a frozen snapshot.
- [ ] Run focused and actual encrypted-source reconstruction checks. If a variant still lacks authentic input/key/expected-plaintext proof, retain its explicit blocker instead of substituting synthetic acceptance. Independently review/commit each accepted format.
- [ ] Commit as `feat: normalize <encrypted-format> UUP payloads`.

## Task R10: add the immutable planner and preflight boundary

**Files:** Create `internal/planner/{types,resolve,dependencies,applicability,space,freeze}.go`, matching tests and versioned rule fixtures; extend shared contracts through coordinator review.

**Interfaces:** Implement `(*Planner).Resolve(ctx context.Context, req Request) (ReadyPlan, error)`. `Request` contains `Selection model.Selection`, `Settings model.ResolvedSettings`, `Resolution source.Resolution`, `Host model.Host`, `DraftRevision uint64` and `Intent JobIntent`. Define `JobIntent` values `BuildMedia` (`build-media`) and `DownloadOnly` (`download-only`) so update-only/partially available sources can explicitly download verified payloads through the same Start contract.

`ReadyPlan` has private state and deep-copy getters: `Selection() model.Selection`, `RequestedSettings() model.ResolvedSettings`, `EffectiveSettings() model.ResolvedSettings`, `Manifest() model.PayloadManifest`, `Operations() []Operation`, `Tools() []tools.Requirement`, `Applicability() []model.SettingApplicability`, `Estimates() Estimates`, `DraftRevision() uint64`, `Intent() JobIntent` and `Digest() string`. Producer-owned `Estimates` uses `int64` sizes/peak-space counters and explicit known/estimated status. Add `MarshalTOML() ([]byte, error)` and `DecodeReadyPlan([]byte) (ReadyPlan, error)` for validated frozen snapshots. `Operation` is a typed dependency node with fixed kind, input/resource/role identities, rule identity and operation-specific parameters, never a command string. R12/R13 extend its typed variants.

- [ ] Add the original E2 tests for unsupported explicit policies, base/final edition distinction, deep copies, tool/rule/graph digests, >4 GiB accounting and host-independent targets. Add `TestDownloadOnlyAcceptsAvailableUpdatePayloads` (download operations exist and no assembly/mastering operations exist), `TestUnknownFamilyCannotCreateMediaPlan`, `TestPlanRoundTripRetainsIdentityWithoutLocators`, `TestDeferredAppValidationPrecedesCustomization` (barrier precedes every app mutation) and `TestPreflightUsesActualScratchAndDestinationFilesystems`.
- [ ] Run `go test ./internal/planner -count=1`; establish expected contract failures.
- [ ] Resolve source dependency/base closure, all explicit/auto policies, provider capabilities, operation ordering, output naming/order, elevation, locks and measured versus estimated storage. Evaluate the selected scratch/cache/output volumes, not merely the launch directory's filesystem. Hash canonical source/settings/tool/rule/graph identity. Checkpoint identity later binds actual predecessor output digests; the pre-execution plan cannot invent hashes for outputs not yet produced.
- [ ] Allow a declared post-materialization app inspection/validation operation where source rules require it. Review must identify conditional applicability; the frozen graph pins the requested policies, validator/rule version and barrier. Failure at that barrier cannot silently change the plan or proceed to customization/publication. Invalid explicit choices detectable during preflight fail before any mutating stage.
- [ ] Rerun planner tests plus `go test ./internal/source ./internal/model -count=1`. Demonstrate that caller edits, changed URLs and serialization do not change a frozen plan; changed identities/rules/tools do. A download-only completion is labeled downloaded source material and never an ISO/conversion success.
- [ ] Review and commit as `feat: freeze complete conversion and download plans`.

## Task R11: assemble source-matching contents for the ISO

**Files:** Create focused `internal/engine/{types,assembly,mediatree}.go`, tests and actual source descriptors. Add source boot-image handling only as needed for the normal files inside the ISO; no WinRE feature or separate installation-media workflow.

**Interfaces:** Preserve `Assembler.Assemble` with ReadyPlan, normalized source, toolchain and current transaction. BaseImages binds actual image/edition/source identities and internal ISO contents.

- [ ] Test source/build/architecture/language/edition matching, ACL/stream/link/reparse preservation, no foreign executable launch, wrong-image rejection and missing-resource failure.
- [ ] Assemble actual Windows image and Setup files for the ISO from the selected source. Preserve source filesystem semantics with proven providers. Do not substitute files from another build.
- [ ] Inspect actual resulting image contents and security/resource identities. No VM/hardware boot, Setup execution, WinRE construction or recovery acceptance is required.
- [ ] Review and commit the validated ISO-content assembly.

## Task R12: implement generation-specific updates and edition derivation

**Files:** Create `internal/planner/{servicing,editions}.go`, `internal/engine/service/{types,executor,updates,editions,cleanup}.go`, `internal/engine/rules/{registry,updates,editions}.go`, matching tests and fixtures.

**Interfaces:** `planner.BuildServicePlan(metadata.Inventory, model.ResolvedSettings) (planner.ServicePlan, error)` and `(*service.Executor).Execute(ctx context.Context, req ServiceRequest, emit model.Emit) (ServicedImages, error)`. `ServicePlan` is a typed dependency graph incorporated in ReadyPlan before it is frozen. ServiceRequest carries that plan, validated input images, toolchain and transaction. Rules return data/operations and do not invoke tools.

- [ ] Add `TestCheckpointUpdatesRequirePredecessors` (dependency order equals the actual generation fixture); `TestExternalUpdatesRemainOutsideImages`; `TestOmittedUpdatesDoNotEnterMedia`; `TestEditionDerivationPreservesDifferences`; `TestCleanupResetBaseFollowGenerationRules`; and `TestFinalEditionInventoryMatchesPlan` (inspected final identities/order match requested outputs, without forcing temporary bases into final indices).
- [ ] Run `go test ./internal/planner ./internal/engine/service ./internal/engine/rules -count=1`; establish named failures.
- [ ] Implement proven servicing-stack/cumulative/checkpoint/MSU/enablement ordering, expansion/preservation policies, per-edition/shared-base strategy, actual edition derivation, cleanup/reset-base applicability and reference/temporary-base retention. Cover legacy and newer servicing generations through R4 rules; explicit unsupported choices fail rather than being ignored.
- [ ] Run focused tests and actual changed-image package/edition inspection. Missing required packages fail despite process exit zero. Split materially different generation implementations into independently reviewed fixture-backed commits.
- [ ] Review and commit as `feat: service updates and derive validated editions`.

## Task R13: implement app, feature, driver and Edge policies

**Files:** Create focused planner/service/rule files for apps, features, OS/WinPE drivers and Edge; no recovery/WinRE service or rule files.

**Interfaces:** PlanApps/PlanDrivers/PlanFeatures consume source-bound inventory and resolved settings and produce typed operations for the existing executor. Preserve deferred app validation before customization.

- [ ] Test actual app dependency/resource/framework/license closure, requested unsupported choices, legacy phases, default/custom/none/preset/stub/full modes, NetFx3 applicability and distinct OS/WinPE driver targets.
- [ ] Implement those supported policies using source-specific rules. Preserve schema-1 parsing; excluded recovery choices are explicit unsupported settings, not silent success.
- [ ] Independently inspect requested/effective app/feature/driver state in actual image outputs. No recovery-image work or installed-OS boot test is required.
- [ ] Review and commit the scoped customization policies.

## Task R14: create, verify and publish the ISO file

**Files:** Create focused `internal/engine/output/{types,export,master,verify,publish,report}.go` and tests. Reuse the existing ISO/UDF inspector through an internal package when needed; preserve existing parser corruption/bounds coverage without expanding a boot-test campaign.

**Interfaces:** Keep Prepare/Verify/Publish and a VerifiedArtifact that only actual content verification constructs. The deliverable is ISO only; WIM/ESD/SWM handling is internal to its Windows image contents, not a standalone output mode.

- [ ] Test wrong/truncated contents, >4 GiB data, exact source/image/edition identities, output hashes and destination-copy failures.
- [ ] Build the normal Windows ISO filesystem with source-matching Setup/image files and required source records. Do not add USB/DVD/physical-disk writing, burning, OS installation or a separate installation-media workflow.
- [ ] Independently inspect the ISO filesystem, required file bytes, image/edition/app contents and large-file representation. Report bootability as untested; boot/Setup execution is not an acceptance gate.
- [ ] Publish from a verified local artifact and recheck copied destination bytes. Never overwrite unrelated output; retain the valid local ISO on copy failure. No crash/restart publication-recovery feature is required.
- [ ] Produce SHA256 and a redacted report of source/settings/tools and actual checks; review and commit.

## Task R15: execute ISO build jobs through the constrained worker

**Files:** Create focused `internal/jobs/{controller,state,events,cancel,persist}.go` and `internal/worker/{protocol,validate,dispatch,entry}.go`; extend existing app entry/composition. No startup recovery index, restart-discovery or replay project.

**Interfaces:** Retain Start(ReadyPlan), Cancel and needed same-run event/download controls. Recover/List/Discard and restart recovery are not required by the amended scope. Worker.Descriptor still aliases the existing authenticated Windows bootstrap; no arbitrary commands or independently supplied operation graph.

- [ ] Test altered plans, unknown operations/peers, one conversion at a time, intent before mutation, safe cancellation, owned-resource cleanup and false-completion rejection. Reuse downloader pause/resume/cache behavior without adding job-restart recovery.
- [ ] Bind private active-job plan/config/source/rule/tool identities and capability handles needed by the elevated worker. Keep tokens/credentials/locators out of shareable plans/reports.
- [ ] Compose real source/download/tool/stage producers and J1 transactions. Independently validate stage outputs before commit; helper exits/events alone do not mean success.
- [ ] Authenticate exact peer/executable/workspace/plan and fixed typed handlers. On failure release only resources created by the active operation; unknown state is preserved and reported. Do not reopen or resume interrupted jobs.
- [ ] Connect the minimum existing application action needed to run a validated ISO build and show its result/error. No new Review/Start/progress screens or terminal-behavior work replaces removed R17.
- [ ] Check actual authorized worker execution and ISO publication, then review and commit. No recovery/restart or boot tests.

## Task R16: move app-editor TUI work ahead of backend completion

**R16s — current first priority: match the accepted Workspace style.** Use the user's 2026-10-29 screenshot and the Workspace variant at `C:/Users/owner/.codex/visualizations/2026/10/27/01a17b69-703d-7eb2-85fd-9d3102de76fa/uup-builder-layouts.html`. Implement in Charm/Lip Gloss: full dark-purple canvas, muted dividers, filled active sidebar/build rows, bordered fields/actions, strong content headings, generous row spacing, sidebar metadata and bottom action/footer areas. Keep actual live data, exact selection, async behavior and TOML actions; never copy sample catalog/app data or simulated progress. Keep narrow layouts usable. Versioned detailed implementation brief/steps are in this plan's SDD workspace `task-R16s-style-brief.md`.

- [x] Update focused layout/theme files and existing navigation/hit geometry where necessary; test resized hit targets and preserve all working settings/discovery behavior.
- [x] Make the visible View TOML control a real read-only view of the current draft, without writes or draft changes.
- [x] Run focused rendering/navigation checks and final appropriate verification; independent review; build and open a fresh styled preview for user testing. Do not alter the user's Windows Terminal settings.

Status: completed and independently reviewed at `236680d`; the styled native preview is open for user testing.

**R16a — next implementation priority:** Reuse completed R1 startup and R2 typed editors; deliver an interactive preview immediately. Implement the app-editor view/state/navigation against existing typed AppInventory/AppSettings contracts before resuming native provider research. Unit fixtures may test rendering, but the running preview must display unavailable/unexamined data honestly and never fabricate selectable app/source records.

**Files:** `internal/tui/apps.go`, focused tests/goldens and existing area registration. Keep the original R17 review/progress/recovery/terminal project removed.

- [ ] Publish/launch the current real TUI preview so the user can test Builds, Image, Conversion and TOML actions now.
- [ ] Implement search/toggles/default/custom/none/preset/stub/full interactions and explicit unresolved/deferred inventory states. Preserve family identities and draft revisions; existing schema-1 settings remain readable.
- [ ] Exercise the preview with the user before more backend/provider work; fix concrete UI feedback first. No fake controller or invented app metadata.

**R16b — later data integration:** After R6/R13 provide real policies/inventory, bind app-family/dependency/license/phase/applicability state to the same editor. Validate actual source-backed behavior and requested/effective choices then. This later dependency must not block the early TUI preview.

## Task R17: removed by user on 2026-10-29

The dedicated Review/Start/progress/recovery screens, subscription/display project, terminal-mode expansion and console-acceptance campaign are excluded. Do not schedule this task or count it as implemented. Existing completed TUI behavior remains. R15 retains only the minimal connection needed to execute a validated ISO build.

## Task R18: verify the reduced scope and package native executables

**Files:** Focused conversion/content/release/clean-machine tests, compatibility evidence, release docs/workflow and checksummed Windows386/amd64/arm64 executable bundles. No recovery or boot integration suites.

**Interfaces:** ValidateReleaseEvidence uses the existing case/evidence producer with an explicit reduced requirement set. Preserve strict historical validators/records; never relabel excluded boot/recovery evidence as passing. Three architecture builds remain a separate gate.

- [ ] Test missing required conversion/source/provider/content evidence, unsupported ISO families, skipped/unconfigured remaining checks, wrong applied-image state and stale tool/plan identities. Bootability/recovery are excluded from the required set.
- [ ] Exercise actual source-family conversion, customization, ISO contents, Unicode/spaces, chosen filesystems/destinations, low-space failure and necessary active owned-resource cleanup. Keep clean-machine provider provisioning and non-admin browsing checks.
- [ ] Do not boot VMs/hardware, execute Setup/install an OS, test WinRE or add job-restart/recovery/terminal campaigns.
- [ ] Run appropriate ordinary tests/vet, available race checks, three CGO-disabled Windows builds, required live/source/provider/corpus and large-transfer checks for the remaining scope. Record actual failures/skips; no new physical x86/ARM64 hardware blocker.
- [ ] Produce local executable/checksum/notices bundles and truthful ISO-content compatibility reports. Fresh whole-product reviews cover the reduced scope; external publication remains a later action.

## Milestones and completion criteria

| Milestone | Concrete acceptance |
| --- | --- |
| Runnable browsing/configuration | R1/R2 accepted; real executable opens the existing Workspace and saves/loads typed config with backups. This milestone does not claim image creation. |
| Proven provider/source foundation | R3/R4/R5/R6 accepted for the selected first family; real provider operations and semantic discovery pass, with incomplete families retained explicitly. |
| First complete build | R7/R10-R15 produce a verified source-matching ISO using real providers. R16a is available for early UI testing; R16b supplies actual app data later. No recovery or boot test. |
| Complete requested product | R8/R9 and every additional R4 family task complete; all in-scope editors/settings work; R18 validates conversion/ISO-content/clean-machine/source coverage and produces all three executables. R17/recovery/bootability testing remain excluded. No required functional gap is waived by compilation or the architecture amendment. |

## Plan self-review

- [x] All original task IDs mapped to implemented, partial or missing components with current-file evidence.
- [x] Fresh ordinary tests, vet, three builds, platform integration, live API outcome, provider gate failure and corpus skip recorded separately.
- [x] Completed foundations are reused; no new bootstrap/module/config/downloader/journal rewrite is scheduled.
- [x] Missing production source/app discovery and refusal-only tool acquisition are explicit tasks rather than being hidden inside UI wiring.
- [x] ISO conversion, generation rules, in-scope customization, active worker execution and reduced release evidence have owners; removed recovery/R17/boot-test/output-mode work is explicit.
- [x] Existing concrete producer types, source/locator separation and private workspace capability boundaries are preserved; new producer contracts are defined before consumers.
- [x] Every Review Focus item is covered by named behavior checks in its owning tasks.
- [x] The one-host architecture amendment is preserved without reclassifying failed/unverified functional evidence as support.
- [x] Execution authorized through the user's SDD invocation; scope/order amended on 2026-10-29. Completed work is tracked in the plan ledger.
