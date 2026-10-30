# UUP Builder User Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This is the sole active development plan; rewriting it does not implement its tasks.

**Goal:** Let a user choose a source, choose apps and conversion settings, and build a verified Windows ISO through the existing Charm Workspace, starting by fixing app-loading rate limits.

**Architecture:** Reuse the working Go application, configuration, discovery, download, Windows and metadata foundations. Complete the user journey in order; implement source/provider capabilities within the workflow step that needs them. First connect one real end-to-end conversion, then extend that same path to every required source family.

**Tech Stack:** Go `1.27.0`; the dependency versions pinned in `go.mod`; Bubble Tea v2, Bubbles v2, Lip Gloss v2, go-toml/v2 and x/sys; individually managed native providers.

**Spec:** [Accepted product design](../specs/2026-10-27-uup-builder-design.md), amended by the [current scope and workflow decisions](../../engineering/2026-10-29-scope-amendment.md), [host proof policy](../../engineering/host-proof-policy.md) and [producer contracts](../../engineering/contracts.md). Existing producer code is the authority for implemented signatures.

**Baseline:** Reconciled against `master`, `02c52364f79f358324990eca37408695618b60d7`, on 2026-10-29. This replan inspects the integrated checkout, not worktree-only experiments. Earlier test results are historical evidence, not fresh verification of this plan.

## Global Constraints

- Go implementation with a Charm TUI; preserve the accepted purple Workspace layout and the completed keyboard/mouse behavior.
- One executable for the user to download and run. Helpers may be extracted or downloaded behind the scenes, with the app managing their complete lifecycle.
- Use TOML for application configuration. Preserve schema version `1`, default path `%LOCALAPPDATA%/UUPBuilder/config.toml`, `parallel_files=4`, `retries=5` and `split_size_mib=3800` without a separately reviewed migration.
- Keep the Go `1.27.0` baseline and dependency pins. Add dependencies only for a demonstrated missing operation with primary-source justification.
- Treat the original downloader, scripts, INI and app-list files as guidance. Do not execute, modify, import or ship them as product resources. The conversion engine is Go calling individual tools directly.
- Cover all builds available in UUP Dump. Keep every advertised target available on every supported Windows 10+ host; do not hide targets because an adapter/provider is unfinished.
- One job builds one architecture and one language, with one or more editions. Run one conversion job at a time, with parallel network transfers.
- Deliver an ISO file. WIM/ESD/SWM are internal representations for its contents. Recovery/WinRE work, the former R17 Review/Start/progress/terminal project, boot/Setup execution tests, physical-media writing and standalone image/directory deliverables remain excluded.
- Existing schema-1 settings remain readable; omitted features must not be represented as supported. Keep active-operation ownership, authorization, cancellation and cleanup of resources created by that operation.
- Complete functionality on the available native Windows host plus successful Windows `386`/`amd64`/`arm64` builds satisfies host-architecture acceptance. Preserve the nine logical common pairs and actual observed host facts; additional physical hosts are optional.
- A skipped, failed or unconfigured functional check is not a pass. Provider candidates, synthetic fixtures and cross-builds alone do not prove conversion support.

## One plan and one order

The five previous development plans have been replaced by this document, including their stale checkboxes, parallel lane schedules and provider-first execution order. Do not resume an old task brief as an independent work queue. Keep implementation, compatibility records, feasibility findings and private research artifacts as evidence; deleting a plan does not discard that evidence or make an unsuccessful experiment pass.

| Order | User reaches | Development task | Demonstrable result |
| --- | --- | --- | --- |
| 1 | Apps currently fails while loading | U01 — fix rate limiting first | Real app loading respects the supplied upstream limiter |
| 2 | Builds → Image | U02 — close selection gaps | Exact build/revision, architecture, language and editions survive the journey |
| 3 | Apps | U03 — finish app selection | Source-offered requests, presets and deferred states behave consistently |
| 4 | Conversion → saved configuration | U04 — finish settings and output choices | A complete, validated ISO request can be saved and loaded |
| 5 | Invoke build from Conversion | U05 — freeze and validate the request | One immutable plan, explicit blockers and controlled dispatch |
| 6 | Download required inputs | U06 — connect managed preparation | Verified payloads and required tools are prepared automatically |
| 7 | Build the Windows image | U07 — reconstruct and assemble the first real source | Source-matching internal ISO contents, independently inspected |
| 8 | Apply chosen updates and editions | U08 — service images | Requested policies and final edition order match inspected images |
| 9 | Apply chosen apps, features and drivers | U09 — customize images | Effective image state matches the user's supported choices |
| 10 | Receive the ISO | U10 — create, verify and publish | ISO, SHA-256 and truthful report at the chosen location |
| 11 | Choose other source generations | U11 — extend the same completed journey | Every required ISO-capable source family works through that path |
| 12 | Download and run the released app | U12 — release acceptance | Clean-machine workflow and all three Windows executables verified |

The rate-limit defect is the explicit first priority. U02 is a focused closure/acceptance task around existing behavior, not a rewrite. U01–U04 must remain usable before conversion/provider development resumes. U05–U10 are one connected conversion slice: preparation, assembly, servicing, customization and publication register into the same planner/controller as each arrives. A missing handler blocks execution explicitly; it never produces simulated completion. U11 expands coverage after the first ISO without weakening the final all-build requirement.

## Current state to retain

| Integrated work | Reuse | Remaining owner |
| --- | --- | --- |
| Real executable startup, typed TOML, save/load/backups, styled Workspace | `internal/app`, `internal/config`, `internal/tui` | U02–U04 only close concrete gaps |
| Grouped build rows retaining actual architecture sources; Space selection; stale-response rejection | `build_groups.go`, `image.go`, `navigation.go`, `model.go` | U02 |
| Source-backed app request list, neutral app lookup, verified small CAB, search/toggles/default/custom/none/stub/full | `internal/source/app_catalog*.go`, `internal/metadata/app_compdb.go`, `internal/tui/apps.go` | U01/U03; semantic applicability U06/U09 |
| API parsing/retries/cache; immutable manifests and locator refresh; verified resumable downloads and proxy | `internal/catalog`, `internal/source`, `internal/download` | U01/U06 |
| Windows workspaces/processes/elevation/IPC, active-operation intent and checkpoints | `internal/platform/windows`, `internal/jobstore` | U05/U06, then real stage integration |
| Metadata parsers, provider manifest/leases, source census and native component observations | `internal/metadata`, `internal/tools`, `tests/probes`, `docs/feasibility` | U06/U07/U11; these do not yet establish working production conversion |
| Missing production semantic discovery, operational tool acquisition, engine/planner/controller/worker/output | No completed implementation to claim | U05–U11 |

Legacy task names are historical cross-references only: R1/R2/R16s/R16k/R16g and the early R16a app slice are retained completed work. R16 preset/data gaps map to U03/U09; R10/R15 to U05; R3–R6 to operation-specific U06/U07/U11 work; R7–R9/R11 to U07/U11; R12/R13/R14/R18 to U08/U09/U10/U12. R17 remains removed, not completed. No new WinRE experiment or native-control preparation precedes U01–U04.

## Review Focus

1. The supplied limiter is shared by client IP and a too-fast same-resource attempt updates its timer: U01 must test concurrent clients, retries and cancellation against that exact state machine.
2. A changed source/endpoint or a legacy deferred app inventory must not silently change app requests: U02/U03/U09 test stale results, retained unresolved requests and the pre-customization validation barrier.
3. Candidate tools or a successfully decoded CAB do not establish compatible image operations: U06/U07/U11 test source/rule/provider closure and preserve distinct unsupported-source versus missing-implementation diagnostics.
4. Changing a draft, tool, workspace or predecessor after planning must not authorize different mutations: U05/U07 test immutable identities, exact peer/handler dispatch, active ownership and conservative cancellation.
5. Helper exit zero, a plausible media tree or a partial destination copy is insufficient: U07–U10/U12 inspect real contents/security metadata and verify final local and destination bytes.

## U01 — Apps loads reliably under the actual get.php limiter

**Status:** Complete, U01 only authorized and implemented on 2026-10-29. Baseline defects: `SourceAppCatalog` used a private `500 ms` interval; other clients and endpoint recomposition did not share that gate. Apps inherited `45 s`/`2 min` whole-load deadlines. Regression tests reproduced the rate-limit and timeout failures before implementation.

**Files:** Modify `internal/catalog/{client,retry,files}.go`, their tests, `internal/source/app_catalog_windows.go`, `app_catalog_test.go`, `internal/app/{interactive,interactive_apps_windows}.go`, `internal/tui/{services,apps,config_actions}.go` and focused tests. Create `internal/catalog/{pacing,pacing_test}.go`. Update `internal/source/testdata/upstream-contract.md` with the supplied contract and what was actually verified.

**Interfaces:** Preserve `catalog.New`, `Client.Files` and `source.AppCatalog.Load`. Add a concurrency-safe `catalog.GetPacer`, `NewGetPacer(clock Clock) *GetPacer`, `(*GetPacer).Do(ctx context.Context, send func(context.Context) (*http.Response, error)) (*http.Response, error)`, and a configurable `Client.Pacer *GetPacer` port configured before use. Default catalog clients for the same service namespace share a process-wide pacer; isolated tests inject one. The pacer owns cancelable admission and server cooldown state around each actual `get.php` HTTP attempt, including retries. Acquire admission with the caller's cancellation context before constructing the bounded per-attempt HTTP timeout inside `send`; waiting in a queue must not consume that network timeout. Payload CDN transfers use their own origin's retry policy.

The user's supplied PHP function, with default arguments, is the behavioral specification:

| Attempt | Result and state |
| --- | --- |
| A different resource before `lastAccess + 10 s` | Rejected; stored resource/time are unchanged |
| Same resource before `lastAccess + 1 s` | Rejected **after updating** stored resource/time |
| Allowed request | Stored resource/time are updated |
| Another application behind the same public IP | Shares the server state; an in-process client cannot reserve that IP globally |

**User follow-up / verified upstream contract:** The user pointed to the JSON wrapper. At [commit c82a95ae6377743f2712ac0bd060e673f4478b0c](https://git.uupdump.net/uup-dump/json-api/src/commit/c82a95ae6377743f2712ac0bd060e673f4478b0c/get.php), the resource is the SHA-1 of the lowercase update/language/edition tuple and the default limiter arguments are used. `noLinks=1` suppresses the limiter rejection, but the limiter is still evaluated first and may update its shared timer. Keep metadata-only requests fast through a shared `GetPacer.DoMetadata` admission path; record their completion so later link-bearing requests remain safe. Serialize link-bearing attempts with `10 s + 250 ms` from the previous get.php attempt completing. Honor longer server cooldowns on both paths. The margin and conservative link policy are implementation choices. A same-resource `1 s + 250 ms` optimization is deferred; U01 does not need it.

- [x] Add a deterministic local server/fake-clock model of the supplied PHP behavior. Assert: `A@0` succeeds; `B@9.999s` rejects without updating A's timestamp; `A@0.5s` rejects and moves its timestamp to `0.5s`; `A@1.25s` still rejects; a repeat after a full second from the last repeat succeeds; changing resource requires the full ten seconds. Give each scenario fresh state.
- [x] Add `TestGetPacerSerializesClientsAndRetries`, `TestGetPacerRetainsCooldownAfterCancellation`, `TestGetPacerDoesNotReserveUnsentRequest`, and `TestEndpointReloadSharesGetCooldown`. Assert actual send timestamps are at least `10.25s` apart under the conservative policy, queued cancellation sends nothing, and canceling a sent request cannot erase its timing state. Endpoint reload must not create a fresh limiter for the same service.
- [x] Add `TestGetPacerHonorsLongerRetryAfter` covering absent/zero/date/overflow headers and HTTP 429/API `USER_RATE_LIMITED`. A shorter header cannot shorten local pacing; an excessive server delay returns a retry-later diagnostic instead of waiting indefinitely or sending early. Preserve the existing three-attempt catalog bound. Recognize a rate-limit API envelope even when its HTTP status does not advertise retryability; leave permanent errors non-retryable. External-IP contention must still result in bounded backoff and an honest error when exhausted.
- [x] Implement pacing at the actual catalog send boundary, not around `Load` or `Files`. Remove the conflicting app-private fixed-interval scheduler. Do not delay unrelated list endpoints or CDN bodies by the get.php interval. Preserve CDN `Retry-After` behavior separately. Metadata-only calls bypass the interval through the same shared gate and still update timing; online locator refresh and later link-bearing resolver calls wait. Test the wrapper's metadata exemption and timer side effect explicitly.
- [x] Add `TestAppsMultiEditionLoadSurvivesPacing`, `TestAppsSelectionChangeCancelsQueuedLoad` and a no-header rate-limit loading test. Replace Apps' fixed whole-load `45 s`/`2 min` deadlines with the Workspace cancellation lifetime plus bounded per-attempt HTTP timeouts/retries; keep other discovery deadlines. Cancel immediately when selection/endpoint changes or the Workspace closes. Show a truthful waiting/retrying message through the existing Apps status; keep the verified CAB cache and never cache signed get.php responses.
- [x] Run `go test ./internal/catalog ./internal/source ./internal/app ./internal/tui -count=1`. New tests must fail for the old `500 ms` behavior and pass after the change; use fake time for long waits. Run `TestAppsAuthenticMetadataCommandToggleSaveLoad` with its retained-metadata input configured, then one bounded real-source preview load without competing live suites. Record requests, waiting, cancellation and the actual result without retaining signed URLs. Build a fresh preview and demonstrate app loading. Commit the focused fix and update this task's evidence.

**Completion evidence (2026-10-29):** Regression tests were observed failing for the supplied limiter, both whole-load deadlines, explicit-refresh propagation and redirected CAB cooldowns before their fixes passed. Independent review identified the redirected-origin issue; its direct/alternate-origin regressions are now green, with no deferred review findings. Fresh real-source loading returned 50 choices using two metadata-only calls, one paced link call and one verified CAB; the authentic retained CAB/TUI test also exercised toggle/save/load. `go test ./... -count=1`, `go vet ./...` and Windows `386`/`amd64`/`arm64` builds passed after the final code change. One earlier concurrent suite run timed out in `TestResumeWaitsForPendingPause`; that test passed 3/3 isolated repeats and the final complete suite passed. Race checks could not build because `gcc` is unavailable. The rebuilt interactive preview is in `.work/u01-preview/`. App applicability and all later tasks remain pending.

## U02 — Choose the exact build, architecture, language and editions

**Files:** Existing `internal/tui/{builds,build_groups,image,model,navigation,services,config_actions}.go`, matching tests/goldens; `internal/app/{wire,interactive}.go` only where a discovered integration gap requires it.

**Interfaces:** Consume current `Catalog.Search/Languages/Editions`, `model.Selection` and `tui.DraftSnapshot`; preserve `ImageReady` as catalog-selection validation, not build readiness. Produce a source-bound draft revision for U03–U05.

- [x] Exercise the already implemented launch → grouped Builds → Image path with real data. Retain exact UUID/revision per architecture, one language and multiple editions. Fix only observed failures; do not rerun a bootstrap implementation task.
- [x] Extend existing navigation/invalidation tests for build, architecture, language and loaded-endpoint changes. Assert old results cannot restore invalid selections; keyboard Space/Enter and mouse select the same real source; host architecture never filters targets.
- [x] Run `go test ./internal/tui ./internal/app -count=1`, inspect normal/compact existing goldens for affected views, and demonstrate the selected source summary. Record which behavior was already complete and any focused fixes.

U02 evidence (2026-10-29): `TestLiveLaunchBuildsImageSelection` exercises the production first-run startup boundary and Workspace commands against current UUP Dump discovery: 9,184 records / 4,315 grouped versions, all nine logical x86/amd64/arm64 host/target pairs with Enter/Space/mouse (27 passing cases), `en-us`, and two actual editions per target. Normal/compact source summaries retain the selected targets/editions and the normal view shows the exact UUID. Existing grouping, host-independent choices, dependent invalidation and input behavior were already complete. A RED/GREEN regression fixed loaded selections becoming ready before their exact source architecture was verified; endpoint reload coverage rejects old results even for identical UUID/language selectors. Required TUI/app tests, `go test ./... -count=1`, and all four existing Builds/Image goldens pass unchanged. Sanitized source identities, actual views, commands/results and scope limits are in `.superpowers/sdd/2026-10-29-uup-builder-user-workflow-plan/task-2-report.md` and its `task-2-*.log` evidence. No payload requests or native image operations were performed.

## U03 — Finish choosing apps before leaving Apps

**Files:** `internal/tui/{apps,messages,model,config_actions}.go`, focused tests/goldens; `internal/source/app_catalog*.go` and `internal/metadata/app_compdb.go` only for source-request defects; create `internal/tui/app_presets.go` and tests.

**Interfaces:** Keep `source.AppCatalog.Load(context.Context, model.Selection) (source.AppCatalogSnapshot, error)` and `model.AppSettings`. Add an explicit **All offered** selection preset with stable ID `all-offered`: set mode `custom` and include every non-framework main FeatureID offered for at least one selected edition, sorted and deduplicated from the current snapshot. Default and None reuse their existing modes; applying a preset changes requested choices only, not package applicability. Do not invent named app bundles or automatically reapply a preset when sources change. Full semantic applicability is produced in U06/U09.

- [x] Add `TestAppPresetsUseCurrentSource`, `TestAppRequestsSurviveDeferredInventory` and `TestAppModesRoundTripTOML`. Assert All offered excludes frameworks and entries with no selected-edition references, deduplicates IDs and stays unavailable for unexamined metadata. Unknown saved preset/request IDs remain visible and unresolved. Assert default/custom/none, search, individual/select-all toggles, stub/full and preset interactions preserve requested values and draft revisions.
- [x] Implement pending preset controls in the existing Apps area. Keep a source-offered request distinct from a validated installable package; missing/legacy metadata displays deferred/unexamined with a reason, not an empty complete inventory. Preserve current neutral-selector and small verified CAB behavior from U01.
- [x] Run `go test ./internal/tui ./internal/source ./internal/metadata -count=1`; inspect affected normal/compact goldens. Demonstrate choosing apps, moving to Conversion and saving/reloading the same request. Keep `AppsApplicable` false until real semantic validation succeeds.

**U03 evidence (2026-10-29):** New preset/request regressions failed before implementation, then passed, including all nine mode/stub TOML combinations and keyboard/mouse controls at normal, compact and short sizes. The scoped TUI/source/metadata/config/platform tests and `go test ./... -count=1` passed. Inspected normal/compact Apps goldens preserve source choices and the pending-applicability summary. The authentic retained CAB (`55eb250595fc2b56c4a10069cb1b238c4bf163fd4c5d79309a6beb73d6dd66a3`) produced 50 offered families; both All offered and an individual Notepad request survived Apps → Conversion → save/reload unchanged, with `AppsApplicable=false`. The demonstration exposed a native rename buffer termination defect; a separate regression reproduced failed or silently missing publications at short path boundaries, and the minimal terminator repair passed 320 boundary publications plus existing replacement/collision tests. Full report and command logs are in this execution workspace's `task-3-report.md`; semantic installability remains owned by U06/U09.

## U04 — Set conversion, storage and ISO output, then save/load

**Files:** `internal/tui/{conversion,fields,config_actions}.go`, tests/goldens; `internal/config/{defaults,validate}.go` and tests only as needed; `docs/configuration.md`.

**Interfaces:** Preserve `config.Config.Request() (model.Selection, model.ResolvedSettings, error)`, current load/save APIs and typed settings. Structural parsing remains backward compatible; unsupported execution choices become explicit diagnostics in U05, not silent coercions during load.

- [x] Add `TestISOWorkflowRetainsRequestedSettings` and `TestLegacyExcludedSettingsRemainReadable`. Assert image/app/update/edition/feature/driver choices, workspace/cache/output paths and naming survive TOML round-trip. Existing readable `image`/`directory` or recovery values must not imply those deliverables/features are implemented.
- [x] Finish only missing controls needed for ISO output and in-scope settings. Keep unsupported choices visibly explained; reuse existing save/load/validate/view behavior, backup semantics and field diagnostics. Do not introduce a new Review/Progress area.
- [x] Run `go test ./internal/config ./internal/tui ./internal/app -count=1`; check affected goldens and demonstrate a saved, reloaded complete draft. Update configuration documentation for the current scope.

**U04 evidence (2026-10-29):** RED/GREEN regressions establish recovery-free new/omitted defaults, ISO-only output-kind editing and visible excluded-scope explanations that override stale applicability claims. Explicit schema-1 image/directory and recovery values remain unchanged through decode, save, load and request creation (12 legacy combinations). Existing typed controls already covered the in-scope settings; Conversion now labels WIM/ESD/SWM as ISO contents and separates .NET/ISO boot settings from excluded recovery. A complete Workspace draft with two editions, an app request, update/edition/feature/driver policies, proxy/download settings, workspace/cache/output paths and ISO naming was saved to real TOML, deliberately edited, then reloaded and checked against independent expected typed values. Normal/compact scope goldens and existing focused/invalid/long views were inspected. Required config/TUI/app tests and one full `go test ./... -count=1` run passed; the historical intermittent download pause failure did not occur. `docs/configuration.md` now documents the working controls, current defaults and legacy readability. Full report, exact commands/results and actual saved TOML are recorded in this execution workspace's `task-4-report.md` and `task-4-*.log`; executable applicability/blockers remain U05, and no native image operation was run.

## U05 — Validate and freeze the request when the user invokes build

**Files:** Create `internal/planner/{types,resolve,applicability,dependencies,space,freeze}.go`, `internal/jobs/{controller,state,cancel}.go`, `internal/worker/{protocol,validate,dispatch,entry}.go` and tests. Extend `internal/app` and the existing Conversion action boundary, with a small `internal/tui/build_action.go` if needed. Reuse platform IPC/elevation and jobstore ownership.

**Interfaces:** `(*planner.Planner).Resolve(ctx context.Context, req planner.Request) (planner.ReadyPlan, error)` consumes `Selection model.Selection`, requested `Settings model.ResolvedSettings`, `Resolution source.Resolution`, actual `Host model.Host`, `DraftRevision uint64` and `Intent planner.JobIntent`. Define `BuildMedia` (`build-media`, ISO construction) and `DownloadOnly` (`download-only`, available payloads) intents. `ReadyPlan` owns private immutable state with deep-copy accessors `Selection() model.Selection`, `RequestedSettings() model.ResolvedSettings`, `EffectiveSettings() model.ResolvedSettings`, `Manifest() model.PayloadManifest`, `Operations() []Operation`, `Tools() []tools.Requirement`, `Applicability() []model.SettingApplicability`, `DraftRevision() uint64`, `Intent() JobIntent` and `Digest() string`; estimates distinguish known sizes from estimates. `MarshalTOML() ([]byte, error)` and `DecodeReadyPlan([]byte) (ReadyPlan, error)` preserve the validated identity without locators. Operations are fixed typed handlers with source/rule/tool/input identities, never executable command text. Preserve `(*jobs.Controller).Start(ctx context.Context, plan planner.ReadyPlan) (jobs.JobView, error)` and `Cancel(ctx context.Context, jobID string) error` from the shared contract; `JobView` is the read-only state/stage/error/artifact/action snapshot. Stage producers U06–U10 register into that graph, rather than introducing alternate controllers.

- [x] Add `TestFrozenPlanRejectsChangedIdentity`, `TestPreflightChecksChosenVolumes`, `TestDeferredAppBarrierPrecedesMutation`, `TestOneConversionAtATime` and `TestWorkerRejectsWrongPeerOrOperation`. Assert immutable source/settings/rule/tool/graph identity, checked actual scratch/output filesystems and >4 GiB accounting, authenticated capability/workspace/plan binding and intent before mutation.
- [x] Implement the planner/controller/worker skeleton and minimum existing application build action/result/error connection. Explicit unsupported settings fail before mutation. A missing provider, discovery producer or handler gives a concrete blocker; no empty success path. Do not run the TUI elevated or add dedicated Review/Start/progress/recovery screens.
- [x] Wire cancellation and cleanup only for resources created by the active operation. Unknown mount/ownership state preserves resources and reports failure. No startup job discovery, restart replay or new recovery feature.
- [x] Run `go test ./internal/planner ./internal/jobs ./internal/worker ./internal/app ./internal/tui ./internal/platform/windows -count=1`. Demonstrate invalid/stale drafts and missing handlers being rejected without native image operations. Real stage execution is verified as U06–U10 register their handlers.

U05 implementation evidence (2026-10-29): private immutable plans retain source/settings/rule/tool/graph identities and round-trip through bounded locator-free TOML. Invalid/stale drafts, excluded legacy output/recovery choices, missing semantic discovery/providers/handlers and unverified ISO publication fail explicitly. Native chosen-volume probing and 64-bit shared-volume accounting were observed on Windows build 19045, native/process amd64, local NTFS; a 5 GiB payload plus a 5 GiB scratch estimate was checked without creating payload/image bytes. Authenticated native pipe tests prove that the worker cannot acquire the held parent writer, can acquire it after release, and requires peer/capability/workspace/plan/intent/operation bindings. Registry snapshots and actual assembly/source/draft-bound deferred app barriers prevent later authority changes or mutation bypass. Active cancellation cleans declared files only and preserves unknown state. The requested package checks, one full `go test ./... -count=1` run and Windows 386/amd64/arm64 builds passed. Full commands/results and limits are retained in this execution workspace's `task-5-report.md` and `task-5-*.log`. U06–U10 stage producers, privileged execution integration and real ISO completion remain pending; no elevation or native image operation was run.

## U06 — Resolve the source and automatically prepare downloads and tools

**Files:** Create `internal/source/{discovery,app_discovery}.go`, `internal/metadata/providers/{cab,wim,appx}.go` and tests. Extend `internal/tools/{manager,acquisition,verification,selection,manifest}.go` plus focused capability/setup files, a reviewed operational manifest and tests. Compose existing `internal/download`, `internal/app/source.go` and planner/job preparation handlers. Update `docs/feasibility/{acquisition,toolchains,source-formats}.md`.

**Interfaces:** Implement existing resolver callbacks through `(*source.Discovery).Metadata(ctx context.Context, selection model.Selection) (source.MetadataPlan, error)` and `Apps(ctx context.Context, selection model.Selection, inventory metadata.Inventory, sets []source.SourceSet) (source.AppDiscovery, error)`. Reuse `metadata.ReadOnlyProvider`, `download.Manager.Fetch/FetchOne`, the existing application composition helper `app.NewSourceManager`, and `tools.Manager.Ensure(ctx, Requirement, Emit) (Toolchain, error)`. Download options continue borrowing distinct `*windows.Workspace` capabilities, not arbitrary path strings. Locators remain runtime-only.

- [ ] Add production discovery tests using exact-source CAB/WIM/Appx inputs, including mismatched provenance, absent app licenses and post-assembly inventory. Reuse U03's verified observations; do not rebuild its request catalog. Test the full selected payload/base/reference/app closure and distinguish absent upstream material from an implementation gap.
- [ ] Select the first real ISO-capable canonical fixture from the existing census, with independent expected contents and operation-specific provider requirements. Close only the extraction/inspection/reconstruction/servicing/mastering proofs this slice needs. Inspect the retained native-desktop/control findings before choosing the next experiment; do not repeat the failed Get-Intl/WinRE sequence or treat component observations as full acceptance.
- [ ] Implement pinned helper acquisition, dependency/prerequisite closure, rights/notices and actual verified materialization through `Ensure`. Bind capabilities to source generation/target/operation/rule identity. Keep refusal for unverified combinations; a readiness boolean or PE header is insufficient. Add missing/wrong dependency, corrupt provider and clean-machine setup tests.
- [ ] Connect exact frozen manifests to the existing download manager, shared U01 get.php pacing for link refresh, proxy policy, source digest/size verification and computed SHA-256 cache. Test expired-link refresh, identity change, cancellation, duplicate content with different provenance, low space and reuse of verified downloads. CDN downloads retain configured parallelism.
- [ ] Run `go test ./internal/source ./internal/metadata/... ./internal/tools ./internal/download ./internal/jobs -count=1`. Run real read-only discovery/acquisition checks and the selected operation-specific proof with actual fixtures; retain failed/skipped results honestly. Produce prepared inputs and verified tools for U07 without claiming an ISO exists.

U06 partial evidence (2026-10-29): production CAB/WIM/Appx metadata adapters,
exact projected query refresh, source/rule-bound capability requests and a
registered preparation handler now preserve verified payload bytes in actual
stage checkpoints. The explicit Windows 10 alternate source
`3d12aa3e-806a-46c9-900e-bf7613959273` / 19045.7811 / x86 / en-us /
professional supplied all 40 catalog-selected files (3,036,466,495 bytes), which
were independently rehashed. Its selected image matches the previously retained
338,670,400-byte baseline SHA-256 and yields three observed WIM XML images;
five semantic inventory gaps remain. Retained ARM64 CAB/Foundation and U03 app
observations still pass without semantic installability claims. The authorized
non-elevated installed-WIMGAPI probe stopped immediately at WIMCreateFile /
ERROR_BAD_FORMAT (11), with unchanged source hashes and no subsequent image
operation. Ensure remains refusal-only; full reference/content/security closure,
servicing, rights/prerequisites and verified tools remain blocked. No U06
acceptance checkbox is complete. The private `task-6-report.md` retains exact
RED/GREEN, acquisition, native failure and verification evidence.

## U07 — Reconstruct and assemble source-matching Windows ISO contents

**Files:** Create `internal/engine/source/{types,adapter,registry,canonical,references}.go`, `internal/engine/{types,assembly,mediatree}.go` and tests; extend preparation/planner/stage registration. Add a small sanitized source descriptor under `testdata/source-families/`; retain large inputs privately. Update focused `tests/probes` contracts rather than weakening historical proof records.

**Interfaces:** `Adapter.Match(metadata.Inventory) (Match, error)`, `Recipe(metadata.Inventory, model.ResolvedSettings) (Recipe, error)` and `Normalize(context.Context, NormalizeRequest, model.Emit) (NormalizedSource, error)`. `Recipe` fixes family/rule/resource/provider requirements; `NormalizeRequest` borrows frozen manifest/inventory, `download.Materialized`, verified toolchain and active transaction. `NormalizedSource` binds actual output digests and source identity. `(*engine.Assembler).Assemble(ctx context.Context, req engine.AssembleRequest, emit model.Emit) (engine.BaseImages, error)` consumes that normalized source and ReadyPlan. Neither output is accepted solely from process exit status.

- [ ] Add `TestCanonicalReferencesRejectWrongOrMissingBase`, `TestAssemblyPreservesSecurityStreamsAndLinks`, `TestAssemblyRejectsForeignSource` and `TestStageBindsActualPredecessorDigest`. Include corrupt resources and attempted target-executable execution on the wrong host. Inspect real ACLs, streams, hard links/reparse data and actual image/edition/source identity.
- [ ] Implement the first proven canonical/reference adapter and assemble its actual Windows image and normal source-matching Setup/image files. Record stage intent before mutation and bind inspected predecessor outputs before accepting successors. Preserve source records needed inside a normal ISO; no recovery-image construction.
- [ ] Run `go test ./internal/engine/... ./internal/planner ./internal/jobs -count=1` and real selected-source reconstruction/assembly with the proven provider. Retain inspected contents and security/resource evidence. The intermediate tree is internal; it is not a new standalone directory deliverable.

**U07 partial evidence (2026-10-29):** Commits `bbd8d39` and `703afa6`
materialize and independently verify all 900 original source-media files from
the first x86/en-us canonical fixture. The shared logical-media namespace
conservatively refuses non-ASCII paths; actual storage paths retain their
existing Unicode behavior. Commit `76c8187` builds a 917,770,992-byte internal
Setup archive candidate from the same source: 818 matching Setup files and 70
new directories, exact launch replacement, retained security/stream/link and
opaque record bytes, correct boot metadata/index and independently verified
output XML counts. The actual first attempt exposed 97 valid empty directory
lists; its regression/fix and failed evidence are retained before the successful
retry. The original 17,637 metadata gaps concern tag-4 semantics, not missing
file references; those semantics remain unknown and all native/complete flags
stay false. Both components passed independent task review; the final full
suite, vet and Windows 386/amd64/arm64 builds passed. Generated candidates were
removed by their owners after inspection. No ISO, native preservation or whole
U07 acceptance is claimed. Production Normalize/Assembler/stage and install-image
integration, verified providers, native acceptance and complete active cleanup
remain open. The default application still reports its semantic-role blocker.
## U08 — Apply updates and produce the selected editions

**Files:** Create `internal/planner/{servicing,editions}.go`, `internal/engine/service/{types,executor,updates,editions,cleanup}.go`, `internal/engine/rules/{registry,updates,editions}.go`, tests and generation fixtures.

**Interfaces:** `planner.BuildServicePlan(metadata.Inventory, model.ResolvedSettings) (planner.ServicePlan, error)` extends the frozen operation graph. `(*service.Executor).Execute(ctx context.Context, req service.ServiceRequest, emit model.Emit) (service.ServicedImages, error)` consumes inspected images, the exact service plan, verified tools and active transaction. Generation rules produce typed data/operations, not commands.

- [ ] Add `TestCheckpointUpdatesRequirePredecessors`, `TestExternalUpdatesRemainOutsideImages`, `TestOmittedUpdatesDoNotEnterMedia`, `TestEditionDerivationPreservesDifferences`, `TestCleanupResetBaseFollowGenerationRules` and `TestFinalEditionInventoryMatchesPlan`. Assert required temporary bases do not leak into final indices and final image order equals the user's selection.
- [ ] Implement selected-generation servicing-stack/cumulative/checkpoint/MSU/enablement ordering, expansion and retention policies, per-edition/shared-base strategy, edition derivation and cleanup/reset-base applicability. Unsupported explicit choices fail instead of being ignored. Register required operations before the plan is frozen.
- [ ] Run `go test ./internal/planner ./internal/engine/service ./internal/engine/rules -count=1`, then independently inspect actual changed-image packages and edition identities. A successful helper missing a required package fails the stage. Extend other generations in U11.

**U08 implementation evidence (2026-10-30):** Commit `c1fcb0a` adds frozen typed
servicing plans, build-28000 update/edition rules, a concrete offline DISM
backend and a worker servicing bridge. Focused tests, the full Go suite and
Windows 386/amd64/arm64 builds passed; Luna high approved the implementation
slice. Actual configured-source acquisition verified 95 payloads
(8,329,466,842 bytes), and read-only XML identifies Professional at ESD index 3,
amd64/en-GB, base 10.0.28000.1. Actual servicing remains pending assembled-image
inputs, exact update metadata and a compatible elevated runtime; system DISM
returned 740. Full U08 acceptance is not claimed. The continuation proceeds
with directly required customization/output implementation while retaining
these concrete prerequisites; no recovery, regression or audit campaign.
## U09 — Apply the selected apps, features, drivers and Edge policy

**Files:** Add focused app/feature/driver/Edge planner, service and rule files with tests; bind real semantic results into existing `internal/tui/apps.go`. No WinRE service/rule files.

**Interfaces:** `planner.PlanApps(inv metadata.Inventory, settings model.AppSettings) (planner.AppPlan, error)` produces source-bound requested/effective app policies and dependency/resource/framework/license operations. `PlanDrivers`/`PlanFeatures` produce typed operations from the existing resolved settings. A post-materialization inventory barrier is an explicit graph operation before customization, not permission to edit the frozen request silently.

- [ ] Test default/custom/none/preset/stub/full and Edge policies against real app manifests, dependencies, architectures, resources and licenses. Test legacy inventory that is available only after assembly; unknown data stays deferred until the mandatory barrier succeeds. Missing requested IDs and invalid licenses fail before app mutation/publication.
- [ ] Implement supported app provisioning/removal, NetFx3 and separate OS/WinPE driver targets using source-specific rules. Keep requested and effective values visible in applicability/report data; set `AppsApplicable` only from matching validated source/draft results. Explicit excluded recovery targets are rejected without dropping readable schema-1 settings.
- [ ] Run `go test ./internal/metadata/... ./internal/planner ./internal/engine/service ./internal/engine/rules ./internal/tui -count=1` and independently inspect actual provisioned packages, features and driver state in the resulting image. Exercise dependency/license failure without publishing an ISO. Demonstrate that U03's chosen requests reach real customization unchanged.

**U09 implementation evidence (2026-10-30):** Commit `c8eef53` adds source-bound
app/bundle/license planning, concrete DISM customization, NetFx3 and separate
OS/WinPE driver operations, a deferred inventory barrier and draft-bound TUI
applicability. Required affected tests and the full Go suite passed; Luna high
approved the implementation slice. The actual saved requests resolved from
243 package manifests and 12 external bundle manifests: all 12 requested IDs,
5 framework operations and 237 declared bundle children, with source licenses.
Native provisioned/stub/feature/driver state and full U09 acceptance remain
pending an elevated compatible runtime and production stage composition.
Edge include/exclude are explicitly unavailable; the saved default is retained.
## U10 — Create, verify and save the ISO

**Files:** Create `internal/engine/output/{types,export,master,verify,publish,report}.go` and tests. Extract reusable ISO/UDF content inspection from `tests/probes` into a focused internal package if needed while retaining corruption/bounds tests. Connect output handlers to the existing job and application result path.

**Interfaces:** Output stages expose `Prepare`, `Verify` and `Publish`; only actual verification constructs `VerifiedArtifact`, with private state binding source/plan identity, size and SHA-256. Internal WIM/ESD/SWM export follows the frozen settings; no separate image output action is added. Publication consumes a verified local ISO and verifies destination bytes before final `model.Artifact` completion.

- [ ] Test wrong/truncated ISO contents, source/image/edition/app mismatch, >4 GiB representation, output collisions, write/copy/digest failures and helper exit zero with missing files. Assert the controller cannot finish before independent local and destination verification succeeds.
- [ ] Master the normal Windows ISO filesystem and source records from U07–U09. Inspect actual required file bytes, internal image state, edition order and filesystem contents. Reuse structural source boot-record handling where needed; do not boot, run Setup or claim bootability testing.
- [ ] Publish without overwriting unrelated output. Retain the verified local ISO if destination publication fails. Write SHA-256 and a redacted source/settings/tool/check report without credentials or signed locators. Report excluded recovery/boot tests as excluded, never passed.
- [ ] Run `go test ./internal/engine/output ./internal/jobs ./internal/app -count=1` and the complete real U02–U10 journey on the first accepted source, starting from the runnable executable. Demonstrate the actual ISO, checksum, report and chosen output location. This is the first end-to-end milestone, not final source-family completion.

**U10 output implementation evidence (2026-10-30):** Commits `4ad5248` and
`62a2303` add native UDF mastering, source BIOS/EFI content verification,
WIM/ESD/SWM export, private verified-publication capabilities and the controller
completion boundary. Full tests and Windows 386/amd64/arm64 builds passed;
Luna high approved this output slice. Actual component checks verified all
1,058 source media files and a 4,353,046,426-byte file inside a real UDF ISO.
These private component ISOs are not the configured Windows deliverable.
Selected-source producer composition is recorded below; elevated servicing and
customization remain pending. A real unserviced Professional/amd64/en-GB/28000.1 base WIM
was separately exported from the exact configured inputs and independently
inspected; source matching DISM files are acquired without machine installation.
No full U10 or native configured-ISO acceptance is claimed yet.

**U10 selected-source composition evidence (2026-10-30):** Commits `37c81d6`,
`14f296b` and `7e3518a` wire managed tools, exact source/app metadata, complete
source assembly, servicing/customization and verified ISO publication into the
same planner/controller, with a runnable `--build-iso` entry. The real frozen
plan resolves 350 payloads, two editions and 17 app/framework operations.
Actual non-elevated checkpoint assembly produced a verified Professional WIM
and two-index Setup boot WIM with launcher readback. Managed runtime acquisition,
source Edge provider readback, full package tests and Windows 386/amd64/arm64
builds passed; Luna high approved this composition slice without findings.
The prepared executable/config/invocation and evidence are retained in
`task-10b-report.md` in this plan's execution workspace. Current DISM execution
requires an elevated token (740); native updates, Enterprise derivation, Edge,
app provisioning and final ISO acceptance are still pending. U11 follows the
first configured ISO; component evidence does not complete U08–U10.

## U11 — Make every required source generation work through the same journey

**Files:** Extend `internal/engine/source`, generation-specific `internal/engine/{rules,service}`, discovery/provider capability manifests, tests, sanitized `testdata/source-families` descriptors and existing census/compatibility records. Add `docs/feasibility/source-family-contracts.md` for actual algorithms and fixtures, not a second task schedule.

**Interfaces:** Keep U07's adapter/normalized-source contract and U05's planner/controller. Each accepted variant supplies exact source/container/index/base/rule/provider identities and independent expected outputs. Unknown matches/conflicting adapters cannot create build-ready plans.

- [ ] Reconcile the existing census against current upstream families. For each family below, record applicable real source(s), algorithm and provider closure, then implement and verify a complete selection → preparation → conversion → ISO run. Keep each material variant an independently reviewable commit within this task.
- [ ] Canonical/reference generations beyond the first fixture, including legacy layouts.
- [ ] Express/PSF/CIX and other differential variants, distinguishing base-dependent and baseless reconstruction; wrong-base/missing-resource/corrupt-index negatives are required.
- [ ] Encrypted ESD and ESRP as separate delivery/algorithm contracts; secret material remains private and never enters plans/reports.
- [ ] Checkpoint MSU, app/FoD and additional specialized source generations identified by the census, including generation-specific servicing/edition rules. Do not schedule dedicated recovery features.
- [ ] For update-only, expired or non-ISO-capable entries retain catalog visibility and explain the missing upstream material. Preserve the ability to download available payloads through a typed download-only intent, with a result explicitly distinct from ISO completion. An unfinished adapter remains an implementation gap, not a reason to misclassify the source as unavailable.
- [ ] Run `go test ./internal/engine/... ./internal/source ./internal/tools ./internal/planner ./tests/probes -count=1` and actual family-specific conversions on the available host. Retain observed coverage and failed/unverified entries; apply the host-proof policy without inventing execution on other hosts. U11 is complete only when every required ISO-capable family and target is supported, not when its catalog rows are visible.

## U12 — Verify release behavior from a clean machine

**Files:** Focused `tests/integration` and release/clean-machine checks, compatibility records, release documentation and checksummed Windows `386`/`amd64`/`arm64` executable bundles; workflow/scripts only as needed for those outputs.

**Interfaces:** Release validation consumes an explicit reduced-scope set of required operation/source/output evidence. Preserve strict historical validators; do not rewrite old failed boot/recovery cases into successful records. Builds remain a separate portability check.

- [ ] Run `go test ./... -count=1`, `go vet ./...` and builds with `GOOS=windows`, `CGO_ENABLED=0`, and each of `GOARCH=386`, `amd64`, `arm64`. Run available race checks where applicable. Record the exact commands, results, host and limitations.
- [ ] Complete required real-source/provider/corpus checks, dense >4 GiB transfer, clean-machine managed helper acquisition, non-admin browsing, spaces/Unicode paths, low-space and destination failures, current-operation cancellation/cleanup and the supported customization/ISO-content suite. A skipped required check blocks the relevant claim.
- [ ] Validate that the released executable completes the workflow without manual helper installation, hidden source substitutions or false success. Preserve all target choices. Exclude boot/Setup execution, recovery/restart, physical-media writing and a new console/terminal campaign.
- [ ] Package all three executables with checksums, required notices and a truthful compatibility report. Seek the appropriate whole-product review before release. External publication is a separate requested action.

## Tracking and execution rules

- **U01–U05 are complete with task reviews clean. U06 and U07 have reviewed partial implementations and actual source-byte evidence, but their full semantic/provider/native/assembly acceptance remains incomplete.** The current continuation starts at U08 as explicitly requested, carrying unfinished U06/U07 prerequisites rather than claiming them complete. U08–U10 have reviewed implementation slices, including real selected-source assembly and concrete producer composition; their native acceptance and the first configured ISO remain pending elevation. U11–U12 remain pending. Current user scope prioritizes a configured ISO and excludes recoveries, regressions, audits and extremely tight requirements. No elevation, host servicing or excluded recovery/boot execution has been performed.
- Work top to bottom. A task may prepare a narrowly required downstream interface, but must not start unrelated provider research or a second subsystem schedule. Put newly found work under its owning workflow task, with its concrete acceptance condition.
- For substantive code changes, run the named new behavior checks before implementation and establish the expected failure; then implement and rerun the owning task's verification. Existing passing checks alone do not establish the new behavior. Finish each independently testable change with a focused reviewable commit.
- Check a task off only when its deliverable is demonstrated. Add a short evidence line with changed files/commit, executed tests, actual user-visible result and any remaining gap. Do not import old unchecked boxes or count old component observations as current completion.
- Preserve an established execution method when development is resumed. Prior implementation used subagent-driven development; this replan does not dispatch workers or message other chats. Read this plan and its current scope amendment before resuming any older chat/worktree.
- If this plan is replaced later, incorporate retained requirements/evidence, remove the superseded plan files and update all active links in the same change. Keep one canonical plan; feasibility records and compatibility reports contain evidence, not competing execution queues.

## Plan self-review

- [x] Rate limiting is first and grounded in the supplied server code, including its timer mutation and shared-IP behavior.
- [x] Task order follows selection → apps → settings → preparation → image construction → customization → ISO delivery.
- [x] Integrated startup/TUI/configuration/source-request work is retained rather than scheduled again from zero.
- [x] Missing production metadata, provider acquisition and worker/stage integration have concrete owners in the first conversion slice.
- [x] Deferred app validation, source/provider identity, active ownership, metadata preservation and destination verification have named checks.
- [x] ISO-only scope, removed recovery/R17/boot tests, host-proof policy and full source-family coverage remain intact.
- [x] Legacy plans are removed and active document links point to this plan; historical evidence remains evidence.
