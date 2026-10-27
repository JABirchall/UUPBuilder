# UUP Builder Multi-Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a single-executable Windows UUP builder with native Go conversion, TOML configuration, the Charm Workspace interface, and every available build target on every supported host.

**Architecture:** A coordinator establishes immutable shared contracts, then assigns independent work to data, Windows/engine, and interface specialists. Go owns planning and conversion; individual verified native tools perform narrowly defined imaging operations. Conversion development and release claims are gated by real provider, source-format, and image evidence.

**Tech Stack:** Go 1.27 baseline; Bubble Tea v2, Bubbles v2, Lip Gloss v2; a pinned TOML library; Windows APIs; managed wimlib/DISM/extraction/differential/ISO providers; Go test and Windows VM/hardware integration checks.

**Spec:** [Accepted design](../specs/2026-10-27-uup-builder-design.md), canonical project path `N:/win11_builder/docs/superpowers/specs/2026-10-27-uup-builder-design.md`.

**Authoritative host-proof amendment (2026-10-27):** The user accepts successful complete functionality on the available native Windows host plus Windows `386`/`amd64`/`arm64` builds as full host-architecture coverage. The [host proof policy](../../engineering/host-proof-policy.md) supersedes earlier mandatory physical-host execution clauses in this master plan and its child plans, including P1/W1/W2/R1. Unavailable x86/ARM64 hardware is no longer a blocker. Keep all nine logical common pairs, truthful actual host records and separate observed/portability-accepted coverage. Functional source/target/provider/servicing/media/dependency/rights/setup and release checks remain required.

## Global Constraints

The following requirements are copied from the accepted design and apply to every task and child plan:

- Go implementation with a Charm TUI.
- One executable for the user to download and run. Helpers may be extracted or downloaded behind the scenes, with the app managing their complete lifecycle.
- Use TOML for application configuration.
- Treat the existing files in this directory as guidance. Do not consume, copy into the product, modify, or execute them as application resources.
- Implement the conversion pipeline in Go and call individual tools directly. Do not use an upstream conversion script as the engine.
- Cover all builds available in UUP Dump.
- Run on Windows 10 and later, supporting the x86 and Arm architecture families.
- Allow every build target on every supported host. Do not restrict available targets to a smaller host/target compatibility matrix.
- One job builds one architecture and one language, with one or more editions. Run one conversion job at a time, with parallel network transfers.
- Product implementation is not authorized by this document's creation; wait for the user's plan review.

## Review Focus

1. An old search/language response arrives after the selection changed: discard it and preserve the current source revision (U1).
2. Download URLs expire or are reissued with different payloads: refresh only matching immutable identities; never mix revisions (D3/D4).
3. Identical filenames belong to different payloads: cache by digest/provenance and reject ambiguous materialization (D3/D4).
4. Power loss occurs between an operation and journal update/publication: recover validated outputs without trusting partial images or overwriting unrelated files (J1/J2/E6).
5. A helper returns success with the wrong image, missing apps, or invalid boot structure: independently verify and refuse completion (E3/E4/E6/R1).

---

## Plan layout and deliverables

This project has separable subsystems, so use this master schedule with three focused execution plans:

| Plan | Owned result |
| --- | --- |
| [Data and configuration](2026-10-27-uup-builder-data-plan.md) | Tested TOML, catalog, source identity/resolution, and resumable downloads |
| [Windows and conversion engine](2026-10-27-uup-builder-engine-plan.md) | Feasibility evidence, managed tools, source algorithms, transactional conversion, verified artifacts |
| [Workspace experience](2026-10-27-uup-builder-workspace-plan.md) | Browse/select/edit/review/progress workflow connected to real services |

Read the accepted design, this master, and the assigned child plan. Child tasks inherit this document's constraints and contracts. The plans describe future files; no Go project or dependencies have been created during planning.

## Agent settings and execution rules

Every specialist, implementer, specification reviewer, and code reviewer must use:

```json
{"model":"gpt-6.1-sol","reasoning_effort":"xhigh","fork_turns":"none"}
```

Use `collaboration.spawn_agent` with these exact settings; do not substitute a different model or effort. Configure the execution coordinator to the same requested model/effort when starting the implementation session. Do not claim this document changes the model of an already running chat.

The current capacity is four concurrent agents including the coordinator. Run at most three child agents. When reviewers need a slot, use the slot released by a completed worker or keep only two implementers running. A fresh reviewer does not implement the task being reviewed.

Each task gets a fresh focused implementer. After the task's focused verification passes, use a fresh specification reviewer, address findings, then a fresh code-quality reviewer. Both use the requested model/effort. Dependent work starts only after that task's reviews pass. Independent tasks may continue while reviews run. The coordinator checks interfaces, integrates accepted commits, and performs whole-product review at the end.

Supply each worker: task ID; spec/master/child-plan paths; exact writable files; prerequisite commit identifiers; contracts consumed/produced; verification commands; and the prohibition on changing other agents' files. Require a return containing changed files, test evidence, limitations, and commit identifier. Never provide a generic “build the subsystem” prompt.

The coordinator owns shared files and dependency changes. Contributors request contract changes rather than editing them concurrently. Use managed isolated worktrees when parallel changes need Git isolation; prefer a suitable existing checkout/worktree when available. Integrate one accepted task at a time. Never reset/stash another worker's changes or stage files belonging to another task.

## File ownership before tasks

| Owner | Planned files and responsibility |
| --- | --- |
| Coordinator | `go.mod`, `go.sum`, `.gitignore`, `internal/model/{source,request,events,artifacts,path}.go`, `cmd/uupbuilder/main.go`, `internal/app/wire.go`, release workflow and integration of contracts |
| Data specialist | `internal/config/**`, `internal/catalog/**`, `internal/source/{identity,manifest,resolver,refresh}.go`, `internal/download/**` |
| Platform specialist | `internal/platform/windows/**`, `internal/tools/**`, `tests/probes/**`, `docs/feasibility/**` |
| Engine specialist | `internal/metadata/**`, `internal/planner/**`, `internal/engine/**` |
| Job specialist | `internal/jobstore/**`, `internal/jobs/**`, `internal/worker/**` after shared contract approval |
| Interface specialist | `internal/tui/**`, `internal/app/interactive.go` |
| Release specialist | `tests/integration/**`, `testdata/compatibility/**`, `docs/release/**` |

Roles rotate as slots become available; they are not six simultaneous agents. Tests and fixtures live beside the owned code unless an explicit integration-task path is listed. Do not commit full Microsoft payloads/ISOs or expiring signed URLs as fixtures. Commit sanitized metadata/corpus descriptors and retrieve authorized large fixtures into ignored storage.

Keep the import graph acyclic: `platform/windows` and `model` are lower-level packages; download never imports source; metadata never imports source/planner; engine stages import `internal/jobstore` for transactions, never the upper-level `internal/jobs` controller. Planner consumes adapter recipes but service executors consume planner operations, never the reverse. `internal/app/wire.go` injects callbacks and stage handlers at the composition boundary.

## Shared contracts established by G0

Keep these names stable. The producing task defines complete field validation and constructors; consumers use the public contracts rather than another package's internals.

| Type | Required content |
| --- | --- |
| `model.Architecture` | String-backed, open-ended upstream target value; common values `x86`, `amd64`, `arm64`; explicit mapping of Go host `386` to target-family `x86` |
| `model.SourceIdentity` | UUID/revision-preserving `UpdateID`, build label, target architecture, language; no expiring URLs |
| `model.Selection` | `UpdateID string`, `Architecture model.Architecture`, `Language string`, `Editions []string` |
| `model.PayloadIdentity` | Trusted digest algorithm/value, size `int64`, original package provenance/name and required encryption identity/fingerprint; never the nullable download UUID or a secret key |
| `model.Payload` | Payload identity and validated logical relative destination; no signed locator in frozen/public serialization |
| `model.PayloadManifest` | Source identity, selected payloads, deterministic manifest digest excluding URLs/expiry |
| `model.Locators` | Runtime mapping from payload identity to URL/expiry; kept separate from immutable manifests/reports |
| `model.ResolvedSettings` | Typed conversion/app/driver/output/storage/download policies covering the design's entire behavior table |
| `model.Host` | Windows OS build, process architecture, native host architecture, filesystem capabilities |
| `model.Event` | Job/stage identity, kind, message, optional completed/total bytes/items, timestamp; progress may be indeterminate |
| `model.Emit` | `func(model.Event)`; coordinator supplies a thread-safe event sink; durable journal changes do not depend on UI delivery |
| `model.Artifact` | Kind, path, SHA-256, size, verification/report paths and source/plan identity |
| `model.Diagnostic` | Stable code, severity, source/key location, message and applicable selection/policy identity |
| `model.SettingApplicability` | Setting key, requested value, effective value, supported/automatic status and concrete reason |

G0 also provides `ValidateRelativePath(value string) (string, error)` for lexical Windows-safe logical paths. Reject traversal, absolute/UNC paths, alternate data streams, NUL and device names. W1 validates actual resolved filesystem containment/reparse points before privileged IO; lexical validation is insufficient for that boundary.

Producer interfaces are fixed here and assigned below:

```go
// D1, internal/config
func Load(path string) (Config, error)
func Save(path string, cfg Config) (SaveResult, error)
func (cfg Config) Validate() error
func (cfg Config) Request() (model.Selection, model.ResolvedSettings, error)

// D2, internal/catalog
func New(client *http.Client, baseURL string) *Client
func (c *Client) Search(ctx context.Context, query string) ([]Build, error)
func (c *Client) Languages(ctx context.Context, updateID string) ([]Language, error)
func (c *Client) Editions(ctx context.Context, updateID, language string) ([]Edition, error)
func (c *Client) Files(ctx context.Context, updateID, language, edition string) (FileSet, error)

// D4, internal/download
func (m *Manager) Fetch(ctx context.Context, manifest model.PayloadManifest, locators model.Locators, emit model.Emit) (Materialized, error)
func (m *Manager) FetchOne(ctx context.Context, payload model.Payload, locator Locator, emit model.Emit) (CachedFile, error)

// M1, internal/metadata
func Inspect(ctx context.Context, req InspectRequest) (Inventory, error)

// D3, internal/source
func (r *Resolver) Resolve(ctx context.Context, selection model.Selection, settings model.ResolvedSettings) (Resolution, error)
func (r *Resolver) RefreshLinks(ctx context.Context, frozen model.PayloadManifest) (model.Locators, error)
func Refresh(ctx context.Context, frozen model.PayloadManifest, fresh Resolution) (model.Locators, error)

// W2, internal/tools; W2 uses the W1 Windows direct runner
func (m *Manager) Ensure(ctx context.Context, req Requirement, emit model.Emit) (Toolchain, error)

// E2, internal/planner
func (p *Planner) Resolve(ctx context.Context, req Request) (ReadyPlan, error)

// J2, internal/jobs
func (c *Controller) Start(ctx context.Context, plan planner.ReadyPlan) (JobView, error)
func (c *Controller) PauseDownloads(ctx context.Context, jobID string) error
func (c *Controller) Resume(ctx context.Context, jobID string) error
func (c *Controller) Cancel(ctx context.Context, jobID string) error
func (c *Controller) Recover(ctx context.Context, jobID string) (JobView, error)
func (c *Controller) Subscribe(ctx context.Context, jobID string) (<-chan model.Event, error)
```

`catalog.FileSet` contains identities and runtime locators separately. `download.Materialized` maps payload identity to an app-owned verified path. `metadata.Inventory` exposes source roles, package graph, image properties, apps/frameworks/licenses, and detected source family. `source.Resolution` combines the frozen manifest, runtime locators, metadata inventory and source classification. `planner.Request` contains selection, settings, `source.Resolution`, host and draft revision; `ReadyPlan` is an immutable operation graph, tool requirements, resolved settings, estimates, draft revision and a content digest, with deep-copy read access rather than exported mutable slices/maps. Its persisted form excludes runtime locators, secret keys and proxy credentials. E2 also produces `planner.Operation`, the typed operation descriptor extended by E4/E5. `jobs.JobView` is a read-only snapshot of job state, stages, errors, artifact/report locations, and actions currently valid. These types are defined by their producing task, never guessed in a consumer.

## Parallel schedule and gates

| Wave | Tasks that can run independently | Gate before dependent work |
| --- | --- | --- |
| Bootstrap | G0 only | Model contracts and focused tests accepted |
| Discovery/proof | P1 provider/source census; D1 config; D2 catalog | P1 records real capability evidence; D1/D2 contracts pass reviews |
| Platform/interface | W1 platform adapters; U1 Workspace after D1/D2 | W1 lower-level contracts reviewed |
| IO/transactions | D4 downloads/cache; J1 journal/checkpoints | Both consume W1 and do not depend on each other |
| Providers/metadata | W2 after D4, then M1 | Verified tooling and semantic source inventory |
| Source/experience | D3 resolution; E1a normalization; U2 editors | Separate writable paths; all consume M1; P1 proof gates apply |
| Other adapters | E1b and E1c after E1a's adapter contract | Source-family algorithms and expected hashes verified |
| Planning/assembly | E2 after D3 and required E1 adapters, then E3 | Real provider/source evidence before mutating images |
| Specialization | E4 updates/editions, then E5 apps/features/drivers/recovery | Dependency-ordered servicing, correct inventories |
| Completion | E6 outputs, then J2 controller/worker, then U3 final integration | Durable safe cancellation, independent media verification |
| Release | R1 evidence closure and integrated review | Full target/host/source coverage and release evidence, not skipped cases |

This table limits concurrency, not task granularity. Follow the explicit dependency list in each child task. P1 starts before broad engine implementation. Independent configuration/catalog/UI work can continue if proof infrastructure is unavailable, but the engine/release cannot be declared complete.

### Gate P: provider feasibility

Prove complete real functionality on the available native Windows host for every required target, including real foreign-architecture image servicing, and build Windows 386/amd64/arm64 executables. Together these satisfy host-architecture coverage for all nine logical common pairs under the host proof policy; other physical host runs are optional. Record exact vendor acquisition route, dependency chain, versions/digests, permitted distribution/use, system prerequisites, and actual outputs. Cross-compilation alone, opening a foreign WIM, or seeing a download page does not pass this gate. Missing functional proof or infrastructure remains unverified; unavailable other-host hardware is not a blocker. A failed functional combination remains a requirement blocker to resolve, not permission to filter that target or invoke an external converter/service.

### Gate S: source algorithms

Census the real catalog's ISO-capable source layouts and their metadata/servicing variants. Give each family a fixture descriptor, reconstruction algorithm, expected digests, matching setup/recovery roles, and generation rules. Canonical/reference/express/PSF/CIX/encrypted are starting categories, not a claim that the taxonomy is complete. Additional discovered families receive concrete adapter tasks before claiming scope complete.

## Task G0: minimal executable contract and test foundation

**Owner:** Coordinator. **Depends:** Plan approval.

**Files:** Create `go.mod`, `go.sum`, `.gitignore`, `internal/model/{source,request,events,artifacts,path}.go`, `internal/model/{source,request,path}_test.go`, `cmd/uupbuilder/main.go`, `internal/app/wire.go`, and `internal/app/entry_test.go`. Create `docs/engineering/contracts.md` from the contract table. The first entrypoint only handles `--config`, reports initialization errors, and later delegates to the UI; do not build placeholder screens.

**Interfaces:** Produces shared `model` contracts above and `app.Run(ctx context.Context, args []string) error`; consumes the accepted spec. This task is limited to a working, testable entry/identity boundary, not wholesale package scaffolding.

- [ ] Write `TestSourceIdentityPreservesRevision`, `TestUnknownArchitectureIsRetained`, `TestPayloadIdentityIgnoresDownloadUUID`, `TestRelativePathRejectsTraversalUNCADSAndDevices`, and `TestEntryRejectsUnknownArgument`; assert revisions survive, `arm`/new architecture strings remain values, null URL UUIDs do not erase digest identity, unsafe logical paths fail, and invalid arguments return a useful error without starting work.
- [ ] Create the minimal module/test harness and run `go test ./internal/model ./internal/app -run 'Test(SourceIdentity|UnknownArchitecture|PayloadIdentity|RelativePath|Entry)' -count=1`; expected failure is the missing contract/entry behavior, not an unrelated environment/dependency failure.
- [ ] Implement the listed model/entry contracts. Use `module uupbuilder`, Go `1.27.0` baseline; resolve exact compatible dependency patches from official module metadata and pin them in `go.mod/go.sum` as each task needs them. Initialize Git only at execution time if the project still lacks it, preserving the original guidance files; commit only the project's explicitly owned new files. Use root-anchored ignore entries `/.work/`, `/downloads/`, `/cache/`, `/artifacts/`, `/.superpowers/` and specific local evidence paths; never use a blanket `tools/` rule that would hide `internal/tools` source.
- [ ] Run the focused command, `go vet ./internal/model ./internal/app`, and `go build -o .work/uupbuilder-bootstrap.exe ./cmd/uupbuilder`; expected exit 0 and the exact tested argument behavior. The bootstrap binary is not a completed product.
- [ ] Review and commit as `feat: establish UUP builder contracts and executable entry` using explicit file paths. Only the coordinator merges contract changes thereafter.

## Task R1: close release evidence and publish native executables

**Owner:** Release specialist plus coordinator. **Depends:** D1–D4, P1, W1–W2, M1, J1–J2, E1a–E1c and E2–E6, U1–U3 reviewed.

**Files:** Create `tests/integration/{release,conversion,cleanmachine,recovery,boot}_windows_test.go`, `testdata/compatibility/{required-cases,ledger.schema}.json`, `docs/release/{compatibility,operator-guide,third-party-notices}.md`, `.github/workflows/verify.yml`; coordinator owns `build/release.ps1` and version wiring. Large source artifacts remain outside Git.

**Interfaces:** Consumes `planner.ReadyPlan`, `jobs.Controller`, and verified artifacts; produces `func ValidateReleaseEvidence(required []Case, evidence []Evidence) error` in `tests/integration/evidence.go` and three native executable/checksum bundles. Reuse/alias P1's `probes.Case`/`probes.Evidence` rather than inventing a second ledger schema; extend that producer through coordinator review for release-specific checks. Delegate host-architecture acceptance to `probes.ValidateArchitectureCoverage`, retaining strict actual-record validation and the separate three-Windows-build prerequisite. Case fixes actual host OS/architecture, target, source family, policies, and boot mode; Evidence fixes source/tool/plan/output digests, real execution outcome, verification, and boot/application checks.

- [ ] Write `TestReleaseRejectsMissingMatrixEvidence`, `TestReleaseRejectsUnimplementedISOFamily`, `TestReleaseRejectsSkippedOrCrossCompileOnlyEvidence`, and `TestCleanMachineCompletesWithoutManualTools`; assertions require all nine common host/target pairs plus discovered formats, valid actual execution, matching source/tool identities, and no manual tool dependency.
- [ ] Run `go test ./tests/integration -run 'TestReleaseRejects' -count=1`; expect failure until evidence validation is implemented. Run the complete tagged functional cases on the available matching native host with explicit fixture roots; report portability-accepted other-host coverage separately. Missing functional prerequisites remain unverified and cannot produce passing release evidence.
- [ ] Implement the evidence validator, integration harness, release script, and CI. Validate representative actual boot/Setup/image application and installed apps/features across every distinct source/servicing family. Exercise worker loss, full recovery, non-admin startup, clean helper acquisition, legacy console/Windows Terminal, x86 memory limits, paths, insufficient space, and remote-output verification. Keep signed URLs/credentials out of reports and logs.
- [ ] Run `go test ./... -count=1`, `go vet ./...`, and supported `go test -race` packages on a host with the race toolchain; build with `GOOS=windows`, `CGO_ENABLED=0`, and each `GOARCH=386,amd64,arm64` unless a documented native dependency requires a different build pipeline. Run the complete actual Windows 10+ current-host target/source suite and ledger coverage evaluator. Expect all required functional cases to pass with observed/portability-accepted bases reported separately; skipped/failed functional cases are blockers, while unavailable other-host hardware is optional corroboration.
- [ ] Perform fresh whole-product specification and code reviews on `gpt-6.1-sol`/`xhigh`, resolve findings, commit only release-task files as `build: verify and package native UUP builder releases`, then prepare user-reviewable release artifacts. Publishing externally remains a separate concrete action.

## Commit and verification discipline

For each child task: write its named failing tests, run the exact focused command and establish a relevant failure, implement its listed signatures, rerun the focused checks, obtain both fresh reviews, then commit explicit owned paths with the task's commit subject. Do not stage unrelated work. Use the same focused command for the red and green steps unless the task explicitly distinguishes a real-provider gate from unit fixtures.

If an environment failure prevents reaching the behavior test, resolve/report the environment failure instead of calling it a red test. Do not broaden/repeat checks without a new change or unresolved concern. Coordinator integration runs package checks for the integrated contracts; full-product checks are reserved for meaningful integration gates and R1.

## Planning self-review and handoff

- [x] Spec coverage mapped: TOML D1; catalog D2; source identity D3; downloads D4; providers P1/W1/W2; metadata M1; source formats E1a–E1c and census expansions; planning E2; assembly E3; specialization E4/E5; media E6; jobs J1/J2; Workspace U1–U3; all-target runtime evidence and accepted host-architecture coverage R1.
- [x] Shared names/signatures and dependency ordering reviewed across all child plans; no agent may invent a replacement controller/planner contract independently.
- [x] Five review-focus conditions assigned concrete tests in their owning tasks.
- [x] Unknown provider/source algorithms are explicit early proof tasks with real evidence gates, not assumed implementations.
- [x] Planning specialists used the requested `gpt-6.1-sol`/`xhigh`; this master preserves it for workers and reviewers.
- [ ] User reviews this plan before implementation begins. Execution method is already selected: multi-agent, using the requested model/effort. Do not ask the user to choose the method again.
