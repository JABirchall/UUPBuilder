# U08 implementation report — 2026-10-30

Status: implementation slice complete with actual-image concerns; full U08 acceptance remains pending. Canonical task checkboxes have not been marked complete.

## Implemented behavior

- `planner.BuildServicePlan(metadata.Inventory, model.ResolvedSettings)` creates a typed, digest-bound service plan for the selected Windows client build 28000 generation. Other generations remain selectable and receive an explicit missing-rule error. Generation comes from inspected WIM/CompDB OS versions, not the descriptive catalog label.
- The frozen ReadyPlan now owns a copied service plan. The service operation binds its exact digest, generation rule and complete declared output filenames before freezing. Decode revalidates service choices against the original settings and final selected/derived edition order. User-selected editions cannot be dropped by an incomplete explicit output order.
- Added evidence-backed `metadata.Update` facts and the narrow Inventory/ProviderResult bridge needed for update identity, format, expected CBS identities, predecessor IDs, edition applicability and ordered expanded CAB members. Metadata inspection validates source/document/resource bindings and copies provider-owned collections.
- Rules produce SSU/checkpoint/LCU/enablement dependency order. Missing predecessors, cycles, incompatible explicit expansion/retention choices, absent explicit enablement and unresolved standalone MSU metadata fail. Every available MSU must be classified unless all updates are omitted.
- Integrate, external and omit policies are distinct. External updates are verified and copied to declared media output files without being added to OS images. Omitted updates produce no integration or retention operation. MSU keep retains its original container. Explicit expansion requires inspected CAB member order.
- Edition processing preserves separate source editions and explicitly declared derivation bases. Derivation exports a private base copy, calls native Set-Edition, and verifies the resulting edition. Temporary bases never become final WIM indices. Shared-base work is used only when it can preserve update applicability; explicit shared-base with edition-specific updates fails.
- `service.Executor.Execute` consumes inspected source images, the exact service plan, verified update inputs and an active jobstore transaction. It builds a concrete final `serviced.wim`, returns ordered image identities/indices and package observations, exposes retained update/base paths, and returns checkpoint output identities for downstream stages.
- The executor checks source WIM identity and bytes, verifies expected CBS packages after application and again before committing each mounted image, verifies the final WIM count/order/edition/architecture/language, and fails when a successful helper omits a required package. Installed, install-pending and superseded package states are distinguished from staged-only packages. CBS neutral-language spelling and identity casing are normalized without allowing an architecture/version mismatch.
- Cleanup follows the selected generation and explicit cleanup/reset-base settings; reset-base On requires cleanup, while Auto preserves rollback. Native cleanup failure remains a failed stage. Cancellation stops new work, uses the platform's safe wait-for-exit policy, and attempts to discard only the transaction-owned mount on failures, including partial mount creation.
- Added a concrete Windows `service.NewDISM(ctx, ownedWorkspace)` backend. It measures and pins installed system `dism.exe` and `expand.exe`, uses the existing owned SessionRunner, and issues fixed offline export/mount/Get-CurrentEdition/Get-Packages/Get-TargetEditions/Set-Edition/Add-Package/cleanup/unmount/Get-WimInfo operations. Logs, scratch and staged/expanded packages stay in the borrowed owned workspace. It does not elevate or service `/Online`. Complete inspection output is bounded separately from the runner's 64 KiB display tails; truncation cannot silently satisfy verification.
- Added `worker.ServicingHandler` and its narrow `ServiceInputProvider` port. The handler takes plan/transaction authority only from the active stage and writes a relative-path checkpoint receipt. The application registers this handler and explicitly reports the absent inspected-assembly provider/runtime rather than pretending a byte-reconstructed source is an assembled mutable Windows image.

## Verification and TDD evidence

Initial API RED commands were run before implementation:

- `go test ./internal/planner -run 'TestCheckpointUpdatesRequirePredecessors|TestExternalUpdatesRemainOutsideImages|TestOmittedUpdatesDoNotEnterMedia|TestEditionDerivationPreservesDifferences|TestCleanupResetBaseFollowGenerationRules|TestServicePlanIsFrozenWithOperations' -count=1` failed to compile because `metadata.Update`, `Inventory.Updates` and `BuildServicePlan` did not exist.
- `go test ./internal/engine/service -count=1` failed to compile because the service request/result/image types did not exist.
- `go test ./internal/worker -run TestServicingHandlerMissingAssemblyProviderIsConcreteBlocker -count=1` failed to compile because `ServicingHandler` and its concrete blocker did not exist.

Behavioral RED/GREEN checks also caught and fixed concrete failures:

- `go test ./internal/planner -run TestFrozenFinalEditionOrderCannotDropSelectedEdition -count=1`: RED `explicit order dropped selected Professional edition`; GREEN after requiring the exact selected/derived edition permutation.
- `go test ./internal/planner -run TestDecoderRejectsServicingChoicesDifferentFromFrozenSettings -count=1`: RED in cleanup/policy/preserve-bases/edition cases; GREEN after binding decoded service choices to original frozen settings.
- `go test ./internal/planner -run TestUnclassifiedMSUCannotBeSilentlyDropped -count=1`: RED `an unclassified update payload was silently omitted`; GREEN after checking every standalone MSU.
- `go test ./internal/engine/service -run TestDISMRejectsCorruptedStagedUpdateOnReuse -count=1`: RED `corrupted reused staged update accepted`; GREEN after verifying staged-file bytes on creation and reuse.
- `go test ./internal/engine/service -run TestPackageVerificationNormalizesCBSNeutralLanguage -count=1`: RED equivalent CBS identity rejected; GREEN after neutral-language/case normalization, with a wrong-architecture negative case retained.
- `go test ./internal/engine/service -run TestPartialMountFailureAttemptsOwnedCleanup -count=1`: RED `partial mount remained after failed stage`; GREEN after installing owned cleanup before the mount attempt.
- `go test ./internal/metadata -run TestUpdateFactsRequireBoundEvidenceAndOwnCollections -count=1`: RED `provider mutated returned update facts`; GREEN after copying all new update collections.

Required focused command:

```text
go test ./internal/planner ./internal/engine/service ./internal/engine/rules -count=1 -timeout=120s
ok uupbuilder/internal/planner 0.206s
ok uupbuilder/internal/engine/service 3.609s
ok uupbuilder/internal/engine/rules 0.024s
```

Final expanded focused command after self-review fixes:

```text
go test ./internal/planner ./internal/engine/service ./internal/engine/rules ./internal/metadata ./internal/worker -count=1 -timeout=120s
ok uupbuilder/internal/planner 0.362s
ok uupbuilder/internal/engine/service 3.154s
ok uupbuilder/internal/engine/rules 0.093s
ok uupbuilder/internal/metadata 0.546s
ok uupbuilder/internal/worker 5.982s
```

`go test ./internal/worker ./internal/jobs ./internal/app -count=1 -timeout=180s` passed all three packages.

The first full `go test ./... -count=1 -timeout=240s` run found two newly invalid TUI fixtures: `TestCancelledPreflightCannotExecuteLatePlan` and `TestConversionBuildConnectsFrozenRequestAndResult`. Both lacked an inspected generation/edition in their synthetic BuildMedia inventory. Added those observations to the shared TUI fixture, as already required by the planner, without changing TUI behavior. Their focused rerun passed (`ok uupbuilder/internal/tui 0.044s`).

Final `go test ./... -count=1 -timeout=240s`: **PASS, exit 0, all packages**. Relevant output: planner 0.986s; service 11.349s; rules 0.026s; metadata 1.253s; worker 24.424s; TUI 7.868s; engine 86.350s; jobstore 101.340s. The command's optional native/source functional checks retain their own opt-in conditions; this full-suite pass does not turn the explicit NOT RUN actual-image acceptance below into a pass.

Windows cross-builds (`go build -o <owned temporary output> ./cmd/uupbuilder`, GOOS=windows, GOARCH=386/amd64/arm64) passed all three architectures, including a fresh final rerun. Final artifacts: `C:/Users/owner/AppData/Local/Temp/uup-u08-final-build-aa23ecfac143463dad60ca9b618b6389`. These builds establish compilation, not native conversion support. No dependencies or Go baseline were changed. `git -c core.autocrlf=false diff --check` passed with no whitespace errors.

## Actual selected-image limitations

The controller independently acquired all 95 configured payloads and observed the real source as Windows 11 26H1 28000.3365 amd64/en-gb. Its read-only WIM XML inspection identified Professional/Client at index 3 of the acquired Professional ESD, base version 10.0.28000.1, with WindowsPE at index 2. The authored generation fixture records only a small factual CompDB projection; it is not redistributed upstream metadata or changed-image evidence.

No actual Windows image was mutated by this implementation run. The configured source still needs an assembled, mutable, inspected image producer and exact update/package/checkpoint facts (including KB5127653's expected CBS identities) supplied through the new input ports. Source reconstruction is not substituted for those missing producers.

The controller observed system DISM 10.0.19041.1 and a medium/non-elevated token; its existing read-only DISM WIM-info attempt returned 740 (elevation required). This agent did not retry native execution, elevate, invoke the historical blocked wimlib route, or mutate the host OS. The backend rejects a system runtime on a host older than the target generation and still needs a compatible managed servicing runtime for the actual build-28000 path. Executable presence/digest and modeled executor tests are not support attestations.

Independent inspection of packages and identities in an actually changed build-28000 image remains **NOT RUN**, not passed. Full U08 acceptance and an end-to-end ISO remain pending those concrete runtime/predecessor prerequisites. The planner supports only the selected generation in this slice; extending generation rules belongs to U11. No recovery, WinRE, boot/Setup execution, physical-media work or regression campaign was added. User config at `%LOCALAPPDATA%/UUPBuilder/config.toml` was read but not modified; the user's WinRE-excluded settings snapshot remains authoritative.

## Changed files

- `internal/planner/servicing.go`, `editions.go`, `servicing_test.go`, `types.go`, `resolve.go`, `freeze.go`, `dependencies.go`, `resolve_test.go`.
- `internal/engine/rules/registry.go`, `updates.go`, `editions.go`, `registry_test.go`, `testdata/windows-client-28000.json`.
- `internal/engine/service/types.go`, `executor.go`, `updates.go`, `editions.go`, `cleanup.go`, `dism_windows.go`, `executor_test.go`, `dism_windows_test.go`.
- `internal/metadata/updates.go`, `updates_test.go`, `inventory.go`, `roles.go`.
- `internal/worker/servicing.go`, `servicing_test.go`, `dispatch_test.go`.
- `internal/app/build_windows.go`, `internal/jobs/controller_test.go`, `internal/tui/build_action_test.go`.
- This report.

## Self-review

Reviewed the typed rule/plan/executor/native/worker boundaries and changed existing call sites. Fixed the meaningful issues exposed above: incomplete final edition order, resealed settings mismatch, partial MSU classification, stale staged package reuse, neutral CBS identities, partial mount cleanup and provider slice aliasing. Existing UI tests changed only in source metadata fixtures. No new command strings enter rules or frozen plans. Remaining integration/actual-image limitations are explicit above; they have not been converted into passing claims.

Native operation references consulted:

- https://learn.microsoft.com/windows/deployment/update/catalog-checkpoint-cumulative-updates
- https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism-windows-edition-servicing-command-line-options
- https://learn.microsoft.com/windows-hardware/manufacture/desktop/add-or-remove-packages-offline-using-dism
- https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism-operating-system-package-servicing-command-line-options
