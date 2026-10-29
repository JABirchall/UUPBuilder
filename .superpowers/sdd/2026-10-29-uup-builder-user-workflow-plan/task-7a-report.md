# U07A — Canonical recipe and source-preserving WIM prerequisite

Status: **DONE_WITH_CONCERNS** for this bounded component. BASE `ec1c3d242b05dee4c2842cc0cfe4555781f444b6`, branch `codex/uup-user-workflow`. No U06/U07 acceptance, operational Toolchain, NormalizedSource, transaction checkpoint, assembled media, servicing or ISO is claimed. No progress.md or acceptance boxes changed. The controller owns independent review.

Implementation commit: **`aecd54d44c9dbed12183af0ad0649c5ed7a9ec6a` — feat(engine): reconstruct source-preserving standard WIM component**. This report is committed separately. Changed files are the new `internal/engine/{types,wimwriter,wimverify,native_windows,actual_test,wim_test,native_windows_test}.go`, `internal/engine/source/{types,adapter,registry,canonical,references,xml,canonical_test,bound_test,facts_test,xml_test}.go`, focused B5 `internal/metadata/wimcontent/reference_claim{,_test}.go`, and sanitized `testdata/source-families/canonical-client-19041-x86.json`.

## Implemented boundary

`internal/engine/source` now defines the planning Adapter Match/Recipe contracts, immutable rule/provider/operation/source descriptors, concrete other-family gaps, and `BindCanonical`. The first match uses original XML x86 / Professional / Client / 10.0.19041.1 and nonempty ordinary decoded OS paths, plus original metadata/image association, source/manifest/index/oracle/reference bindings. It does not whitelist UUIDs, infer roles from filenames/boot indexes, or execute target code. Its original index may be any mapped positive image index; synthetic source tests use index 1 and a misleading filename, while the real selected metadata maps to original index 3. Boot/Setup roles remain unproved.

`BoundRecipe` has no exported authority-bearing fields or serialized constructor. It borrows the live MetadataArtifact and ReferenceView and exposes copied descriptors and bounded readers. It authenticates the exact selected original source before/after reading its XML, completely hashes original metadata before/after descriptor construction, checks original reference/witness identities and sizes, preserves every matching witness in per-resource provenance digests, and checks context/parent liveness after serialization. Its resource lineage binds full SHA1/size/SHA256 and original provenance. Source metadata is never regenerated from interpreted records.

The controller approved a focused B5 read-API extension: `ReferenceView.Claim`, `ReferenceAt`, `WIMWitnessAt`, `CABWitnessAt`, `CheckLive`. Scalar counts/values allow exact witness/string preflight without Snapshot/JSON or a nested resolution clone. These are historical values; live reads still borrow and revoke with both parents. No B5 construction/verification/serialization behavior or deferred B5-M1 cleanup was changed.

`engine.Reconstruct` consumes only a live BoundRecipe. The private standard writer emits one standard uncompressed WIM (version 0x10d00), fresh GUID, original RP_FIX default, original selected metadata bytes, one blob per complete verified content identity, a checked 50-byte blob table and the original selected IMAGE XML body. Only the single-image INDEX/container framing changes. Unknown XML inside the image is retained. Unsupported outer namespace dependencies are refused instead of silently dropped. Empty metadata streams keep their original zero hashes and need no new blob. Default/named/reparse/EFS/opaque stream records, security descriptors/IDs, short/raw names, timestamps, hardlink IDs, tags/EAs, reserved/unknown fields and metadata padding are carried by the exact original metadata resource.

Primary blob-table semantics count file-stream references including hardlink link counts. The writer derives counts from every original dentry stream; it does not collapse files into a hardlink merely because they share bytes. Original hardlink groups must be consistent. The synthetic production-producer fixture has two hardlink names and distinct same-byte files: the shared blob gets five references while all original file identities remain in the unchanged metadata.

`wimverify.go` independently reads all header fields/reserved bytes, extents, ordering, table flags/part/refcounts/hashes, exact metadata/content hashes and XML bytes against original expectations, without using the descriptor encoder. A separate full-output SHA256/custody reread and another full original-resource reread precede publication. The private Artifact borrows one retained read-only file; Close revokes readers and performs checked owned cleanup. Caller paths cannot grant output authority. Its receipt always leaves WindowsCompatible and NativeFilesystemPreservation false. Independent original source Recipe expectations are retained privately for future native comparisons, rather than inferred from a produced image.

`native_windows.go` implements only the fixed installed-WIMGAPI read-only observation: measured SystemDLL, existing/read open with documented flags 0, count 1, file XML, documented owned temporary metadata-cache prerequisite, load image 1 and image XML, then measured modules while file/image/library remain live. Image/file handles, LocalFree, temporary custody and DLL rehash/close failures prevent successful observation. It accepts no caller provider, path, flags, callbacks, reference registration or write operation. The first actual native observation described below predates later hardening and is explicitly not a final-code or final-output native proof.

The public `Adapter` here deliberately contains only implemented planning contracts. There is no placeholder Normalize, Assembler or stage handler. Full canonical U07's NormalizeRequest/NormalizedSource and Assembler contracts still require real prepared predecessor custody, operational Toolchain and active transaction authority.

## Budgets and lifetimes

Public zero limits choose ceilings; internal read-budget exhaustion stays zero and fails. Limits can only be lowered. Before allocation or calls, the source boundary caps 4096 manifest payloads, 64 queries/sources, 4096 aggregate projected payloads, 4096-byte identity fields, 32768-byte runtime paths, 64 destination components, 16 MiB aggregate raw manifest strings, 262144 references/metadata entries, 524288 witnesses, 1 MiB XML, 512 MiB conservative result accounting and 64 GiB reads. Snapshot accounting includes the original Oracle's conservative summary, bounded original-record serialization scratch, stream-count map and exact resource/witness/string costs. No full reference snapshot is made. The final actual source accounting was **435,659,240 bytes**.

The writer caps 524288 resources, 1 MiB XML, 8 GiB output, 512 MiB result accounting, 64 GiB reads and a 64 KiB streaming buffer. Checked total size, count/table/string/result/read requirements and actual fresh temp-volume maximum file/available space (output plus 64 MiB reserve) precede output creation. It owns one generated protected local NTFS store and reserves declared size when creating the output. Its exact read preflight is two original resource passes plus three complete output-equivalent passes. A literal 325-byte synthetic WIM requires exactly 981 reads; 980 and an exhausted residual fail.

The native boundary caps XML copies at 1 MiB, 32 cache files plus the held owner marker, 64 MiB per cache entry / 128 MiB aggregate, and requires 256 MiB available cache space. It checks owner file identity/hash, directory identity, file type/reparse/link/count/size bounds and preserves unexplained remnants rather than recursively deleting. Cache cleanup errors latch. Modules are at most 256 files / 128 MiB each / 512 MiB aggregate, measured during live imaging handles/library. Cancellation and a 60-second elapsed boundary are checked between calls; one synchronous OS call cannot be preempted. The OS's internal allocations and Go runtime/allocator retention, existing caller-owned producers, NTFS metadata and unrelated processes are not whole-process/whole-volume peak guarantees. Operation-time file identities are a bounded module observation, not complete clean-machine dependency/rights attestation.

The configured checks recreated original B1/B2/B3/B4/B5 producers from retained source bytes because all prior stores were closed. Every new output/decoded producer/artifact was closed by the configured test. JSON receipts are historical, location-free evidence; no later reader can mint authority from them.

## Exact original binding and final recipe

- Source: UUID `3d12aa3e-806a-46c9-900e-bf7613959273`, catalog **19045.7811 / x86 / en-us / professional**. Original XML/output baseline stays **10.0.19041.1 / Professional / Client**; no serviced 19045.7811 output is claimed.
- Manifest `675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9`; original index `ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a`; original Oracle `55c616fbf48127e824365337ad8a509a92b43b1a79043378a20dfa417d46b019`.
- Selected metadata SHA1 `29256693076c5877942412848136d702889e3141`, SHA256 `271d6f490baa2f90d497e0d21f721b56d4e2cfc5323feb0bfb491b9c2989201a`, **18,731,096 bytes**.
- Recipe digest `d9c0b86b68faba1bd72da6a35fa49a38474b7903674ad6c3ba8a859235a3edd9`; final proof descriptor digest `d0b80160009283259439ce48a9cf0dd9024c42c8d7140577fa0fc1885c694749`.
- Resource lineage `486533fcd1f268c5b38361aa2abc915a1e73640f7251cde70f266953a830e81e`; original XML SHA256 `90a802d3b9f7ef0c8f5a6508579c6516bc2f1f3dc4f1dbd4769363e7fc03e3d8`; reconstructed XML SHA256 `1cd55adba5b338370bb0440a5e91a4da41d7a164a0ab76417c8888c8b1d78049`, **2,280 bytes**.

The final proof includes original metadata/index/oracle, WIM/CAB/reference digests, resource lineage/count/size, permitted operations, candidate provider contract and independently derived original path/security/stream/link witnesses. Its ten representative original records include ntoskrnl.exe, SOFTWARE, SYSTEM, a reparse record, opaque tag record, empty stream and two members of a hardlink group. Full exact metadata bytes and original Oracle bind every other record, including fields not interpreted semantically. The original **14,515 gaps** are unchanged (13,546 EA, 195 callback ACE, 774 historical WIM-missing references); the new live view resolves bytes separately. There is no metadata semantic-completeness claim.

## Actual commands and first-versus-final chronology

No source acquisition occurred. Both configured checks used:

```powershell
$env:UUP_CANONICAL_PREPARED_ROOT=(Resolve-Path '.superpowers/sdd/2026-10-29-uup-builder-user-workflow-plan').Path
go test ./internal/engine -run '^TestPreparedCanonicalReconstruction$' -count=1 -v -timeout 30m
```

The first additionally set `UUP_CANONICAL_NATIVE=1`; the final did not. Both recreated 13 WIM sources / 22 local CAB sources, the 39,471-reference union and live selected metadata through reviewed production producers. All required hashes/sizes/metadata bytes and every reconstructed resource were checked. The writer output contains **39,472 resources**, **5,059,338,660 resource bytes**, **5,061,314,748 total bytes** and **25,302,621,564 charged read bytes**. No WIM was published or delivered; both private outputs were closed and removed.

**First actual check, 332.34s / package 332.386s, PASS:** output SHA256 `a48cbadbef7deaf645c28c992d44431c239fbbde3f4f3e49af89b748a3675f79`; proof `ac7c0676072aff005bd0f93b94e15147428aa8285fd73a569a46bcccd61f0859`; source accounting 411,793,296 bytes. Its exact output and descriptor are retained as `task-7a-first-output.json` and `task-7a-first-recipe.json`, log `task-7a-first-actual.log`.

The one installed native sequence succeeded on that first exact WIM. WIMCreateFile used GENERIC_READ / OPEN_EXISTING / flags 0 / ignored NONE, count was 1, WIMSetTemporaryPath and WIMLoadImage(1) succeeded, and file/image XML reported **0 / Professional / Client / 10.0.19041.1**. The independently retained first original Recipe has the same baseline/architecture/edition. All cleanup returned nil. Installed WIMGAPI measured **780,640 bytes**, SHA256 `31638dc7ceb75258940c3b256935f385f192fa9d0f47516d711f029dc241154f`. Current actual host: **AMD64 process / native AMD64, Windows build 19045**, local NTFS with ACL/ADS/reparse/hardlink capability facts. Fifteen module identities were measured while file/image/library remained live, including the test executable and installed OS modules; they are in `task-7a-first-native.json` (SHA256 `cd98e4c475b6158e3ea00d496dfae3acb83bea225e97d5771b615aea8fbc1df8`). No native failure or fallback occurred.

While that compiled first check ran, source preflight/representative selection was tightened. Subsequent self-review also tightened cache ownership/latching, propagated LocalFree errors, corrected the native PVOID representation after vet, and retained original Recipe expectations directly for future comparisons. The first native routine compared native XML against the source-preserving output XML; the configured test separately asserted the original Recipe baseline before reconstruction. The final code compares native XML directly with the private original Recipe expectations. **The revised native path was not exercised again.** The single first observation establishes container open/count/load/XML interoperability for its first exact output only, not final-code operation acceptance or a production provider capability.

**Final byte-only check, 383.56s / package 383.610s, PASS:** output SHA256 `04aac68c6ad791185c03517b778b595f07673b5f91120dbf2a686d39f6a29c7f`; final proof/accounting above; log `task-7a-final-actual.log`. It explicitly logged `native interoperability NOT configured`. Its receipt keeps WindowsCompatible=false and NativeFilesystemPreservation=false. New random container GUIDs explain different full-output hashes; resource lineage and XML hashes are identical. No native status is transferred to this new output. After its compiled byte-only run began, the native expectation storage/PVOID guard changes and the unsupported outer-namespace refusal were finalized; those do not alter its successful source/resource/framing bytes, and their focused tests and final vet/builds were run separately.

Retained final descriptor JSON SHA256 `8c3d112e3bb44f6f7026f55b7fc29c790f9e7fed79ec9319d9cd6bb969345db6`; final output receipt JSON SHA256 `61accdb2d61f452bb47b4ea37b98c952aa5ba0ef7b802d408be6c542f4a6cb7d`. First recipe JSON SHA256 `505bc7873aad5995ee09a031b7b819b48c80083abf41f0db9ffe2a777318dba8`; first output receipt JSON SHA256 `5851fc08363f6299841b49c2de792f8a4d37d47a925b29d859fe5845a13f6e11`. These hashes address receipts, separately from the actual WIM hashes above.

## TDD and test evidence

Initial missing-contract REDs preceded each implementation group:

| Command | Expected initial failure | GREEN |
| --- | --- | --- |
| `go test ./internal/engine/... -count=1` | undefined Canonical/BindCanonical/Inputs/writeStandard/writeInput/Artifact | focused engine/source `ok` |
| `go test ./internal/metadata/wimcontent -run TestReferenceValueClaims -count=1` | missing Claim/ReferenceAt/WIMWitnessAt/CABWitnessAt/CheckLive | `ok 0.194s` |
| `go test ./internal/engine -run TestNativeInspection -count=1` | undefined InspectReadOnly | `ok 0.095s` |
| `go test ./internal/engine/source -run TestExpectedFacts -count=1` | undefined expectedFacts | subsequent focused source suite `ok` |
| `go test ./internal/engine -run TestNativeExpected -count=1` | undefined expectedImage | subsequent engine/source suite `ok` |

Behavioral RED/GREEN regressions from self-review:

- `go test ./internal/engine/source -run TestResourceLineage -count=1`: RED `resource proof ignored byte identity`. JSON ignored private boundResource fields. Explicit resource serialization fixed it; engine/source suite passed.
- `go test ./internal/engine/source -run TestCanonicalPreflights -count=1`: RED `raw unbound fields reached validation canonical reconstruction source mismatch`. Raw Source/projection fields lacked early per-field checks. Added preflight before manifest validation; GREEN `ok 0.024s`.
- `go test ./internal/engine/source -run 'Test(BoundRecipe|CanonicalRejectsEmpty)' -count=1`: RED `empty kernel granted install role <nil>`. Required OS paths now need nonempty ordinary data streams; source suite GREEN `ok 0.263s`.
- `go test ./internal/engine -run TestNativeCache -count=1`: RED `foreign owner accepted <nil>`. Cache owner identity/hash and latched cleanup checks fixed it; covering native tests GREEN `ok 0.128s`. The first RED stopped before test cleanup and left one fresh test scope with the deliberately changed marker; it was identified by its exact generated path, verified flat/regular/same expected marker under the intended temp directory, and removed non-recursively. No unknown scope was deleted.
- `go test ./internal/engine/source -run TestSelectedXML -count=1`: RED carried `<p:OPAQUE>` after dropping its outer namespace declaration. This bounded rule now refuses such namespace dependencies; GREEN `ok 0.016s`. Unknown ordinary XML remains carried.
- `go test ./internal/engine -run TestZeroArtifact -count=1`: RED panicked on a zero Artifact's nil retained file. Invalid readers now return ErrInput and zero/nil Close is safe; complete engine/source GREEN `ok 0.684s / 0.949s`, with focused engine vet exit 0.

Additional characterization/adversarial checks cover full raw synthetic callback/tag metadata, empty/default/named/reparse streams, unchanged hardlink IDs and distinct identical-byte files, original-baseline identity, foreign/missing/closed parents, caller mutations, original-source drift, wrong resource hashes/order/header/table/XML, count/string/buffer/result/read/output limits, exact/exhausted read remainders, cancellation and source change after output mutation starts, no accepted partial artifacts, reader revocation, and unknown-cache preservation/latching. Synthetic fixtures provide no Windows interoperability or native filesystem proof. One source-drift test initially wrote zero over an existing zero GUID byte, so it correctly observed no change; the test was corrected to write a different byte before asserting refusal.

Latest affected package command before broad checks:

```text
go test ./internal/engine/... ./internal/metadata/wimcontent -count=1
ok engine 1.285s; source 1.368s; wimcontent 3.515s
```

Later source-expectation/cache tests also passed in complete focused engine/source runs (latest `ok engine 1.426s; source 1.696s`), and the final namespace guard had its exact RED/GREEN above.

## Broad validation and self-review

The first concurrent `go test ./... -count=1` failed two existing timing gates while actual reconstruction and architecture builds were running:

```text
TestInteractiveExitReportsPreservedBuildResources/active-at-quit
  build_windows_test.go:171: active handler setup did not finish: context deadline exceeded
  active-at-quit 5.48s; app package 29.474s
TestCloseRetainsCompletedCleanupFailure
  controller_test.go:226: handler not entered (10.22s)
  jobs package 26.189s
```

Retained as `task-7a-full.log`; neither app/jobs implementation nor test timeout changed. After heavy reconstruction ended, exact focused reruns passed: `go test ./internal/app -run '^TestInteractiveExitReportsPreservedBuildResources$' -count=1 -v` (**0.28s**), then `go test ./internal/jobs -run '^TestCloseRetainsCompletedCleanupFailure$' -count=1 -v` (**0.15s**). Output/exit 0 are in `task-7a-focused-recheck.log`. The timing/load explanation is an inference from concurrent versus quiet results, not a traced scheduler diagnosis.

A subsequent quiet `go test ./... -count=1` passed **all 27 tested packages**, plus cmd/uupbuilder with no test files. After the final namespace guard, a fresh whole-suite run again passed all 27 packages; exact stdout and exit 0 are in `task-7a-final-full.log` (the prior quiet pass is `task-7a-quiet-full-initial.log`). Optional configured tests in default runs were unconfigured/skipped; the two explicit configured checks above supply actual current-host evidence. The last zero-Artifact refusal/Close guard was added during that last whole run and then covered by the complete post-change engine/source tests and vet above; it changes no successful reconstruction/native path. No unrelated suite failure is omitted.

First `go vet ./...` reported `native_windows.go:181:51: possible misuse of unsafe.Pointer`. The PVOID output now has type unsafe.Pointer directly; no API/flags changed. **Fresh final go vet ./... exited 0**, recorded in `task-7a-vet-final.log`. Fresh final `GOOS=windows GOARCH=386/amd64/arm64 go build ./...` each exited **0**, recorded explicitly in `task-7a-builds-final.log`. These are compilation facts, not new physical-host operations. `git diff --check` and staged diff check passed. No dependency/Go baseline/TUI/config change occurred. No helper or reviewer agent was dispatched.

Self-review read the focused source/proof/reference/streaming/verification/native custody changes and corrected the behavioral findings above. The native file is 497 lines containing the complete narrow inspection/cache/module lifetime; it remains a focused but relatively large review surface. No claim hides that the revised native guards have compile/synthetic evidence after the first actual observation.

## Primary format/API references

Read solely as primary format/API documentation; no wimlib implementation was copied/imported/executed:

- [Pinned WIM header definition](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/include/wimlib/header.h) and [resource descriptor definition](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/include/wimlib/resource.h): standard header, resource flags/widths and standard version.
- [Pinned blob-table format](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/src/blob_table.c) and [stream reference semantics](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/src/write.c): metadata table order and stream counts including hardlink link counts. Only format/semantic definitions informed the independent Go implementation.
- Microsoft [WIMCreateFile](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wim/dd851934(v=msdn.10)?view=windows-11), [WIMGetImageCount](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wim/dd851938(v=msdn.10)?view=windows-11), [WIMGetImageInformation](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wim/dd834949(v=msdn.10)?view=windows-11), [WIMLoadImage](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wim/dd834941(v=msdn.10)?view=windows-11), [WIMSetTemporaryPath](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wim/dd851937(v=msdn.10)?view=windows-11). The load documentation requires the temporary metadata-processing location; this is not image application.
- Rehashed retained official Microsoft wimgapi.h, **15,956 bytes**, SHA256 `8aafd624abcdc32098007e5ce5b15ebc6ca3dab1835a7bba664f04a84d35cd7a`, under the already-retained vendor-header-data/header-only record. It supplies exact access/disposition/NONE constants and signatures; no header acquisition or installer/helper execution occurred in U07A.

## Remaining U06/U07 integration and limits

The operation-specific component descriptor and source-preserving Go writer are now concrete and reviewable. U06 must still issue only actually proven source/target/operation/rule/provider capabilities, establish rights/notices, dependency/clean-machine lifecycle and retained proof revocation. The first historical WIMGAPI observation cannot mint the revised final Toolchain. Whole U06 and all-five-operation/default Ensure refusals remain unchanged.

Full U07 must compose prepared inputs and inventory under active predecessor/transaction custody, implement Normalize and Assembler, record intent before actual mutation, bind actual predecessor/output digests, independently prove native ACL/EA/ADS/hardlink/reparse behavior and establish normal Setup/boot/media roles. Current opaque-byte carry is not that native filesystem proof. Planner requirements and frozen ReadyPlan validation must change together to match real per-operation Recipe authority; neither was silently altered here. Default app composition/real handlers remain required before U10, with no deferral to U12, while servicing/mastering/publication remain refused until proved.

Every advertised target/family and nine logical host/target pairs remain obligations; other physical hosts are optional under current host-proof policy. ARM64 historical evidence was not relabeled as this active x86 selection. All unsupported families/layouts/namespace contexts are implementation gaps, not upstream-unavailable. The sanitized testdata descriptor is an observation, never live authority.

No mount/apply/export/capture/servicing, privileges/elevation, source/target/downloaded DLL/helper/shim/script execution, host setup/install, publication, boot/Setup execution, recovery work or source mutation occurred outside deliberate synthetic test files. The stopped downloaded-wimlib route was not retried.

## Fix round 1 — U07A-R1 constructor-failure custody

FIX_BASE: `0f880426e4a51a92bff196fe4685a85c4171bfbf`. Read the exact Important/P2 finding in `task-7a-round-1-findings.md` and the full `task-7a-review.md`. Verified the cause against `Workspace.Close`: it closes a handle without removing its generated directory. The old root/parent opener failures discarded close errors and returned only the opener error, losing the generated scope identity before `InspectReadOnly` could receive a nativeTemp.

Changed only `internal/engine/native_windows.go`, new `internal/engine/native_temp_test.go`, and this report. A constructor ownership guard is registered immediately after workspace creation. It owns every acquired handle until both extra roots are held by nativeTemp, attempts all applicable closes on an opener failure, joins their errors with the original failure, returns no cache, and explicitly reports `native cache preserved at <exact generated path> (scope=<generated directory ID>)`. Because that early chain lacks complete checked directory custody, it deliberately preserves the owner-marked directory rather than attempting deletion. Later fully constructed nativeTemp cleanup remains unchanged. The private filesystem opener/closer seam cannot choose a provider, image API, source or inspection operation.

Tests use real fresh protected workspaces and deterministic root-open/parent-open failures, each with normal closes and reported close failures. They check the opener and close error chains, exactly one close attempt for every acquired handle, actually closed test handles, a nil result, explicit generated path/ID, unchanged directory identity and owner bytes. The injected close failures are reported after actual close so the tests do not strand handles. Test cleanup independently verifies its own exact flat fresh scope/owner and removes only that marker and empty directory; unknown or replaced entries are preserved. There is no recursive deletion.

RED → GREEN evidence:

```text
go test ./internal/engine -run '^TestNativeTempConstructorRetainsOpenerFailureCustody$' -count=1 -v
Initial missing-seam compile RED: undefined nativeTempConstructorOps / newNativeTempWith.
After extracting only the old behavior into that seam, behavioral RED:
  all four root-open|parent-open / close-ok|close-error cases failed
  native_temp_test.go:81: constructor lost generated scope identity: injected constructor opener failure
  FAIL ... (0.14s); package FAIL 0.155s
After adding the immediate ownership/preservation/error-join guard:
  all four cases PASS (0.12s); package ok 0.139s

go test ./internal/engine/... -count=1
ok uupbuilder/internal/engine 0.947s
ok uupbuilder/internal/engine/source 0.980s
affected packages exit=0
```

Exact retained outputs: `task-7a-fix-1-red.log`, `task-7a-fix-1-green.log`, `task-7a-fix-1-packages.log`. Self-review read the entire scoped production/test diff, checked ownership transfer and both early failure branches, and confirmed no unchecked close remains in either branch. `git diff --check` passed. Only focused and affected-package checks were run for this constructor fix, as directed; the full 27-package/native/reconstruction/vet/build bundle was not repeated.

No provider, recipe, writer, Toolchain, operation graph or app behavior changed. The first native and final byte-only observations above retain their exact historical identities and chronology; this fix neither reruns nor promotes either observation. U07A awaits the controller's scoped rereview before further implementation.
