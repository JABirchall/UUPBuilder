# U07B3 — CAB-resolved original stream expectations

Base `fb34ca243363be744a3d771ac4580f2244d5ebf9`, branch `codex/uup-user-workflow`. The concrete binder bug is fixed and covered by a small live production-producer regression. The selected source has **not** been rebuilt or rerun in this slice. Whole U06/U07, selected-source preflight fit, image application, native preservation and production admission remain incomplete.

## Root cause and actual data

The reviewed current-token run recorded in `native-selected-trial-20261029-174811-b3034e43/preflight-only-current-token.log` failed after **307.93s** at `fixed_apply_selected_windows_test.go:39`, in `BindSourceExpectations`. The executable was 9,311,744 bytes, SHA256 `d7c3cfc09ac0eb5262a552d1f2d4a1c422fac8139ddd08fee245c9ac70d57c56`. Its `preflight-exit.json` records exit1 and no elevation. It never reached provider construction, privilege acquisition or native application. The original log alone did not identify a field.

The rejecting invariant at base `internal/engine/preservation_expectations_windows.go:383` was:

```go
if id.SHA1 != s.SHA1 || !s.SizeKnown || id.Size != s.Size {
    return nil, ErrInput
}
```

This wrongly required the original **WIM index** to know a stream size even when the same original reference had already been resolved and byte-verified through a CAB by B5 and sealed into the canonical recipe.

Read-only diagnostic extraction from `task-6b3-actual-oracles.json` and `task-6b5-actual-union.json` established the original-versus-resolved values below. Both name the exact configured original Oracle digest `55c616fbf48127e824365337ad8a509a92b43b1a79043378a20dfa417d46b019`, metadata SHA1 `29256693076c5877942412848136d702889e3141`, metadata SHA256 `271d6f490baa2f90d497e0d21f721b56d4e2cfc5323feb0bfb491b9c2989201a`, manifest `675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9`, and index `ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a`.

| Field | Exact diagnostic value |
|---|---|
| First original unresolved use | Entry15, stream0, `/Program Files/Common Files/Microsoft Shared/Ink/hwrenclm.dat` |
| Dentry / stream offsets | 146504 / 146568 |
| Original reference ordinal / SHA1 | 7 / `ed032e12ed7c91466149b88eaa01d2a5b28d58c9` |
| Original stream / reference size | Size0, SizeKnown=false, zero WIM witnesses, original `missing-stream-reference` gap |
| Union reference7 | Same original reference/hash; one CAB witness; Size499248, SizeKnown=true |
| CAB content SHA256 | `dd6b45ec4dba1525fdd504affbc06eae8905560d36f07fd370ae4d89d98a1179` |
| CAB payload | `Microsoft-Windows-LanguageFeatures-Handwriting-en-us-Package-x86.cab`, SHA256 `a3aae6e22401168a96f77cfb4e05a4c7f0a3c2fbbefd4a879639a73115dfb84f` |
| CAB member | `x86_microsoft-windows-t..nkrecognition.en-ca_31bf3856ad364e35_10.0.19041.1_none_1d7c519f513a567d\hwrenclm.dat`, Size499248, offset43607, folder0 |

`task-6b3-missing-sample.json` independently retains that original raw dentry and offsets. The original producer report lists 774 unresolved references and 1457 uses; its first unresolved use is entry15. These historical files were used only as diagnostic **data**, never imported into a verified producer or capability. The field-specific original-run attribution comes from this data-flow trace and the matching live reproduction, not from a new instrumented large run.

The trace is intentional upstream behavior: `wimmeta/streams.go:212–215` copies the original WIM reference's size knowledge into the original stream. `wimcontent/references.go:221–222` separately records a size proved by complete WIM/CAB byte checks. `engine/source/references.go:90` seals that resolved SHA1/SHA256/size/provenance into the same original reference ordinal; `source/types.go:168` exposes only the live sealed resource. No producer or source API needed changing.

## Minimal reproduction and correction

Existing small preservation fixtures placed every nonempty stream in the WIM, so all original stream sizes were known. The new fixture keeps the same 11 hand-built original entries and places the default (`shared original`, 15 bytes), ADS (`named bytes`, 11 bytes) and reparse (`opaque reparse bytes`, 20 bytes) resources **only in an ordinary uncompressed CAB**. One unreferenced ordinary WIM resource satisfies the existing WIM content producer's nonempty-work contract. The fixture runs public manifest/index/decoded metadata/Oracle/WIM content/CAB/reference union/canonical recipe/reconstructed WIM/preservation proof producers. It imports no serialized authority and performs no native image operation.

Before the fix, the live fixture reached `BindSourceExpectations` and reproduced `unbound WIM reconstruction input` in 0.63s. Restoring only the old guard after adding diagnostics reproduced the exact small-fixture boundary: `phase=stream-resource entry=3 stream=0 offset=512`. The guard was restored to its fixed form before final checks.

The fix uses the already-sealed `EntryExpectation.Content[j]` identity and size for native observation descriptors, read budgets, complete stream comparison and bounded reparse reads. It still compares the original SHA1 and checks the original size whenever originally known. `Original`, original Oracle completeness/claim/gaps, original reference ordinal and all parent/digest checks remain unchanged. Encoded empty streams still use their existing zero-size/empty-byte representation.

Per the controller's explicit U07B3 ruling, the consumer separately discharges only an exact `missing-stream-reference` requirement whose entry, stream offset and hash match the original stream, and whose same live recipe reference yields exactly the retained full resolved resource identity, including SHA256, size and provenance. The historical gap remains accessible unchanged. Other unknown gaps remain requirements; no general gap whitelist was added. The small source still has original MetadataComplete=false and four original gaps, including all three missing-WIM-reference gaps, while the separate consumer can compare its fully resolved bytes.

Failure diagnostics add only fixed phase names and entry/stream/offset scalars, preserving wrapped error identities. Metadata-before/after, records, entries, streams, EAs, gaps, reparses and final liveness remain distinguishable without adding source/workspace locators or arbitrary diagnostic payloads.

## Verification and chronology

The first fixture setup attempt failed before binding with `unbound WIM content input` because a metadata-only WIM has no ordinary work. Adding the unused WIM resource corrected the fixture. The first implementation run passed binding/native budgeting and all independent mismatch negatives, but the equality test expected 256 too few read bytes: it omitted the two synthetic 128-byte inventory observations. The test expectation was corrected; that failed run is retained in `task-7b3-cab-green-initial.log`.

| Exact command | Result / retained evidence |
|---|---|
| `go test ./internal/engine -run '^(TestSourceExpectationsResolveCABOnly|TestSourceNativeObservationBudgetsResolvedCAB|TestPreservationComparisonUsesResolvedCAB)' -count=1 -v` before production changes | Behavioral RED, exit1, package1.187s; all three stop at binder `ErrInput`. `task-7b3-cab-red.log` |
| `go test ./internal/engine -run '^TestSourceExpectationsResolveCABOnly' -count=1 -v` with only the old guard temporarily restored | Behavioral RED, Go exit1, package0.452s; bounded exact phase/entry/stream/offset shown above. Restoration was in `finally`; the wrapper required Go exit1. `task-7b3-diagnostic-red.log` |
| `go test ./internal/engine -run '^(TestSourceExpectations(ResolveCABOnly|ResolveOnlyExact|CABResolution)|TestSourceNativeObservationBudgetsResolvedCAB|TestPreservationComparisonUsesResolvedCAB)' -count=1 -v` on final code | GREEN, exit0, package1.860s. `task-7b3-cab-green.log` |
| `go test ./internal/engine -count=1` on final code | Exit0, package32.633s. `task-7b3-engine.log` |
| `go test ./internal/engine/source ./internal/metadata/wimmeta ./internal/metadata/wimcontent ./internal/metadata/cabindex -count=1` on final code | Exit0: source1.857s, wimmeta0.619s, wimcontent6.173s, cabindex4.746s. `task-7b3-producers.log` |
| `git diff --check` | Exit0; only repository CRLF conversion notices from Git. |

The final regression proves the independent literal comparison of **11 entries and 7 streams**, no mismatches/unresolved fields, 86 default/ADS content bytes in native preflight, a separate 20-byte verified reparse read, and exact source/read accounting. Lowered reparse, comparison and native budgets refuse. Independent default/ADS content, size and reparse changes prevent complete comparison. Wrong gap kind/entry/offset/hash does not resolve; changed resolved SHA256/size/provenance, swapped/missing reference, foreign proof and closed source refuse. Original-source closure revokes content reads; generated-output closure revokes the native observer. An unknown original tag remains unresolved despite successful CAB resolution.

Self-review read the complete focused production/test diff, checked all original-size consumers, exact gap matching, source and generated-output lifetimes, unchanged SHA1/SHA256/provenance checks, reparse bounds and residual accounting. No helpers/reviewer agents, unrelated Minor changes, progress/whole-task acceptance edits, full-suite/vet/cross-build bundle or large-source replay were used.

## Next controlled real preflight

After review, request one controller-owned rebuild-and-rerun of the **same** `TestConfiguredFixedSelectedSourceApply` entry against the frozen source root, pinned to the reviewed fix commit and a newly measured test executable. Independently reconfirm the inherited non-elevated token lacks Backup/Restore/Security, retain the exact artifact SHA256/size, environment/request and complete log/exit receipts, then use the existing exact gate `UUP_FIXED_SELECTED_APPLY=reviewed-source-contract-0x182` and frozen absolute `UUP_FIXED_SELECTED_SOURCE_ROOT`. If that token condition changes, do not run this preflight-only scope. The desired new evidence is successful fresh expectation binding and the actual source-derived observer/preflight formula, followed by the existing missing-privilege refusal; a new boundary/limit failure is evidence to investigate, not authorization to raise caps or continue to an image call.

No original selected-source rerun, installed fixed provider construction, actual image/native load/apply/mount/capture/export/service, real privilege acquisition/adjustment, UAC/elevation, source/target/downloaded executable/DLL/script/shim, installer/setup/boot/recovery/publication or stopped original-ESD/wimlib route was performed in U07B3. Small ordinary fixtures and their existing installed data-codec/query ports are the only new execution evidence. The next real preflight remains controller-scoped; it is not authorized or performed by this report.
