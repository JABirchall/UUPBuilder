# U06B4 — Exact CAB content witnesses

Status: **DONE_WITH_CONCERNS** for this bounded CAB/reference slice. Implementation: **8b60b6dad4d2d0c4c4630f9a0fdc31616207fee8 — feat(metadata): verify source-bound CAB reference witnesses**, based on `abf76f00d9f7fd914af0254ad70bd0e3e96b62ac`, branch `codex/uup-user-workflow`. Report-only follow-up commit follows this implementation. Whole U06, reconstruction, operational Ensure and ISO support remain incomplete.

The final configured check resolved **774/774** originally missing image-3 hashes, with **871 exact CAB member witnesses**, **zero unresolved hashes**, and **391368460 retained logical member bytes**. Those witnesses retain all observed provenance: **92 ambiguous hash groups**, largest group **4**. They do not change the original B3 oracle or its semantic gaps.

## API, authority and ownership

`cabindex.Build(ctx, manifest, files, oracle, limits) (*Result, error)` accepts the original frozen manifest/local identities and a live production `*wimmeta.Oracle`. It accepts no asserted receipt, standalone hash, arbitrary reader, codec or provider path. Production always selects the installed OS FDI provider; test injection remains package-private. Inputs are copied, validated against the live source/manifest claim, and processed in canonical manifest-destination order, independently of caller slice order. A path or candidate filename never supplies byte authority.

`Result.Catalog()` exposes an immutable location-free catalog with SHA256 of deterministic JSON. `Snapshot` copies all mutable nested slices. It retains the original source/manifest/index/metadata/oracle receipt and digest, original reference claims and metadata summary/completeness, source attempts/skips, exact member ordinals/names/folders/offsets/sizes/attributes and source/member digests. `ReferenceClosure` concerns only references absent from this original WIM index. `ContentVerified` and `ConversionSupported` remain false.

`Result.Content(witnessIndex)` returns a borrowed private read-only `*ContentArtifact`; `Receipt()` returns its exact CAB witness and `Binding()` returns the complete original immutable oracle claim. Caller mutation of returned values cannot alter authority. `ReadAt` is bounded to the verified member. `Result.Close` revokes every borrowed reader, closes handles and removes only checked owned entries. Receipts/bindings remain historical evidence after Close; bytes return `os.ErrClosed`. Cleanup errors remain latched on repeated Close and identify preserved owned scopes. The configured test closes all artifacts after independent verification; the persisted inventory is historical evidence, and a later consumer regenerates live artifacts through Build.

Before native work, every selected CAB is opened read-only and completely verified for size, original digest and computed SHA256 on its retained handle, with handle/path SameFile and stability checks. All selected directories and aggregate declarations are checked before loading FDI. Complete sources are rehashed before publication; failed operations attempt final verification where cancellation permits. Every actual member is fully streamed and hashed, the retained candidate is reopened read-only with write/delete sharing denied, its original created-file identity is checked, and SHA1/size/SHA256 are independently reread. Final publication verifies artifacts and private directory custody again. Native success alone cannot publish a witness. Equal-SHA1 contradictory sizes/SHA256 fail; valid duplicate members retain distinct provenance. Nonmatches stay nonmatches; nested CAB bytes are refused as explicit unresolved gaps rather than recursively interpreted.

The controller approved three focused shared extractions: `metadata/cabformat` framing, `metadata/localsource` retained source verification with the old wimindex wrapper, and `platform/windows.SystemDLL` installed-library lifetime reused by RAW and FDI. It also approved the value-only oracle claims and final artifact Binding accessor. No helper/reviewer agents were used.

## Provider, ABI and bounds

The provider loads only an absolute installed-system `cabinet.dll`, through the shared measured/locked-file lifetime and restricted DLL search policy. The loaded module must be SameFile as the retained measured file. Close rehashes it and cleanup errors gate publication. There is no external extractor process or materialized CAB member path: FDI receives numeric input/output handles; every output name is generated inside a fresh protected local NTFS workspace. Spill/neighbor-cabinet access is refused. No member is executed, including run-after-extract flags.

The SDK defines `DIAMONDAPI` as **cdecl**. LONG/UINT are 32-bit and INT_PTR is pointer-sized; FDINOTIFICATION follows x86 pack-4 or Win64 natural alignment. Go 1.27's actual 386 call assembly explicitly supports cdecl/stdcall and restores SP from BP. Callbacks use `NewCallbackCDecl`. Exactly eight process-wide trampolines are registered, with context-aware serialized session dispatch, avoiding unreclaimable per-operation callbacks. The ERF value is pinned through FDIDestroy. Callback-provided stack/heap buffers are borrowed only during the call, with checked pointer+length, transfer and aggregate read limits; they are separate from fully tracked bounded PFNALLOC payloads.

Zero limits select these ceilings; nonzero values may only lower them:

| Budget | Ceiling |
|---|---:|
| Manifest payloads / queries / total projected payloads | 4096 / 64 / 4096 |
| Aggregate manifest strings / one string | 16 MiB / 4096 bytes |
| Destination path components | 64 |
| Selected CAB sources / one source / aggregate source bytes | 64 / 1 GiB / 2 GiB |
| References / aggregate members / retained witnesses | 524288 / 262144 / 16384 |
| Aggregate folders / CFDATA blocks | 4096 / 262144 |
| One CAB member name | 255 bytes |
| One member / aggregate declared folder output | 256 MiB / 2 GiB |
| Private logical payload bytes, including current partial candidate | 2 GiB |
| Metadata/name reads per source / aggregate | 32 MiB / 64 MiB |
| Accounted result / one framing directory | 256 MiB / 128 MiB |
| One callback transfer | 1 MiB; values below the shared 64 KiB hashing buffer fail before reads |
| Outstanding native allocations / requested payload bytes | 4096 / 32 MiB |
| Cumulative native allocation payload / provider source reads | 256 MiB / 8 GiB |

Framing validates header/folder/file/count/name/block extents, source/table overlap and member-range overlap before native calls. Counts and conservative fixed/variable charges precede directory/result allocations. No whole CAB or decompressed folder buffer is allocated. Declared/observed size overruns, limits, cancellation, provider errors and cleanup failures prevent publication and clean partial owned data where its custody remains known. Unsupported split/spanned/nonzero-cabinet layouts and Quantum are explicit refusals; nested members are explicit gaps. Unselected servicing CABs do not become baseline proof.

The legacy metadata adapter keeps **32 MiB CAB, 1024 folders/members, 16 MiB/member, 128 MiB declared output, flat ASCII names** and its existing extraction behavior; regression tests preserve its long-name error and opaque standalone cabinet ordinal. The old **1 MiB RAW LZMS APIs and decode geometry remain unchanged**. No dependency or Go baseline changed.

These are conservative data/accounting bounds, **not whole-process/native/volume peak guarantees**. Existing oracle/index memory, caller accessor and temporary canonical JSON copies, Go runtime and native allocator overhead, DLL mappings, and filesystem allocation/metadata/journal overhead are separate. The private disk limit accounts logical owned member payload bytes plus the current partial candidate; it is not an exact NTFS allocated-cluster/whole-volume bound. Native requested allocations are measured, not the allocator's physical overhead. Cancellation is checked at I/O/allocation/notification boundaries; FDI is synchronous and cannot be forcibly preempted if the OS codec stops making callbacks. ARM64 operation has compilation evidence only; the actual 386 evidence is WOW64, not a physical x86 host.

Primary contracts read: [FDICreate](https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fdicreate), [FDICopy](https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fdicopy), [FDIDestroy](https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fdidestroy), [FNALLOC](https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fnalloc), [FNWRITE](https://learn.microsoft.com/en-us/windows/win32/api/fdi/nf-fdi-fnwrite), [SDK fdi.h](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/fdi.h), [SDK fdi_fci_types.h](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/fdi_fci_types.h), and [Microsoft MS-CAB format](https://download.microsoft.com/download/4/D/A/4DA14F27-B4EF-4170-A6E6-5B1EF85B1BAA/%5BMS-CAB%5D.pdf). Also inspected installed SDK `10.0.26100.0/um/{fdi.h,fdi_fci_types.h}` and `C:/Program Files/Go/src/internal/runtime/syscall/windows/asm_windows_386.s`; documentation only, no downloaded/source/target helper executed. The existing owned process runner was inspected before choosing callbacks.

## TDD and focused checks

Focused commands use `go test <listed packages> -run '<listed test>' -count=1 [-v]`. The principal observed behavioral RED/GREEN pairs were:

| Packages / test | RED before implementation or fix | GREEN |
|---|---|---|
| cabformat / `TestDirectoryValidatesBeforeOutputAndHonorsReadBudget` | valid bounded directory rejected | package passed |
| localsource / `TestRetainedSourceChecksOriginalHashAndPathIdentity` | exact source rejected | exact hash/path checks passed |
| platform/windows / `TestSystemDLLIsInstalledMeasuredAndCloseRevokesExports` | installed provider unavailable | measured installed lifetime passed |
| wimmeta / `TestValueClaimsRequireLiveVerifiedOracleAndCannotMutateIt` | live claim incomplete | claims passed |
| cabindex / `TestBuildRetainsExactBytesAllDuplicateProvenanceAndMissingReferences` | provider implementation gap | native exact bytes, duplicates and explicit missing passed |
| cabindex / `TestFDIBorrowsBoundedNativeStackBuffers` | documented stack buffer rejected; actual FDI 36-byte header read was outside PFNALLOC storage | bounded immediate borrowed buffer passed |
| metadata / `TestLegacyCABLongNameRemainsMalformedAndOrdinalIsOpaque` | legacy long-name error changed | old error/ordinal behavior passed |
| cabformat / `TestDirectoryReservesCallerMemoryBeforeDirectoryAllocation` | directory memory limit bypassed | preallocation refusal passed |
| cabindex / `TestManifestAndReferenceCountsAreBoundBeforeValidationCopies` | invalid enlarged manifest reached validation instead of count refusal | pre-copy bound passed |
| cabindex / `TestFDIClosedLifetimeRefusesNativeCalls` | closed provider called stale export and test process faulted (`0xc0000005`) | `os.ErrClosed` before any native call |
| cabindex / `TestRetainedCandidateCannotBeReplacedByEqualBytes` | equal replacement bypassed file identity | original-file check passed |
| cabindex / `TestUnexpectedPrivateEntryPreventsPublicationAndCleanupIsReported` | extra private entry allowed publication | refusal and retained-cleanup report passed |
| cabindex / `TestClosePreservesCleanupFailureAfterRevokingReaders` | repeated Close hid cleanup error | latched failure/read revocation passed |
| cabformat / `TestReferenceNameCeilingRemainsAnExplicitLimit` | supported-bound excess called malformed | explicit reference limit passed |
| cabindex / `TestVariableNamesAndDirectoryCountsGateBeforeNativeConstruction` | variable/directory lower budget bypassed | all lowered field/name/folder/block cases passed |
| cabindex / `TestSourceOrderAndClosureSkippedIdentityAreDeterministic` | valid manifest permutation selected c.cab before b.cab | canonical order/explicit skipped identity passed |
| cabindex / `TestBorrowedContentCarriesImmutableOriginalBindingAndRevokesReads` | original artifact binding absent | nil/zero, copied complete claim and closed read revocation passed |

Fault tests cover no-op/wrong/short/overrunning output, changed source/output, provider-close failure, cancellation, aggregate/native/read/disk/witness budgets, partial-batch cleanup, nested material and duplicate provenance. Conflicting equal-SHA1 size/content guards use an explicitly seeded synthetic fingerprint contradiction, not a claim to possess a real SHA1-collision CAB. Native corrupt-checksum and canceled DLL-close tests are regression/characterization coverage. The test fixture WIMs pass through public B1/B2/B3 producers; production does not import test helpers.

One affected-check command mistakenly named nonexistent `./internal/probes`; its other nine packages passed and the command reported setup failure for that path. The correct `./tests/probes` passed subsequently and in the full suite. No failure was omitted or counted as a pass.

## Configured source proof and chronology

No source download. Exact UUID `3d12aa3e-806a-46c9-900e-bf7613959273`, catalog 19045.7811, x86/en-us/professional; manifest **675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9**. Necessary integration preparation recreated the original live 13-container index **ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a**, used production DecodeMetadata, and parsed only the selected image-3 oracle **55c616fbf48127e824365337ad8a509a92b43b1a79043378a20dfa417d46b019**. This was production input creation, not a standalone B1–B3 proof replay. Original metadata SHA1 **29256693076c5877942412848136d702889e3141**, decoded SHA256 **271d6f490baa2f90d497e0d21f721b56d4e2cfc5323feb0bfb491b9c2989201a**, size **18731096**.

```powershell
$env:UUP_CAB_REFERENCE_PREPARED_ROOT=(Resolve-Path '.superpowers/sdd/2026-10-29-uup-builder-user-workflow-plan').Path
go test ./internal/metadata/cabindex -run '^TestPreparedCABReferenceClosure$' -count=1 -v
```

The final run passed in **104.40s** while the full suite overlapped; the initial configured run had passed in 56.45s. No failed configured result was hidden. Final results: 39471 original references, 774 original missing hashes, **944 decoded members across all 22 selected baseline FOD/language CABs**, 871 retained witnesses, 774 distinct matching hashes, zero unresolved, zero CAB-specific gaps, 408513304 declared/observed bytes. Every retained witness was independently reread for SHA1, SHA256 and size; all 22 original CABs were independently rehashed for final SHA256/size after Build. All 22 supplied sources were needed; SSU and the four Windows update/enablement CAB identities are explicitly `not-selected` and supplied no baseline proof. Full attempted/skipped identities and member provenance live in the private inventory.

Installed AMD64 provider: cabinet.dll **382b026e091d6e63c36ad386b632dadae2b321492362a039000de42fa28b0885**, **164680 bytes**; process/native architecture AMD64/AMD64. Provider source reads **265286160** bytes; requested native peak **2183477**, cumulative **48036494** bytes; accounted result **15567512** bytes. These are the stated counters, not sampled process peaks.

Separately, the generated 386 Go test binary actually ran four native data tests under WOW64. It used installed x86 cabinet.dll **c4cf2b420d974630c3701e624b5849abf1cb1049d24e7bc9968c9366462a067f**, **136512 bytes**, process x86/native AMD64. Exact extraction, bounded borrowed callbacks, closed lifetime and corrupt-checksum refusal passed (5.083s). This is functional process/ABI evidence, distinct from physical-host and cross-build evidence.

Final full validation: **`go test ./... -count=1` passed all 23 tested packages**, **`go vet ./...` exited 0**, and **Windows 386/amd64/arm64 `go build ./...` all exited 0**. Optional configured proof tests in the default suite were skipped, not counted as functional acceptance. These binaries and the refreshed actual/WOW64 runs preceded only the final controller-approved additive `ContentArtifact.Binding` value accessor/field/final binding gate/test. No native/provider/producer/framing change followed them. The amended accessor had behavioral RED/GREEN (`ok ... 0.090s`) and the final entire cabindex package passed (`ok ... 1.697s`); its configured source test was unconfigured/skipped. Per controller direction, the full suite/vet/build/actual bundles were not repeated solely for this value accessor.

Retained ignored evidence, relative to this report directory:

| File | Size / identity |
|---|---|
| `task-6b4-actual-cab-witnesses.json` | **8319936 bytes**, SHA256/catalog **9f0d4c899a8de0720619a316f20eee3921ee7ee226891cf620e4e3861af28beb** |
| `task-6b4-validation.log` | Bounded observed command/output transcript and exact verification chronology |
| `task-6b3-actual-oracles.json` | Unchanged original B3 oracle/1457 missing-reference-use evidence; original missing result remains historical evidence |

## Self-review and remaining concerns

Reviewed the focused shared-adapter diffs and all new authority/custody/provider code, tested real installed native operations, and ran `git diff --cached --check` successfully before the implementation commit. Source/metadata/oracle digests reproduce; legacy extraction/RAW limits and public contracts remain intact. No controller ledger/progress or whole-U06 acceptance boxes were edited.

All originally missing hashes in this selected reference view now have exact CAB bytes. Original B3 metadata completeness remains **false**, with its original **14515** gap records still bound unchanged: 13546 EA records, 195 callback ACE records and the historical 774 missing-reference records. CAB matching supplies byte-derived sizes separately from original metadata/index sizes; it does not interpret/apply EA/security callbacks or silently rewrite those records. WIM solid 64 MiB file-content decoding, other-source/global closure, reconstruction, servicing, full Ensure/tool/ISO support and physical ARM64 functionality remain unproved. The logical disk/native-request accounting, synchronous cancellation and OS overhead boundaries stated above remain explicit concerns; no whole-volume or process peak claim is made. No image operation, source/target/downloaded helper execution, elevation, installation, source mutation or publication was performed. The stopped wimlib route was not retried.

## Fix round 1 — U06B4-R1 and U06B4-R2

Review base: **b6b0707c60a075aef561c3d73304ef40916b6b68**. Fix implementation: **f03a558cbd20565aca799c1c03ce6bb8963256c5 — fix(metadata): enforce CAB preallocation boundaries**. Read the verbatim round-1 findings and complete review, verified both production paths, and addressed both Important findings. No native/provider/shared-framing/default-limit/legacy behavior was redesigned.

**R1:** `build.go` now checks the remaining result allowance alongside the existing metadata/declared-output remainders before `cabformat.Inspect`. An exhausted result remainder returns `cabindex.ErrLimit`; it can no longer become the framing parser's zero/default 128 MiB allowance. The nonzero checked remainder is then passed to Inspect. The shared parser's zero/default contract stays unchanged.

**R2:** Before `PayloadIdentity.Validate`, error formatting, or name normalization, `build.go` checks all six caller-supplied identity string fields against the existing `MaxVariableBytes`. It then requires exact identity membership in the already bounded/validated manifest. Only bound, bounded identities can reach the existing validation/normalization path. Source authority is tightened; no arbitrary input path/receipt or reader grants authority.

Changed files: `internal/metadata/cabindex/build.go`, new `internal/metadata/cabindex/preallocation_test.go`, and this appended report. Exact covering tests:

- `TestExhaustedResultRemainderRefusesBeforeCABFraming`: hand-derived **39408-byte exact initial charge** (`286*8 + 1*256 + 2*16384 + 4096`), with two independent parser sentinels. A valid source with a one-byte parser metadata budget and a correctly source-hashed malformed signature must both return the Build result-limit error before framing can observe its own budget/signature errors. This asserts the actual early boundary, rather than only a provider-construction count.
- `TestUnboundSuppliedIdentityNameIsBoundBeforeNormalization`: caller-owned **8388612-byte uppercase unbound `.CAB` name**, with a 40 KiB result limit, tested under default and lowered (256-byte) variable caps. The early variable-limit error and a generous **less-than-1-MiB Build allocation** assertion detect the full lowercase copy. Caller input construction is outside the measured interval; counters include bounded bookkeeping/runtime noise and are not whole-process peak claims.
- `TestSuppliedIdentityFieldsAreBoundBeforeValidation`: six subcases cover digest algorithm/value, provenance source/name, and encryption method/fingerprint. All require the variable-limit refusal before ordinary validation.

R1 behavioral RED, before its guard:

```text
go test ./internal/metadata/cabindex -run '^TestExhaustedResultRemainderRefusesBeforeCABFraming$' -count=1 -v
FAIL .../valid-source-parser-budget-sentinel
    framing began after exact result exhaustion: cabinet framing limit exceeded
FAIL .../malformed-source-signature-sentinel
    framing began after exact result exhaustion: malformed cabinet framing
FAIL uupbuilder/internal/metadata/cabindex 0.027s
```

GREEN after R1, same command: both subcases passed; `ok uupbuilder/internal/metadata/cabindex 0.028s`.

R2 behavioral RED, before its guards:

```text
go test ./internal/metadata/cabindex -run '^Test(UnboundSuppliedIdentityNameIsBoundBeforeNormalization|SuppliedIdentityFieldsAreBoundBeforeValidation)$' -count=1 -v
FAIL .../default-variable-cap
    Build allocated 8411056 bytes for an unbound 8388612-byte uppercase name
    supplied name did not hit its early variable bound: unbound CAB content input
    unbound name reached allocating normalization: 8411056 bytes
FAIL .../lowered-variable-cap
    Build allocated 8405960 bytes for an unbound 8388612-byte uppercase name
    supplied name did not hit its early variable bound: unbound CAB content input
    unbound name reached allocating normalization: 8405960 bytes
FAIL all six TestSuppliedIdentityFieldsAreBoundBeforeValidation subcases
    supplied identity reached validation before its variable bound: unbound CAB content input
FAIL uupbuilder/internal/metadata/cabindex 0.135s
```

GREEN after R2, same command: all eight subcases passed; measured Build allocations **6544** and **3344** bytes; `ok uupbuilder/internal/metadata/cabindex 0.062s`.

Final focused verification after both guards:

```text
go test ./internal/metadata/cabindex -run '^Test(ExhaustedResultRemainderRefusesBeforeCABFraming|UnboundSuppliedIdentityNameIsBoundBeforeNormalization|SuppliedIdentityFieldsAreBoundBeforeValidation)$' -count=1 -v
PASS all three tests / ten subcases
Build allocation counters for uppercase unbound name: 8896 and 3344 bytes
ok uupbuilder/internal/metadata/cabindex 0.045s

go test ./internal/metadata/cabindex -count=1
ok uupbuilder/internal/metadata/cabindex 1.556s
```

Self-review: inspected the exact two guard changes and complete new regression file, confirmed positive/default input behavior through the affected package tests, and ran `git diff --cached --check` successfully before the implementation commit. The earlier 774-hash closure/inventory, full suite, vet, architecture builds and WOW64 checks remain **historical evidence**, not latest-code proof. They were not replayed for these two guards; the configured source test was unconfigured/skipped in the affected package run. No shared parser change required cabformat verification. Original source/oracle/artifact authority, native limits, cleanup and all previously reported scope/accounting concerns remain unchanged. No controller progress or acceptance file was edited, and no helper/reviewer was dispatched.
