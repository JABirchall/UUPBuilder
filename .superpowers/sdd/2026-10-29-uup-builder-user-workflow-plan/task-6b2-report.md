# U06B2 — Verified standard metadata-resource decoding

Status: **DONE** for this bounded slice. Canonical U06 remains incomplete and unchecked. Implementation commit: **40fd0f4 — feat(metadata): verify bounded standard WIM metadata decoding** (parent `136046d`, reviewed B1 alias repair). No controller ledger was changed.

## Implemented contract and B3 handoff

Added this production entry point beside the reviewed immutable index:

```go
func wimindex.DecodeMetadata(ctx context.Context,
    manifest model.PayloadManifest, files []metadata.LocalResource,
    idx *wimindex.Index, limits wimindex.DecodeLimits,
) ([]*wimindex.MetadataArtifact, error)
```

It decodes all eligible standard metadata resources in the exact supplied index. There is no public physical-range, descriptor, arbitrary ReaderAt, output-path or codec injection argument. The injected codec port used by framing tests is package-private and explicitly synthetic. Missing/changed manifest, provenance, encryption, source, container, header, entry or index identity fails without returning artifacts.

The manifest/files are copied, the original manifest is validated, every local identity must match it completely, and the exact immutable index serialization/digest is checked. Each source is opened read-only and retained from initial complete original-digest/SHA256 verification through independent same-handle B1 parsing, exact container comparison, decoding and the final complete source rehash. Path/handle identity, original size and modification time are checked by the unchanged reviewed `sourceView`. No B1 interpretation or hard limit was weakened. B1's physical alias grouping in `layout.go` is unchanged.

The standard framing reader computes chunk count without addition overflow, selects 32/64-bit offset width, checks table/physical extents, and streams N-1 offsets without retaining the table. It validates every chunk before loading a codec, then rereads/rechecks offsets during sequential decoding. Empty, duplicate, decreasing, oversized or out-of-range chunks fail. Stored chunks use their bytes directly; compressed chunks use exact expected output lengths, including the last partial chunk.

Output is first an unpublished private temporary file. Full sequential SHA1/exact size must match the original WIM record. The complete temporary file is then independently reread on the same handle and its original SHA1, size and computed SHA256 verified again. All source final rehashes and provider/handle cleanup must succeed before the artifact batch is returned. Codec success, plausible structure or partial batch success cannot publish a receipt. Error/cancellation removes current and earlier pending outputs.

`MetadataArtifact.Receipt()` returns a value copy containing exact source identity, manifest/index/source SHA256, complete original payload provenance/digest/size/encryption identity, header, original entry/descriptor/location/image index, original SHA1, decoded SHA256/size, provider identity and `SourceRehashed=true`. It contains no runtime path, locator, token or secret. `ReadAt` exposes only bounded reads within that verified size. B3 can use `io.NewSectionReader(artifact, 0, int64(artifact.Receipt().Size))`. `Close()` closes and removes its owned private temporary file; it is idempotent and retries failed deletion. Read-after-close fails. Callers must close every returned artifact. The API does not expose a write handle or a source handle.

For direct B3 inspection, the configured check retained **15 private evidence copies** (35,187,080 bytes) under this report directory's `task-6b2-decoded/<decoded-SHA256>.metadata`. `task-6b2-private-decoded.json` binds each relative private location to its complete receipt. Existing content-addressed evidence is checked rather than overwritten. These are internal metadata evidence bytes, not an image/directory product deliverable. Public receipts remain location-free. A future caller should use the verified API above; these retained copies must be hash/size checked against their receipts before parsing. The same API/check regenerates all bytes from `actual-preparation/prepared-source.json` and the existing source handles; no source download is needed.

Selected B3 input is:

```text
task-6b2-decoded/271d6f490baa2f90d497e0d21f721b56d4e2cfc5323feb0bfb491b9c2989201a.metadata
source: professional_en-us.esd, image index 3, entry 3 (lookup order)
original descriptor: offset 334736484, size 3228184, original 18731096, flags 6
original SHA1: 29256693076c5877942412848136d702889e3141
decoded SHA256: 271d6f490baa2f90d497e0d21f721b56d4e2cfc5323feb0bfb491b9c2989201a
decoded size: 18731096
part: 1; references: 1; LZMS chunk size: 131072
```

## Primary references and native provider

These primary sources were read as documentation; no wimlib code, downloaded helpers or target libraries were imported or executed:

- [wimlib v1.14.5 resource.c](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/src/resource.c), compressed-resource format description and `read_compressed_wim_resource`: ordinary N-1 offsets relative to table end, width transition at 4 GiB logical size, stored chunks and final partial chunk rules. Its separately described alternate/solid and pipable layouts are excluded here.
- [Microsoft compressapi.h](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/compressapi.h), retrieved 2026-10-29: `COMPRESS_ALGORITHM_LZMS=5`, `COMPRESS_RAW=(1<<29)`, DWORD algorithm, BOOL results, pointer-sized handles/SIZE_T lengths and output length pointer. The implementation uses those documented values and fixed exports.
- [Microsoft CreateDecompressor](https://learn.microsoft.com/en-us/windows/win32/api/compressapi/nf-compressapi-createdecompressor), [Decompress](https://learn.microsoft.com/en-us/windows/win32/api/compressapi/nf-compressapi-decompress): Cabinet provider, RAW block mode, exact original block output length, and the requirement to independently check data since successful decompression may produce wrong bytes for corruption.
- B1's previously reviewed `header.h`, `resource.h`, `blob_table.h`, `blob_table.c`, `wim.c`, `header.c` references remain the authority for descriptors/indexing; those parsers were reused unchanged.

The old native RAW LZMS body was extracted to focused `internal/rawlzms`. The historical `nativeLZMS` signature is unchanged and delegates to it. Its bounds/cancellation-before-loading contract remains **1 MiB input and 1 MiB output**. `extractObservedWIM`, Foundation acceptance and old probe tests/caps are unchanged. Production code imports no test code.

Only `GetSystemDirectory()/cabinet.dll` is accepted. The measured OS file is opened with read access and read-only sharing, retained while loaded, and hashed before and after use. `LoadLibraryEx` uses absolute provider path plus DLL-load-directory/System32 search flags; the loaded module must be the same physical file as the retained measured handle (also accommodates OS architecture redirection). Fixed documented CreateDecompressor/Decompress/CloseDecompressor exports only; no image API. Each chunk gets a fresh RAW decompressor, closed before the next call. OS library/file cleanup errors prevent publication.

Actual host: Windows `10.0.19045.0`, native/process AMD64, `go version go1.27.0 windows/amd64`. Actual installed provider: `cabinet.dll`, **164680 bytes**, SHA256 **382b026e091d6e63c36ad386b632dadae2b321492362a039000de42fa28b0885**, reported file version `5.00 (WinBuild.160101.0800)`. Provider dependencies, clean-machine materialization/rights and other host-native execution remain unproved.

## Budgets and observed memory

Zero decoder limits select these hard ceilings; callers can only lower them:

| Budget | Ceiling |
|---|---:|
| Metadata resources per call | 256 |
| Chunks per resource | 16384 |
| Logical bytes per resource | 64 MiB |
| Total logical bytes | 256 MiB |
| Resource reads (physical bytes + second table pass) | 256 MiB |
| Individual input/output chunk | 1 MiB |
| Simultaneous caller chunk buffers | 2 MiB |

Counts/output/read declarations are rejected before metadata reads/output allocation/native calls as applicable. Table offset memory is a fixed 8-byte value; tables are never buffered. Raw resources copy with at most 64 KiB (or lower caller buffer/chunk limit). Source verification and B1 parsing retain their separate fixed 64 KiB hashing / 50000-byte table buffers and B1 index/XML/count budgets. Decoded-file rehash uses a separate 64 KiB buffer after chunk buffers are dead. These are **caller chunk-buffer limits**, not a whole-process heap or OS-codec memory guarantee; immutable index serialization and retained B1 descriptor records also use Go heap. OS-managed internal decompressor allocation has no documented peak bound here. Cancellation is checked before/after each native call and throughout Go reads; a running native call is not interruptible.

Actual 15-resource geometry: **276 chunks**, 1,044 table bytes, **6,112,004 physical bytes**, **6,113,048 accounted resource-read bytes**, **35,187,080 decoded bytes**. All standard declarations are 131072 bytes, so every actual native input/output is within that declaration and the unchanged 1 MiB per-call ceiling. Final test memory samples after decoding plus independent artifact/evidence passes: Go HeapAlloc **68,534,480**, HeapSys **171,606,016**, TotalAlloc delta **108,748,304** bytes. These are process Go samples, not native peak measurements. The 64-bit table geometry/entry path is tested synthetically; the 64 MiB metadata output ceiling rejects complete resources at or above the format's 4 GiB transition.

## TDD and verification

Before substantive decoding, the boundary/cancellation test was observed RED:

```text
go test ./internal/metadata/wimindex -run 'TestStandardMetadataVerifiedBoundaryAndLifecycle|TestMetadataLimitsAndCancellationPreventCodec' -count=1
--- FAIL: TestStandardMetadataVerifiedBoundaryAndLifecycle
    verified metadata missing: WIM metadata decoder implementation gap
--- FAIL: TestMetadataLimitsAndCancellationPreventCodec/cancel
    WIM metadata decoder implementation gap
FAIL uupbuilder/internal/metadata/wimindex 0.041s
```

The stub deliberately returned the missing-decoder error. GREEN after implementation:

```text
go test ./internal/metadata/wimindex -run 'TestStandardMetadata|TestCodecSuccess|TestMetadata' -count=1
ok uupbuilder/internal/metadata/wimindex 0.076s
```

The installed-provider identity/lifetime test was also RED before implementation, then GREEN:

```text
go test ./internal/rawlzms -count=1
--- FAIL: TestSystemProviderIdentityAndClosedLifetime
    native LZMS provider must be pinned System32 cabinet.dll
FAIL uupbuilder/internal/rawlzms 0.012s
# after implementation:
ok uupbuilder/internal/rawlzms 0.015s
```

Self-review added a separate RED for independent decoded-temporary-file verification before publication:

```text
go test ./internal/metadata/wimindex -run TestDecodedTemporaryBytesAreReverifiedBeforeReceipt -count=1
--- FAIL: TestDecodedTemporaryBytesAreReverifiedBeforeReceipt/corrupt
--- FAIL: TestDecodedTemporaryBytesAreReverifiedBeforeReceipt/short
--- FAIL: TestDecodedTemporaryBytesAreReverifiedBeforeReceipt/extra
--- FAIL: TestDecodedTemporaryBytesAreReverifiedBeforeReceipt/cancel
    unverified temporary bytes accepted
FAIL uupbuilder/internal/metadata/wimindex 0.019s
# after implementing complete same-handle file reread:
go test ./internal/metadata/wimindex -run 'TestStandardMetadata|TestCodecSuccess|TestMetadata|TestDecodedTemporary' -count=1
ok uupbuilder/internal/metadata/wimindex 0.083s
```

Final focused checks after edge-case/lifecycle tests:

```text
go test ./internal/metadata/wimindex ./internal/rawlzms ./tests/probes -count=1
ok uupbuilder/internal/metadata/wimindex 0.247s
ok uupbuilder/internal/rawlzms 0.025s
ok uupbuilder/tests/probes 4.345s
```

Behavioral coverage includes raw/stored versus compressed chunks, final partial chunk, single/multiple chunks, width/count/overflow bounds, zero/decreasing/duplicate/outside offsets, before-read count/cancel, corrupt/changed source before and during decode, original expected hash/size mismatch, codec failure/no-op/wrong bytes, temporary output corrupt/short/extra/canceled, partial-batch cleanup, lowered budgets before codec, wrong manifest/payload/index/descriptor authority, accessor/caller mutation and closed artifact/provider lifetime. Synthetic codec tests prove framing/verification only. The historical Foundation/`extractObservedWIM` tests remain in the passing probes suite. The separately tagged historical 22000 ARM64 Foundation functional observation was not rerun or claimed; its runtime descriptor was not configured. B2's real 19045 x86 Foundation metadata is included in the independently verified 15/15 check below.

Configured actual command (executed successfully twice: first actual proof, then final provider/lifecycle/evidence-retention version):

```powershell
$env:UUP_WIM_METADATA_PREPARED_ROOT=(Resolve-Path '.superpowers/sdd/2026-10-29-uup-builder-user-workflow-plan').Path
go test ./internal/metadata/wimindex -run '^TestPreparedStandardMetadataDecoding$' -count=1 -v
```

Final exact relevant output:

```text
verified=15 bytes=35187080 index=ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a
provider={Name:cabinet.dll SHA256:382b026e091d6e63c36ad386b632dadae2b321492362a039000de42fa28b0885 Size:164680}
Go-heap-alloc=68534480 Go-heap-sys=171606016 Go-total-allocated-delta=108748304
content-verified=false conversion-supported=false
--- PASS: TestPreparedStandardMetadataDecoding (11.60s)
PASS
ok uupbuilder/internal/metadata/wimindex 11.636s
```

Every artifact was read completely again and its SHA1/exact logical size independently compared with B1's original resource record, then SHA256 compared with the receipt. Every retained evidence copy was also rehashed after close/reopen. The original descriptor index was independently reproduced before decoding. Source files were rehashed before and after decoding on retained handles; all original source identities match. Actual per-resource original SHA1/size/output SHA256, full bindings and rehash receipts are in `task-6b2-actual-metadata.json` and the complete actual log.

Representative image-3 prefix only: `f025020060010000e400000000000000c000000000000000a800000000000000`. This was retained as byte-format sanity; no dentry, security, path, stream or reference semantics were inferred.

Affected check (`task-6b2-affected.log`):

```text
go test ./internal/source ./internal/metadata/... ./internal/tools ./internal/download ./internal/jobs -count=1
ok uupbuilder/internal/source 9.843s
ok uupbuilder/internal/metadata 1.310s
ok uupbuilder/internal/metadata/providers 3.404s
ok uupbuilder/internal/metadata/wimindex 1.346s
ok uupbuilder/internal/tools 6.950s
ok uupbuilder/internal/download 17.453s
ok uupbuilder/internal/jobs 5.384s
```

Final broad verification (one full suite after final substantive code, exact complete output retained):

```text
go test ./... -count=1
?  uupbuilder/cmd/uupbuilder [no test files]
ok uupbuilder/internal/app 8.234s
ok uupbuilder/internal/catalog 0.253s
ok uupbuilder/internal/config 15.815s
ok uupbuilder/internal/download 30.984s
ok uupbuilder/internal/jobs 7.258s
ok uupbuilder/internal/jobstore 42.485s
ok uupbuilder/internal/metadata 2.009s
ok uupbuilder/internal/metadata/providers 2.965s
ok uupbuilder/internal/metadata/wimindex 1.762s
ok uupbuilder/internal/model 0.049s
ok uupbuilder/internal/planner 1.049s
ok uupbuilder/internal/platform/windows 4.658s
ok uupbuilder/internal/rawlzms 0.041s
ok uupbuilder/internal/registryhive 0.036s
ok uupbuilder/internal/source 14.444s
ok uupbuilder/internal/tools 10.196s
ok uupbuilder/internal/tui 7.198s
ok uupbuilder/internal/worker 23.522s
ok uupbuilder/tests/probes 19.418s

go vet ./...                     # exit 0, no diagnostics
GOOS=windows CGO_ENABLED=0 GOARCH=386 go build ./...    # exit 0
GOOS=windows CGO_ENABLED=0 GOARCH=amd64 go build ./...  # exit 0
GOOS=windows CGO_ENABLED=0 GOARCH=arm64 go build ./...  # exit 0
git diff --cached --check         # exit 0
```

All **19 tested packages** passed. Unconfigured actual tests are skips in the ordinary suite, not functional evidence; the explicit configured 15/15 run is the actual B2 evidence. Race checking was not run: `Get-Command gcc` found no compiler. Cross-builds establish compilation, not native execution on additional physical hosts. No full-suite failures were omitted. Git emitted only its configured LF-to-CRLF working-copy notices when staging.

## Immutable evidence identities

Frozen source: UUID `3d12aa3e-806a-46c9-900e-bf7613959273`, catalog `19045.7811`, x86/en-us/professional. Canonical manifest digest: **675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9**. Reproduced 13-source index digest: **ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a**. Selected container: 338670400 bytes, SHA256 **edf4967f0d9f8b8703d24489f727786cd314c43a26cfdc111e5d3b8e40d13dc0**. Original source bytes and original private descriptors were not changed.

All following private artifacts are relative to this report directory; raw input paths occur only in the existing private prepared descriptor. JSON file SHA256 is distinct from the canonical manifest/index digest:

| Artifact | Bytes | SHA256 |
|---|---:|---|
| `actual-preparation/selected-manifest.json` | 20167 | `77aac46059ea0247b80a62bf5d03924772bf45e3ab96b8f8c7fdc430658e1fb5` |
| `actual-preparation/prepared-source.json` | 53321 | `e9529aa610b1a25df0dad6fa8f33b759b65a74a2d00cf460f7b7b59527de986e` |
| `task-6b1-actual-index.json` | 48944 | `f850495caaee23208ba33dcf125e34aebce9b0973e6a1d47a86055bd5de7e844` |
| `task-6b2-actual-metadata.json` | 40503 | `1d03359a64d4ff7dc2302d997e37389385a8a1d0195ca3f328459c49f93dd994` |
| `task-6b2-private-decoded.json` | 42088 | `83b44a17e2beca1455d679560c5c92dbb4c11929d342f494949bdc89b9c7df24` |
| `task-6b2-actual-metadata.log` | 4785 | `7d5149cb218216a75ccfda9eaf0fd745d0bf56c0d3a5213e44e99a406708a9ab` |
| `task-6b2-affected.log` | 305 | `4b9d158f24fb07f4161167cf6b58c7020b7ca00d3ee66f914b6ca0f7b05d9d24` |
| `task-6b2-full-test.log` | 850 | `97fba44e83049231835ccf83a662cf155c8d0d8afd2880563231c185cbb8eae7` |
| `task-6b2-vet.log` | 38 | `01660a56c1ebb4ea328d81f6de051be5d832556cdd592c3e81dabca62202b1cf` |
| `task-6b2-build.log` | 134 | `c778c66c0c49d1217c0e1a56700bbf9df272bbeb49d6d3292f989cb6d34ec26c` |

The 15 `.metadata` filenames are their complete decoded SHA256 values; exact original SHA1/size, descriptor/container/source binding and each relative filename are in the private location manifest above. These private binaries/locators/logs remain ignored evidence rather than repository product resources.

## Files, self-review and remaining limits

Implementation commit `40fd0f4` changes:

- `internal/metadata/wimindex/metadata.go`: public limits, immutable receipt/read-only artifact lifecycle, production entry point.
- `internal/metadata/wimindex/metadata_decode.go`: exact frozen-source/index authority, same-handle source lifecycle, streaming output verification and batch publication boundary.
- `internal/metadata/wimindex/standard.go`: bounded standard table geometry, validation and chunk streaming.
- `internal/metadata/wimindex/metadata_test.go`: synthetic behavioral framing/integrity/authority/budget/cancellation/lifecycle tests.
- `internal/metadata/wimindex/metadata_actual_test.go`: configured exact-source 15/15 original-record proof, independent artifact checks, private evidence retention.
- `internal/metadata/wimindex/index.go`: package comment updated to distinguish descriptor indexing and separate metadata-byte verification; index API/behavior unchanged.
- `internal/rawlzms/{rawlzms,provider_windows,provider_other}.go`, `provider_windows_test.go`: focused shared installed-OS RAW LZMS primitive, provider identity/lifetime and unchanged per-call ceiling.
- `tests/probes/lzms_windows.go`: signature-preserving delegation; old acceptance/caps and Foundation readers/tests unchanged.

Self-review tightened decoded temporary-file rehash, bounded reader EOF behavior, deletion retries and same-physical-loaded-provider verification; the final actual/focused/full checks include those changes. The entry point remains a single bounded all-standard-metadata operation. No unresolved correctness concern was found within B2. The 315-line orchestration/verification file is focused on one operation; no broader refactor was attempted.

Unimplemented: solid alternate tables/resources (including every observed 67108864-byte declaration), standard non-LZMS compressed codecs, larger metadata/chunks, nested dentry/security/streams/reference semantics, semantic image-3 closure, reconstruction/servicing, operational Ensure and ISO production. Wider table arithmetic is understood/tested without lifting any production resource or native ceiling. Whole-index `ContentVerified` and `ConversionSupported` stay false. A verified metadata artifact proves its original bytes only.

No elevation, privilege changes, WIMGAPI/image API, mounts, apply/export/capture/servicing, target code, downloaded wimlib, original script execution, host installation, source downloads or external publication occurred. Sources were only opened read-only; generated private artifacts are owned/cleaned by this operation.

Deferred prior Minors remain separate and unchanged: U05 partial Begin cleanup (U05-M1), U06A composition wording (U06A-M1), U06B1 entry-limit fixture. See their existing controller/review ledger pointers; B2 neither resolves nor relabels them. B1 alias repair `136046d` and its reviewed physical grouping are preserved.
