# U06B5 — Verified WIM file-content decoding

Status: DONE_WITH_CONCERNS for this bounded data-only slice. Whole U06, reconstruction, servicing, operational Ensure and ISO support remain incomplete. Implementation commit: **6fd712e — feat(metadata): verify bounded WIM file content and reference union**, based on `6d59a676e785e25d46f67a0e6de760ef564fd300`, branch `codex/uup-user-workflow`.

## Result and exact scope

The configured production path decoded every original nonmetadata record in the frozen 13-container index: **54,694 / 54,694 active witnesses**, zero inactive witnesses, **26 unique physical backing resources** (15 solid and 11 ordinary raw), **6,558,510,563 retained logical bytes**, including **6,518,144,764 solid bytes**. All original SHA1/exact sizes and separately computed SHA256 values passed; every blob was independently reread before publication, and the configured test independently reread all 6,558,510,563 witness bytes again. All original source handles were fully checked against their original digest, computed SHA256, size, retained identity and named path before reparse and after decoding; the configured test additionally independently rehashed all 13 WIM/ESD sources at the end.

There were **103 solid chunks**: **102 compressed** native RAW LZMS calls and **one stored raw solid chunk**. The 11 raw ordinary resources are counted separately as 11 stored units, giving **114 total declared chunk/resource units** and **12 stored units**. All solid declarations were 64 MiB. Native decoding ran in the current AMD64 process on native AMD64 Windows build 19045, using installed measured cabinet.dll SHA256 **382b026e091d6e63c36ad386b632dadae2b321492362a039000de42fa28b0885**, **164680 bytes**. This is actual larger-block operation, distinct from compilation, synthetic ports, skipped configuration, physical x86/ARM64 hosts or conversion capability. The large multi-chunk backing has 32 chunks, 31 compressed; its full chunks take the exact 64 MiB output path into DecodeInto. Native success alone never grants a receipt.

Necessary live integration preparation recreated B1/B2/B3 and B4 authorities, rather than treating retained JSON as production authority. Explicit B2 composition verified all **15 original metadata records** by full SHA1/size/SHA256 reread. The selected image-3 WIM/CAB view resolved **39,471 / 39,471 references**, including the 774 original WIM-missing hashes through **871 original CAB witnesses**, with **zero unresolved references**. Original B3 evidence and metadata completeness remain unchanged.

## APIs and immutable authority

`wimcontent.Decode(ctx, manifest, files, originalIndex, limits) (*Result, error)` accepts the frozen manifest, exact local identities and the live immutable production B1 index. There is no public range, asserted hash, reader, provider path, injectable codec, index constructor or serialized receipt input that can mint content authority. Initial count/string/result checks precede manifest normalization/copies and full-container reparse. Source files remain the same read-only retained handles through full initial verification, independent framing reparse, resource reads and final full verification. Each live reparse compares the complete original header/entries/images and mapping to the private original index.

The controller explicitly approved these focused shared boundaries:

- `wimindex.ContentClaim`, `ContentContainerAt`, `ContentEntryAt`: immutable value/count accessors without a hidden whole-index/container clone. `CompareContentContainer` is only framing comparison against the private original index, not source or content authority. Its entry allowance must be positive; zero is exhausted.
- `metadata/privatestore`: extracted the existing CAB generated-name protected local NTFS custody/created-file identity/read-only reopen/checked cleanup logic. The CAB adapter remains thin and retains its old API, limits and behavior. Shared File objects are locked for reads/close; the owner revokes every retained borrower before removal. CAB empty-read close behavior has an explicit regression test.
- `cabindex.Catalog.Claim`, `WitnessAt` and live `Result.Binding`: value-only claims/counts before copies, complete original oracle binding and closed-parent refusal. No whole catalog Snapshot/JSON is needed to obtain authority/counts.
- `BindReferences` and optional `ComposeMetadata`, described below. No broader construction/provider/servicing interface changed.

`Result.Catalog` is immutable, deterministic, location-free JSON with its SHA256 digest. It retains exact original source/index/header/entry/provenance and separate blob/backing digests. Snapshot copies nested mutable slices. The original Index is never mutated: `NonMetadataVerified=true` belongs to the new content catalog; its `ContentVerified` and `ConversionSupported` remain false.

`Result.Content(witnessIndex)` returns a read-only bounded interval borrower over its one retained backing handle, without opening a handle per witness. Its receipt includes the exact original Entry and logical offset; Binding returns the original value-only index claim. `Result.Close` revokes all interval readers, closes the bounded backing handles and removes only checked owned entries. Receipts/catalog values remain historical evidence after Close. Cleanup failures are latched on repeated Close and identify preserved owned scopes. No partial batch can be returned as verified; source, output, codec close, file close, custody, cancellation or cleanup failures discard the unpublished result or preserve owned evidence with an error.

`BindReferences(ctx, content, oracle, cabResult, limits)` binds the exact original source/manifest/index/oracle and both immutable catalog digests, before allocation. It rehashes every used live WIM/CAB artifact completely, requires each receipt/Binding to match, retains all matching provenance and ambiguity, and refuses conflicting equal-SHA1 sizes or SHA256 bytes. It creates a new immutable ReferenceView with exact unresolved hashes. Its readers borrow both parents; closing either parent revokes view reads. Closing the view revokes its borrowers and leaves the parents owned by the caller. Historical receipts do not imply later readability.

`ComposeMetadata(ctx, content, index, liveB2Artifacts, limits)` is the explicit additional byte-composition boundary. It requires every original metadata ordinal exactly once, exact original index/source/header/entry bindings, live artifacts and complete SHA1/size/SHA256 rereads, plus another full retained backing check. Missing, duplicate, foreign and closed metadata is rejected. Only this new MetadataComposition may claim whole-index `ContentVerified=true`. It retains the original index claim and metadata receipts without changing B1/B2/B3. `CheckLive` checks the borrowed parents; its snapshot is historical byte evidence. Metadata application/security/EA semantics and ConversionSupported remain outside this claim.

## Framing, native contract and budgets

The alternate solid format is implemented independently from the pinned primary definitions: a 16-byte logical-size/chunk-size/codec header, followed by N little-endian 32-bit compressed sizes. Counts, lengths, physical extents, sums, final partial chunks and reusable pair requirements are checked before codec loading or large chunk allocations. Raw stored chunks bypass native decoding. Logical blob offsets never become physical offsets. Full original backing descriptors canonicalize aliases across separate solid runs; B1's overlap/conflict/canonical descriptor checks are independently repeated on the original held handles.

The exact index's 11 ordinary resources are all raw and supported. Compressed ordinary N-1 tables, XPRESS/LZX, pipable/split or other unsupported layouts remain explicit implementation refusals. No alternate framing was inferred from B2, and no second N-1 implementation was copied. An unsupported layout is an implementation gap, not evidence of upstream absence.

`rawlzms.SolidProvider` is a separate installed-OS RAW LZMS contract. `OpenSolid` selects the installed system provider internally and accepts only lowerable `SolidLimits`; `DecodeInto` borrows bounded caller input/output buffers. Each input and output is at most **64 MiB**. Old `MaxBytes=1 MiB`, `Decode`, `Provider.Decode`, probe and B2 limits remain unchanged. Both contracts share the same focused installed-DLL/native lifetime primitive; no unbounded native entry point is exposed. Old 1 MiB provider/guard tests and legacy Foundation checks passed in the full suite.

Zero public limits select hard ceilings; positive values only lower them:

| Budget | Hard ceiling |
|---|---:|
| Original WIM/ESD sources | 64 |
| Manifest payloads / queries / projected payloads | 4096 / 64 / 4096 |
| Aggregate manifest strings / one identity field / runtime path | 16 MiB / 4096 bytes / 32768 bytes |
| Destination components | 64 |
| Original index entries / retained witness budget | 524288 |
| Unique backing resources / retained backing handles | 256 |
| Chunk entries per resource / aggregate declared chunk+raw units | 131072 / 262144 |
| Source size / aggregate source bytes | 4 GiB / 8 GiB |
| Logical backing / aggregate private decoded output including ordinary | 4 GiB / 8 GiB |
| Native input / native output / simultaneous live caller chunk buffers | 64 MiB / 64 MiB / 128 MiB |
| Aggregate source, framing and retained-byte reads | 64 GiB |
| Accounted result/reparse/record/table/map/seal memory | 512 MiB |

The fixed 64 KiB hashing and bounded B1 parser buffers are separate from the caller chunk-pair ceiling; caller buffer limits below 64 KiB fail before those helpers. Reparse charging includes XML decode/tokenization/image values and repeated identity serialization, not only entry counts. Raw caller identity fields and locators are bounded before validation/error formatting/normalization/keys or copying. Exhausted residual allowances are refused rather than passed as helper default sentinels. Declared resource/output/read/count limits and free private storage are checked before native construction. At most one reusable input/output chunk pair is live per streamed resource; no complete backing or image is buffered in memory.

Disk preflight uses the actual fresh private temp volume, requires all declared decoded logical bytes plus at least 64 MiB conservative reserve (or 64 KiB per backing), checks maximum file size, and reserves declared bytes for partially written files as soon as they are created. It does not reuse the old preparation 3x-copy estimate. This configured operation required **6,558,510,563 WIM file bytes**, plus **35,187,080 live B2 metadata bytes** and **391,368,460 CAB witness bytes** (total **6,985,066,103 decoded logical bytes** across the three owning producers), existing original sources, inventory JSON and filesystem overhead. Borrowing/composition creates no additional decoded copy. All live decoded stores/artifacts were closed and removed by the configured test; retained JSON is historical evidence, and later assembly must regenerate live authorities.

These are logical/accounting ceilings, not whole-process or whole-volume peak guarantees. Existing caller/index/oracle memory, caller accessor/JSON copies, Go runtime/allocator retention, native OS codec allocations and DLL mappings, NTFS clusters/metadata/journal and other processes are outside the stated measured/accounted numbers. Native internal peak was not measured or bounded by the caller-buffer contract. Cancellation is checked in reads, hashes, resource/chunk loops and before/after native calls; a single synchronous OS call cannot be preempted.

## Primary references

Read as format/API documentation only; no wimlib or other downloaded/source/target code was executed:

- [wimlib v1.14.5 resource.h](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/include/wimlib/resource.h), `alt_chunk_table_header_disk`, solid flags and table widths.
- [wimlib v1.14.5 resource.c](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/src/resource.c), documented original/solid distinctions, chunk geometry, raw chunks and partial final chunks.
- [wimlib v1.14.5 blob_table.c](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/src/blob_table.c), original backing/blob descriptor and logical mapping definitions used by the existing B1 reader.
- [CreateDecompressor](https://learn.microsoft.com/en-us/windows/win32/api/compressapi/nf-compressapi-createdecompressor), [Decompress](https://learn.microsoft.com/en-us/windows/win32/api/compressapi/nf-compressapi-decompress), and [Using the Compression API](https://learn.microsoft.com/en-us/windows/win32/cmpapi/using-the-compression-api). RAW requires the exact original output size; even native success can yield wrong bytes, hence full original digest checks.

## TDD and focused evidence

Initial tests preceded each new contract group. The first RED runs failed compilation specifically because the requested SolidProvider, immutable index accessors, private store, alternate parser, decoder/result or reference/composition APIs did not yet exist. These were missing API REDs, not behavioral acceptance. Relevant commands and GREEN results:

| Command | Initial missing-contract RED | GREEN |
|---|---|---|
| `go test ./internal/rawlzms -run TestSolidContract -count=1` | undefined SolidLimits/OpenSolid/ErrSolidLimit | full package `ok 0.016s` |
| `go test ./internal/metadata/wimindex -run TestContentClaims -count=1` | undefined ContentClaim/entry/container/Compare methods | `ok 0.019s` |
| `go test ./internal/metadata/privatestore -count=1` | undefined New/Profile/ErrLimit | `ok 0.058s` |
| `go test ./internal/metadata/wimcontent -run TestAlternateFraming -count=1` | undefined bounds/Limits/inspect | `ok 0.014s` |
| `go test ./internal/metadata/wimcontent -run 'Test(DecodeVerifies|WrongNoop)' -count=1` | undefined Result/decode/codec | `ok 0.575s` |
| `go test ./internal/metadata/cabindex -run TestContentValueClaims -count=1` | undefined Binding/WitnessAt | `ok 0.116s` |
| `go test ./internal/metadata/wimcontent -run 'Test(BoundUnion|UnionRefuses|WholeIndex)' -count=1` | undefined BindReferences/ComposeMetadata | `ok 0.715s` |

Behavioral self-review RED/GREEN pairs:

```text
go test ./internal/metadata/wimcontent -run TestBoundFingerprintMismatch -count=1
RED: mismatched witness returned no integrity error <nil> (0.224s)
Cause: mismatch with no I/O error passed nil through the integrity wrapper.
GREEN: integrity mismatch now always returns ErrIntegrity; combined focused run ok 0.181s.

go test ./internal/metadata/cabindex -run TestClosedCABArtifactAlso -count=1
RED: closed empty read remained usable <nil> (0.287s)
Cause: shared retained File was closed, but CAB adapter's data pointer remained nonnil.
GREEN: adapter nils its data after close; full CAB package passed subsequently.

go test ./internal/metadata/wimcontent -run TestReparseXMLAllocation -count=1
RED: large live XML reparse bypassed lower result budget <nil> true (0.457s)
Fixture: 128 KiB XML comment encoded as UTF-16; only six index records and 256 KiB caller result cap.
GREEN: XML/repeated-identity reparse charges precede normalization/reparse; ok 0.030s.

go test ./internal/metadata/wimcontent -run TestTotalChunkBudget -count=1
RED: two solid chunks plus one raw resource bypassed aggregate chunk budget <nil> true (0.204s)
GREEN: aggregate declared units include ordinary raw resources before framing/native construction; ok 0.018s.
```

Other focused tests cover exact partial/raw/compressed framing, zero/oversized/trailing/header mismatches, lower buffer/count/read/output/storage/result budgets, raw oversized unbound identity preallocation (less than 1 MiB Build allocation allowance for a caller-owned 7 MiB name), nil/zero authority, original wrong blob hashes, corrupt tokens, no-op/wrong/error/close-failing codecs, cancellation/source/caller-slice mutation, logical intervals crossing chunk boundaries, canonical aliases across runs, seeded equal-SHA1 size/SHA256 contradictions, nested accessor mutation, partial owned cleanup, unknown-entry preservation and latched cleanup failures, foreign/closed bound parents and missing/duplicate/closed B2 metadata. Synthetic codec ports remain private test-only evidence and provide no native capability proof.

A controlled directory-rename test initially expected the rename to succeed, but Windows denied it because the live directory custody handles exclude that rename. The test was corrected to require either blocked rename with valid custody/cleanup, or an integrity refusal after a successful controlled rename. No product failure was hidden. An early gofmt wildcard invocation failed on Windows wildcard expansion; explicit filenames corrected it before later validation.

Final affected command before full validation:

```text
go test ./internal/metadata/wimcontent ./internal/metadata/privatestore ./internal/metadata/cabindex ./internal/metadata/wimindex ./internal/rawlzms -count=1
ok wimcontent 3.946s; privatestore 0.409s; cabindex 3.449s; wimindex 0.498s; rawlzms 0.023s
```

Afterward the last aggregate raw-chunk guard had its RED/GREEN above, and all final production code was included in the full validation and final configured proof. A final test-only exhausted-private-framing/read-remainder check was added while those commands ran; latest complete wimcontent tests passed **2.117s**, and focused wimcontent vet exited 0. It verifies zero remains exhausted rather than selecting any default.

## Actual commands, identities and retained evidence

```powershell
$env:UUP_WIM_CONTENT_PREPARED_ROOT=(Resolve-Path '.superpowers/sdd/2026-10-29-uup-builder-user-workflow-plan').Path
go test ./internal/metadata/wimcontent -run '^TestPreparedContentDecodingAndSelectedUnion$' -count=1 -v -timeout 30m
```

No source download. UUID **3d12aa3e-806a-46c9-900e-bf7613959273**, catalog 19045.7811 x86/en-us/professional; original manifest **675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9**; immutable B1 index **ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a**; unchanged original image-3 oracle **55c616fbf48127e824365337ad8a509a92b43b1a79043378a20dfa417d46b019**. Necessary live B4 Build reproduced CAB catalog **9f0d4c899a8de0720619a316f20eee3921ee7ee226891cf620e4e3861af28beb**.

The first configured run passed **248.48s** with content catalog **559b33c62d0c388361885c269d44b925f35792ccd544f92328bba8f5f628c1d4** and union **e29bd4b93942ca2a643de1cad6e4e0e97dd7337fa8f993291fd7e9c46a5c9441**. It preceded the final XML/identity accounting, raw total-chunk guard, and CAB empty-read adapter fix. It is historical evidence; the final configured refresh below includes all production changes. No earlier standalone B1/B2/B3/B4 proof was rerun solely for reassurance: these were required live integration inputs.

The final configured run passed **324.98s** (`ok ... 325.117s`) while full tests/vet/architecture builds ran concurrently. Its exact key output was:

```text
decoded sources=13 backings=26 witnesses=54694 active=54694 inactive=0
output=6558510563 reads=32295312171 accounted=199711008
provider=cabinet.dll 382b026e091d6e63c36ad386b632dadae2b321492362a039000de42fa28b0885 164680 bytes
process/native=amd64/amd64 WindowsBuild=19045
solid=15 solid-bytes=6518144764 compressed-chunks=102 stored-chunks=12
selected-refs=39471 cab-witnesses=871 unresolved=0
whole-index-bytes=true conversion=false original-metadata-complete=false original-gap-records=14515
content=09f0bbb69bb9952bf602ab33ffd805d200196d59b06d4e38fcdaf13101a445e4
union=225200568cdc7c885e4ef797aadb55e44d94b4a2675aeb8090028137aa04b96d
PASS
```

The new union preserves **11,267 ambiguous provenance groups**, **50,010 matching WIM witnesses** and all **871 matching CAB witnesses**; ambiguity means multiple valid provenance witnesses with equal bytes, not conflicting bytes. Union rereads totaled **6,562,796,655 bytes**, with **342,374,424 accounted result bytes**. B2 metadata totaled **35,187,080 bytes**; explicit metadata composition reread **6,593,697,643 bytes** including another full WIM backing check. The final decoder accounted **199,711,008 result/reparse bytes** and **32,295,312,171 total source/framing/private reads** under its 512 MiB / 64 GiB ceilings. These are counters/accounting, not whole-process peaks.

All final decoded bytes/digests reproduce the first run; catalog digests changed because the corrected accounting value is part of the immutable catalog and the union binds that digest. The output label `original-semantic-gaps=14515` in the literal test log counts all original gap records, including the 774 historical missing-reference records; the semantic/reference distinction below is authoritative. Both actual runs passed; there was no failed or skipped required decode.

All 13 original container and 26 private backing SHA256 values, every original nonmetadata SHA1/size/descriptor/provenance and all reference witness relationships are retained in ignored location-free inventories beside this report. No runtime source paths, private store locations or capability tokens occur in their public receipts. Final evidence file sizes/digests:

| File | Bytes | SHA256 |
|---|---:|---|
| `task-6b5-actual-content.json` | 73,759,846 | `09f0bbb69bb9952bf602ab33ffd805d200196d59b06d4e38fcdaf13101a445e4` |
| `task-6b5-actual-union.json` | 75,612,094 | `225200568cdc7c885e4ef797aadb55e44d94b4a2675aeb8090028137aa04b96d` |
| `task-6b5-actual-metadata-composition.json` | 26,943 | `ff2ebdbc76c31d1e4bfaff820c01a043fddb95fad78ec70cc73b4ab3b9021f41` |

`task-6b5-actual.log` and `task-6b5-final-actual.log` retain both full configured command outputs. The final whole metadata/source/header/entry identities are in the inventories, rather than manually abbreviated into a second authority. Inventory statistics above were read after completion as historical report evidence only. The live artifacts were created by the production producers and closed/cleaned by their owners.

## Final validation and self-review

`go test ./... -count=1` passed **all 25 tested packages** (plus cmd/uupbuilder with no test files), including legacy metadata/RAW/probes. Optional configured tests in that default run were unconfigured/skipped, not counted as functional acceptance; the explicit configured integration above supplies actual evidence. `go vet ./...` exited **0**. Separate `GOOS=windows GOARCH=386`, `amd64` and `arm64` `go build ./...` each exited **0**. Exact full output is in `task-6b5-full.log`; vet/build success had no diagnostic output. These commands ran against the final production code concurrently with the final configured run. Builds prove compilation only on other architectures; no new physical-host or cross-process native support claim was inferred.

Self-review covered the entire focused new authority/framing/streaming/custody/reference/composition code, the extracted CAB adapter diff, old RAW guard preservation, result budgets before allocation, and partial/error lifetime paths. The four behavioral issues above were corrected and covered. `git diff --check` passed; `git diff --cached --check` exited 0 before implementation commit **6fd712e**. The report-only follow-up commit records these results; it changes no executable code. No dependency, Go baseline, application/TUI/configuration behavior, controller progress.md or whole-U06 acceptance checkbox changed. No helper/reviewer agent was dispatched.

Remaining scope/concerns: unsupported compressed ordinary/other codecs/layouts remain explicit implementation gaps; general discovery, other-source/global content closure, metadata EA/callback application, reconstruction, servicing, operational Ensure and ISO creation are still incomplete. Original B3 retains **14,515 original gap records**: **13,546 EA**, **195 callback ACE**, and **774 historical WIM-missing-reference records**. The new reference view resolves the bytes separately and does not erase those records or claim metadata semantic completeness. Current-process AMD64 native operation is proved; physical ARM64/x86 operation is not newly proved. The accounting/native synchronous-cancellation/OS memory and volume limitations stated above remain explicit. No image API, mount/apply/export/capture/servicing, elevation, privilege acquisition, host installation, source mutation, downloaded/source/target DLL/helper execution, shim, script route or publication occurred. The stopped downloaded-wimlib route remained prohibited and was not retried.
