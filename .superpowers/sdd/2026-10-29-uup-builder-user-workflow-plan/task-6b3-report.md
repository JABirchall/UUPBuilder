# U06B3 — Source-bound nested WIM metadata oracle

Status: **DONE_WITH_CONCERNS** for this bounded metadata-oracle slice. Implementation commit **75c7f7b — feat(metadata): add source-bound nested WIM metadata oracle**, based on `72cf7656dead0099b4c14e1c9c6b411ae722005d`, branch `codex/uup-user-workflow`. The concerns are the explicit semantic/reference gaps below and the stated memory-accounting boundary. Whole U06, content verification, reconstruction, operational Ensure and ISO support remain unproved. No controller ledger or acceptance box was changed.

## API, authority and lifecycle

Added `internal/metadata/wimmeta` with this production entry point:

```go
func Parse(ctx context.Context, artifact *wimindex.MetadataArtifact,
    idx *wimindex.Index, limits Limits) (*Oracle, error)
```

The public API accepts only B2's private read-only artifact type and the exact B1 immutable index. It cannot accept a path, asserted receipt, physical offset, arbitrary reader or injected codec. An externally constructed zero artifact cannot pass. The parser borrows the artifact; the caller must close it. It never modifies or closes the borrowed artifact, source files or index. The package-private byte parser used by synthetic tests cannot publish an authoritative result.

`Index.MatchesMetadataReceipt` compares the immutable source, manifest/index digest, complete payload identity, source SHA256/rehash flag, header, original entry/descriptor/location/image mapping, original SHA1 and original size. `Parse` checks the decoded SHA256 as well as original SHA1/size against all parsed bytes. Its final publication gate independently rereads the same artifact completely after parsing, reference mapping and digest construction. Changed, truncated, closed or canceled input returns no oracle. No error path returns a partial verified result.

The controller explicitly approved two focused immutable B1 read helpers, `MatchesMetadataReceipt` and `LookupCount`, because cloning `Index.Snapshot` or calling an unbounded `Lookup` first would defeat a lowered result budget. Binding checks scan existing immutable values and perform only small fixed digest-format allocations; they do not clone or serialize the index. Witness count and memory charges are checked before `Lookup` copies witnesses. B1/B2 construction, source verification, original index serialization, decoder geometry and codec contracts remain unchanged.

`Oracle.Snapshot` deeply copies every mutable slice, nested stream/tag/security/SID/ACL/ACE view, reference witness, hardlink member and end-marker record. `Summary` returns a bounded value. `MarshalJSON` is deterministic, location-free JSON; `Digest` is SHA256 of those exact JSON bytes, without a trailing newline. Traversal is disk-order DFS, security remains table order, index witnesses retain B1 order, and hardlink groups sort by original numeric ID. Runtime/private locations never appear in the oracle or its receipt. Source-relative WIM paths are metadata, never host output paths.

## Interpretation and limits

The iterative traversal interprets the security prefix, root and nested sibling lists, 0/8 end-marker values, aligned lengths, original names/short names, child offsets, attributes, raw FILETIMEs, security IDs, hardlink/reparse union and every main/extra stream record. A bitmap rejects reused/overlapping ranges, cycles and aliased child lists. Exact duplicate sibling/stream names fail; case remains unchanged. Original UTF-16 units are retained. Invalid UTF-16, embedded separators/nulls and other unrepresentable path components cannot become a different valid display path: parent/raw-name identity remains and the display path stays unresolved. Unknown tags, reserved/padding values and unreachable bytes are retained with explicit gaps.

Security descriptors remain raw self-relative bytes. The parser checks descriptor/header offsets, SID revision/count/extents, ACL extents/counts, ACE extents, supported SID-bearing ACE forms and optional object GUID extents. Unknown ACE bodies, callback application data and unsupported headers/flags stay explicit semantic gaps. Null versus absent ACL control bits remain in the original descriptor. No ACL or SID is applied to the host, and no authorization decision is evaluated.

Stream roles follow the documented main/extra unnamed precedence, named streams and reparse ordering. The all-zero hash denotes empty encoded data; it supplies size zero with `metadata-empty` provenance. Nonempty hashes obtain size only from exact index witnesses, marked `index-witness`; absent witnesses leave size unknown. All witnesses and duplicate-source ambiguity survive. Hardlink ID zero creates no shared group. Nonzero IDs preserve member records; conflicting inode fields remain distinct and unresolved. Source record offsets never influence inode consistency.

Zero limits select these hard ceilings; callers can lower them but cannot raise them:

| Budget | Ceiling |
|---|---:|
| One metadata artifact | 64 MiB |
| Accounted result and parser bookkeeping | 512 MiB |
| Dentries | 262144 |
| Tree depth | 256 |
| Total encoded streams, including main placeholders | 524288 |
| Streams per dentry | 4096 |
| Security records / tagged extra fields | 65536 each |
| ACEs | 1048576 |
| Copied original index witnesses | 524288 |
| One variable field / security descriptor | 1 MiB each |

Input size and impossible minimum result budgets fail before artifact reads/input allocation. Input is fully read in 64 KiB portions and hashed within its separate 64 MiB cap. Counts, extents, variable sizes and conservative fixed/variable memory charges are checked before the associated result allocations. No recursive traversal is used. Context checks cover reads, traversal, budget operations, descriptor/ACE/resource loops and final verification; cancellation before publication always discards the result.

The 512 MiB value is conservative accounting for retained result structures and parser bookkeeping, **not a whole-process Go/native peak guarantee**. Existing immutable index memory, the bounded input buffer, temporary JSON encoding buffers, and caller-owned accessor/serialization copies are separate. JSON encoding and hashing check cancellation at their operation boundaries. Final selected-image accounted bytes: **352631784**. Final integration-process samples after all artifacts/source checks: HeapAlloc **497513808**, HeapSys **993689600** bytes. These are samples, not measured peaks; the final verification ran alongside the normal suite/builds. No B2/native limit was raised.

## Primary format evidence

Read as documentation only; no wimlib code/helper was imported, copied into production, compiled or executed:

- [wimlib v1.14.5 dentry.c](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/src/dentry.c): on-disk dentry/extra-stream definitions, sibling termination, name lengths/alignment and main/extra stream-role precedence.
- [wimlib v1.14.5 security.c](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/src/security.c) and [security.h](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/include/wimlib/security.h): security prefix, original descriptor sizes and self-relative representation.
- [wimlib v1.14.5 tagged_items.c](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/src/tagged_items.c) and [tagged_items.h](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/include/wimlib/tagged_items.h): tag/length/data/padding framing. The header defines tag 2 as extended attributes; it does **not** define observed tag 4. No semantics for tag 4 were inferred.
- [wimlib v1.14.5 inode_fixup.c](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/src/inode_fixup.c): zero/nonzero hardlink identifiers and the need to preserve inconsistent records rather than merge guessed fields.
- [Microsoft winnt.h](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h), [SID](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid), [ACL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl), [ACE_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header), [object ACE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace), [callback ACE](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_callback_ace), [security descriptor control](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control): relative offsets, structural extents, optional GUIDs, control and ACE flags. Structural interpretation does not evaluate callback/application conditions.

## TDD evidence

Before substantive parser implementation, stub-backed behavioral RED:

```text
go test ./internal/metadata/wimmeta -run 'TestNestedTree|TestTree|TestInvalidUTF16' -count=1
--- FAIL: TestNestedTreeKeepsExactRecordsAndStreams
    nested metadata interpretation missing: WIM metadata interpretation implementation gap
--- FAIL: TestTreeRejectsInvalidStructureAndBudgets
--- FAIL: TestInvalidUTF16IsLosslessAndNeverBecomesAnotherPath
FAIL uupbuilder/internal/metadata/wimmeta
```

The malformed/budget tests required the specific layout/limit/cancel failures, so the missing-parser error also failed them. Security and stream tests were separately RED before the implementation:

```text
go test ./internal/metadata/wimmeta ./internal/metadata/wimindex -run 'TestSecurity|TestExtraStreams|TestMetadataBinding' -count=1
--- FAIL: TestSecurityStructureAndUnknownACEArePreserved
--- FAIL: TestSecurityRejectsInvalidExtents
--- FAIL: TestExtraStreamsReparseAndTaggedMetadata
    WIM metadata interpretation implementation gap
ok uupbuilder/internal/metadata/wimindex 0.018s
```

The index helper's initial RED was `go test ./internal/metadata/wimindex -run '^TestMetadataBinding' -count=1`, failing `exact binding/count missing`; after its implementation that test passed, including false source/manifest/index/payload/header/entry/hash/size bindings and mutation checks.

Further focused RED checks found and then corrected these concrete publication/preservation issues:

| Command selector in `go test ./internal/metadata/wimmeta -run '<selector>' -count=1` | Observed expected RED |
|---|---|
| `TestPublicOracle\|TestReferenceSize\|TestFinalArtifact` | `digest is not the exact deterministic serialization` (encoder newline) |
| `TestRootName\|TestExactSibling\|TestImpossibleResult` | `named root normalized into valid root path`; read of a closed artifact before rejecting impossible result budget |
| `TestWitnessAmbiguity\|TestIndependentRecord` | witness copy count and tagged-field count accepted despite lowered ceilings |
| `^TestExtraStreamsReparseAndTaggedMetadata$` | original tagged-record offset missing |
| `^TestEndMarkerOriginalValuesAreRetained$` | original 0/8 end-marker values missing |
| `^TestHardlinkComparisonUsesTagValuesRatherThanRecordLocations$` | equal tag values at different record offsets incorrectly marked a hardlink conflict |
| `^TestUnknownACEAndReparseFlagsRemainUnresolved$` | `reserved ACE flag treated as understood` |

Final affected GREEN after the last acceptance guard:

```text
go test ./internal/metadata/wimmeta ./internal/metadata/wimindex -count=1
ok uupbuilder/internal/metadata/wimmeta 0.057s
ok uupbuilder/internal/metadata/wimindex 0.230s
```

Coverage also includes exact sibling collisions/case preservation, short names, malformed name terminators and extra streams, invalid child ranges/alignment/length, alias/cycle/overlap, depth/count/field/security/ACE/result/input budgets, empty/default/named streams, reparse references, inconsistent hardlinks, invalid UTF-16, security IDs/SIDs/ACLs, closed/changed/truncated artifacts, cancellation, accessor mutation, exact witness sizes/provenance and duplicate-source ambiguity. Synthetic fixtures prove parser behavior, not actual source completeness.

## Configured actual proof and identities

Actual command (final run after the last semantic guard; no new downloads):

```powershell
$env:UUP_WIM_ORACLE_PREPARED_ROOT=(Resolve-Path -LiteralPath '.superpowers/sdd/2026-10-29-uup-builder-user-workflow-plan').Path
go test ./internal/metadata/wimmeta -run '^TestPreparedNestedMetadataOracle$' -count=1 -v
```

The test opens the frozen manifest/original 13 WIM/ESD sources, reproduces B1's exact digest, calls **production `DecodeMetadata`**, then passes all 15 returned private artifacts into **production `wimmeta.Parse`**. It independently hashes every final artifact against the original entry SHA1/size and decoded SHA256, and finally independently hashes all 13 original files against their frozen B1 SHA256/size. Artifacts are closed on exit. The retained B2 copies were hash/size checked before their limited research inspection; their paths/receipts never grant production authority.

Frozen source: UUID `3d12aa3e-806a-46c9-900e-bf7613959273`, catalog `19045.7811`, x86/en-us/professional. Manifest digest **675cf6f2462def2f1a07f533d477488cde9e30217dd272acee2857c5fe8abef9**; index digest **ce99b93ee46a341ac8d339163ca32da2ac0231b52893e62cc30fbf0b74461f5a**. Selected `professional_en-us.esd` source SHA256, also reproduced finally: **edf4967f0d9f8b8703d24489f727786cd314c43a26cfdc111e5d3b8e40d13dc0**.

Selected lookup-order image 3: original metadata SHA1 **29256693076c5877942412848136d702889e3141**, decoded SHA256 **271d6f490baa2f90d497e0d21f721b56d4e2cfc5323feb0bfb491b9c2989201a**, **18731096 bytes**. Its deterministic oracle digest is **55c616fbf48127e824365337ad8a509a92b43b1a79043378a20dfa417d46b019**.

Final relevant output:

```text
metadata=professional_en-us.esd image=3
summary={Entries:78515 Directories:13567 Streams:78515 Security:352 ACEs:3340 References:39471 HardlinkGroups:19843 Reparse:2 Gaps:14515 AccountedBytes:352631784}
complete=false metadata-verified=true
parsed=15/15 evidence-sha256=d1efdca336ca13472e3046ec1589448a1beeddaf0f2becfda57381420af4d4e8
Go-heap-alloc=497513808 Go-heap-sys=993689600 content-verified=false conversion-supported=false
--- PASS: TestPreparedNestedMetadataOracle (17.32s)
ok uupbuilder/internal/metadata/wimmeta 17.425s
```

All 15 artifacts, totaling **35187080 decoded bytes**, parsed successfully: **154132 entries/encoded streams**. Thirteen oracles have no explicit metadata/reference gap; professional image 2 and image 3 remain incomplete. All actual dentries encode only a main hash: no actual extra/named-stream record was observed. Named-stream behavior is synthetic coverage only. All 15 full oracle digests, original receipts, counts, exact gap records, absent-hash inventory and all **1457** missing-reference use records are retained in the JSON evidence, with bounded original-record/tag/security/hardlink/reparse witnesses.

## Exact unresolved inventory and representative witnesses

| Resource | Unresolved inventory |
|---|---|
| professional image 2 | **17637 tag-4 records**, all observed payload length 4; metadata complete=false |
| professional image 3 | **13546 tag-2 extended-attribute records**, **195 type-9 callback ACEs**, **774 nonempty hashes absent from the current 13-container WIM index**; complete=false |

The 774 absent hashes have **1457 active default-data uses**, no directory uses, no reparse uses and no extra/named-stream precedence ambiguity. Of those uses, 275 encode hardlink ID zero; the remainder retain their nonzero IDs/groups. This is a gap in current WIM-index source closure. It does **not** prove absence from the complete 40-payload manifest or upstream. As the controller noted, that manifest also contains Handwriting/TabletPCMath/Hello-Face and other FOD/language CABs; these are plausible candidates, not proven byte matches. CAB decoding/content closure was not attempted here.

A separately bounded retained-byte cross-check visited only 99 records to compare the first eight absent references with original fields. Examples under `/Program Files/Common Files/Microsoft Shared/Ink/` are `hwrenclm.dat`, `hwrenUSlm.dat`, `hwrusash.dat`, `micaut.dll`, `mip.exe`, `mraut.dll` and en-US MUI counterparts. Each sampled record has attributes `0x20`, security ID 5, child offset zero, extra-stream count zero, a nonzero main hash and a nonzero hardlink ID with two retained members. For `hwrenclm.dat`: dentry offset **146504**, length **128**, main hash **ed032e12ed7c91466149b88eaa01d2a5b28d58c9**. Primary precedence therefore makes it an active default stream. Hardlink grouping cannot manufacture its absent bytes or size. The final production proof retains these raw records plus all missing uses, so it does not depend on the research script.

Tag-4 samples in image 2 at offsets **22616**, **22760**, **22904** have payload **02000000** (length 4), associated with `ink/tabskb.dll`, `ink/TabTip.exe`, `ink/TipRes.dll`. The checked pinned primary tag header does not define tag 4. It remains unknown. Image-3 tag-2 samples at offsets **145984**, **147160**, **147416** have lengths **108**, **117**, **117**. The first starts **58000f002443492e434154414c4f4748494e540001005400**. Raw EA payloads/padding are preserved, with no arbitrary EA-value interpretation or application.

All 195 ACE semantic gaps are type 9. Owner/group SIDs, ACL/ACE sizes and the embedded trustee SID extents validate; callback application data remains uninterpreted and `Understood=false`. The evidence retains security-table ID **9**, its **480-byte** original descriptor, and its parsed structural views as a representative callback witness. Security-table ID 0 is retained separately. These facts do not establish full security reconstruction.

Other selected source facts:

- `/Windows/System32/kernel32.dll`: dentry offset **3904096**, security ID **5**, hardlink ID **281474976756627**, raw FILETIMEs **132201724468431685**, SHA1 **9d62d08a7de5152db50a7bbac02ee36e0dc299db**, size **644960** from exact index witnesses.
- Hardlink group **281474976756467** retains DFS entries **19400** and **60906** (`kbdibm02.dll` and its WinSxS name); recorded fields are consistent. Group counts include every encoded nonzero ID, including single-member IDs.
- `/Users/All Users`: offset **2063904**, attributes **9238**, security ID **211**, tag **0xa000000c**, flags **1**, reparse-stream SHA1 **4261f11a3a16537c4b87698b8f3c795929ed0212**, index size **76**.
- `/Users/Default User`: offset **2064048**, same attributes/security ID/flags, tag **0xa0000003**, SHA1 **1a324a6d1a0fba19ffc95ca84d720ede328cfa18**, index size **84**. Reparse bytes/targets were not decoded.

## Final validation, retained evidence and review

Final native full suite after the last acceptance guard:

```text
go test ./... -count=1
20 packages passed; cmd/uupbuilder has no test files
internal/metadata/wimindex 1.209s; internal/metadata/wimmeta 0.109s
tests/probes 20.256s; no failed package

go vet ./...
(no diagnostics; exit 0)

GOOS=windows GOARCH=386 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=arm64 go build ./...
(all exit 0)
```

The normal suite's private configured checks remain unconfigured/skipped; that is not counted as functional proof. The separate configured B3 command above passed 15/15. B2 was not independently rerun solely for reassurance; B3 legitimately regenerates its artifacts as integration input. The final full suite/builds were repeated only because self-review added the reserved-flag acceptance fix. The first build-log wrapper hit an unsupported PowerShell `Tee-Object -LiteralPath -Append` combination; that wrapper was corrected and all three final commands then completed successfully. No skipped or failed wrapper/check is represented as a pass.

Private evidence paths below are relative to this report directory and remain ignored:

| Artifact | Bytes | SHA256 |
|---|---:|---|
| `task-6b3-actual-oracles.json` | 5626332 | `d1efdca336ca13472e3046ec1589448a1beeddaf0f2becfda57381420af4d4e8` |
| `task-6b3-actual-oracles.log` | 5462 | `30383fbf78e7a1ae5be685d0cd12ca8fe39487977fe689db9acc1090ac3e0d74` |
| `task-6b3-full-test.log` | 900 | `7a79a81c9ed3b7a1b548450762faaf8ef815ddc0949b14b45881ed3a0ee8faf7` |
| `task-6b3-build.log` | 124 | `36ad84c27ee19e6f6a7a3e74dd1291894a7a2e82b85520dd0ca1558fcdc238bf` |
| `task-6b3-missing-sample.json` (bounded research only) | 7079 | `7af635285566b343cd9245b9f30578091cfe1b877b1908454699a850ace97e5a` |

Files: `wimmeta/oracle.go` owns the API/result/limits/publication boundary; `tree.go` owns bounded nested traversal/names/tags; `security.go` owns security records; `streams.go` owns stream/reference/hardlink interpretation. Their focused tests and `actual_test.go` provide the synthetic/configured evidence. `wimindex/binding.go` and its test are the sole B1 extension. No existing parser block or unrelated code was duplicated/refactored.

Self-review corrected JSON-digest newline identity, named-root display handling, pre-read minimum budgets, separate witness/extra-field count limits, marker/tag offset preservation, location-independent hardlink comparison and unknown ACE/reparse flag acceptance. Final diff check was clean. The remaining strict canonical alignment/root-list support, budget ceilings and uninterpreted EA/callback/tag semantics are implementation limits; they are not source-unavailable claims. Independent review remains controller-owned.

No source downloads, CAB/file-content/solid decode, original script execution, image API, mount/apply/export/capture/servicing, elevation/privilege change, host installation, target/source DLL execution, downloaded wimlib route or ISO claim occurred. Only the unchanged B2 **1 MiB RAW LZMS** mechanism was used while regenerating metadata. Solid/file-content closure, including the separate reviewed 64 MiB contract, is the next separate slice. Original sources and B2 probe contracts are unchanged.

## Fix round 1

Review base: **17f4098ff98aebc16d8a99c0f7c695e67270805b**. Fix commit: **04292d2 — fix(metadata): keep unsupported control and EFS semantics unresolved**. Addressed the exact Important findings **U06B3-I1** and **U06B3-I2** after checking both code paths and their cited primary definitions. The separately deferred Minor U06B3-M1 wording is unchanged. No controller ledger was edited.

For I1, [Microsoft's control documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control) and the [public winnt.h definitions](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h) enumerate the supported mask **0xff3f**. `security.go` now records `security-control-semantics` for unsupported stored bits, including `0x0040` and `0x0080`, at the original control-word offset. Its detail retains the exact unsupported bit value; the full original descriptor/control word remains unchanged. Documented control combinations retain their existing structural interpretation.

For I2, rechecked pinned [dentry.c](https://raw.githubusercontent.com/ebiggers/wimlib/v1.14.5/src/dentry.c), specifically `assign_stream_types_encrypted` and `write_dentry_streams`: encrypted data streams are packed into one EFS raw stream identified by the first nonzero unnamed hash; ordinary default/named/reparse assignment belongs to the unencrypted branch. `streams.go` now separates those branches. A valid EFS raw main hash or unnamed extra remains `encrypted-raw`, with an unused zero main placeholder where appropriate. Missing identifiable EFS raw data, named extras, additional unnamed records and an encrypted/reparse combination are explicitly `encrypted-stream-semantics` gaps. Unsupported records use `unresolved-encrypted`, preserving names, hashes, offsets and reference witnesses instead of ordinary data roles. Encoded zero-hash reference size still has `metadata-empty` provenance; this does not assert an empty decrypted file or an understood EFS layout. No EFS content decoder or capability was added.

Covering test files and exact names:

- `internal/metadata/wimmeta/security_test.go`: **TestPublicDescriptorControlSemanticsGateCompleteness** uses otherwise gap-free artifacts produced through the existing public B1/B2 fixture boundary. Controls `0x8040`, `0x8080` and combined `0x80c0` must preserve raw bytes and produce the sole expected semantic gap, with `MetadataVerified=true` and `Complete=false`. Supported controls `0x8000` and `0xff3f` remain gap-free/complete for metadata only.
- `internal/metadata/wimmeta/streams_test.go`: **TestPublicEncryptedStreamSemanticsGateCompleteness**, with **streamLayoutFixture**, covers 12 public-bound cases: zero main/no extras, zero-main directory, main EFS raw, unnamed-extra EFS raw, EFS plus named/nonempty or named/empty extras, named extra without EFS raw, multiple nonzero unnamed hashes, an empty unnamed extra, encrypted/reparse, and unencrypted empty/named controls. Every nonempty hash has an exact index witness, so unrelated missing-reference gaps cannot hide the acceptance failure. Tests check exact roles, gap kinds/counts, original attributes/hash/name preservation, size provenance and content/conversion flags remaining false.

I1 behavioral RED before its guard:

```text
go test ./internal/metadata/wimmeta -run '^TestPublicDescriptorControlSemanticsGateCompleteness$' -count=1 -v
--- PASS: .../0x8000
--- PASS: .../0xff3f
--- FAIL: .../0x8040
    unsupported control 0x8040 counted complete or unresolved inventory lost: complete=true gaps=[]
--- FAIL: .../0x8080
    unsupported control 0x8080 counted complete or unresolved inventory lost: complete=true gaps=[]
--- FAIL: .../0x80c0
    unsupported control 0x80c0 counted complete or unresolved inventory lost: complete=true gaps=[]
FAIL uupbuilder/internal/metadata/wimmeta 0.042s
```

GREEN after the guard, same exact command: all five subcases passed; `ok uupbuilder/internal/metadata/wimmeta 0.037s`.

I2 behavioral RED before separating encrypted roles:

```text
go test ./internal/metadata/wimmeta -run '^TestPublicEncryptedStreamSemanticsGateCompleteness$' -count=1 -v
--- FAIL: .../zero-main-no-extras
--- FAIL: .../zero-main-directory
--- FAIL: .../efs-with-named-extra
--- FAIL: .../efs-with-empty-named-extra
--- FAIL: .../named-extra-no-efs
--- FAIL: .../encrypted-reparse
    encrypted acceptance lost: complete=true gaps=[]
--- FAIL: .../multiple-unnamed-hashes
--- FAIL: .../efs-with-empty-unnamed-extra
    unrelated gap hides unsupported encrypted semantics {stream-role 1 232 extra unnamed stream has no unambiguous role}
--- PASS: .../main-efs-raw
--- PASS: .../extra-efs-raw
--- PASS: .../unencrypted-empty
--- PASS: .../unencrypted-named
FAIL uupbuilder/internal/metadata/wimmeta 0.064s
```

During test authoring, an incorrect repeated-byte hash expectation was corrected from `11...` to the fixture's actual `01...` before this RED run. The valid-layout control cases then passed against the pre-fix implementation, so the retained RED above isolates the actual unsupported-role behavior. GREEN after the role fix, same exact command: all twelve subcases passed; `ok uupbuilder/internal/metadata/wimmeta 0.066s`.

Final focused amended-behavior verification:

```text
go test ./internal/metadata/wimmeta -run '^TestPublic(DescriptorControl|EncryptedStream)SemanticsGateCompleteness$' -count=1 -v
--- PASS: TestPublicDescriptorControlSemanticsGateCompleteness (0.03s)
--- PASS: TestPublicEncryptedStreamSemanticsGateCompleteness (0.05s)
17/17 subcases passed
ok uupbuilder/internal/metadata/wimmeta 0.094s
```

Final affected-package check, with the configured source proof explicitly unconfigured:

```powershell
$env:UUP_WIM_ORACLE_PREPARED_ROOT=''
go test ./internal/metadata/wimmeta -count=1
# ok uupbuilder/internal/metadata/wimmeta 0.129s
```

All affected behavioral tests passed; the private configured test was skipped, not counted as fresh functional proof. Per the scoped fix instructions, the prior 15/15 observed-source evidence and full-suite/vet/architecture evidence above were not repeated solely for reassurance. This round changes only the unsupported semantic paths and their tests; it does not add observed-source coverage or widen any B1/B2/RAW LZMS limit.

Self-review: inspected all four changed code/test files and the focused diff; `git diff --check` passed. The unencrypted precedence/fallback is unchanged, valid encrypted layouts remain identifiable, public artifact/source authority and copied accessors are untouched, and new gaps retain normal budget/cancellation/publication gating. The actual EA/callback/tag-4/current-WIM-index missing-hash inventories remain unresolved as before. Complete metadata acceptance, decrypted contents, security reconstruction, conversion and ISO support are not inferred from these fixes. No new download, original source write, host/image operation, helper or reviewer was used.
