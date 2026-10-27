# Source-format census and Gate S

Recorded 2026-10-27. **Sampled census; Gate S has no passing family.** No source
was proved globally upstream-unavailable. Observed metadata, missing algorithms,
missing fixtures, transient request errors and missing upstream material remain
different facts. `testdata/compatibility/required-cases.json` preserves those
dimensions and keeps unknown families visible. No payload, CAB, image, helper
or signed locator is committed.

The accepted design requires all ISO-capable upstream formats and all targets.
Catalog visibility does not establish conversion support. An implementation gap
must not hide a target, rename valid sources “unavailable”, substitute another
build or turn incomplete media into a success. A selected `updateonly` response
does not establish the whole UUID's media capability.

## Research origin and limits

The coordinator's `source-census-research.md`, `source-research/` metadata and
`research-evidence-digests.json` record the actual requests and retained bytes.
[Official JSON API](https://git.uupdump.net/uup-dump/json-api) reference commit:
`c82a95ae6377743f2712ac0bd060e673f4478b0c`. Pinned resolver
[get.php](https://git.uupdump.net/uup-dump/api/src/commit/7386a277aa8656fb6f8210d4b5731a44acaac30b/get.php)
and [requests.php](https://git.uupdump.net/uup-dump/api/src/commit/7386a277aa8656fb6f8210d4b5731a44acaac30b/shared/requests.php)
commit: `7386a277aa8656fb6f8210d4b5731a44acaac30b`. Source snapshots measured
SHA-256 `f7c8b88ec4a6db06a5d54e697d01f6a87ea3b116997eb5ecb0b35ce8b4872068`
and `f6d5ac7065e0d7bbc0d63fcfdb42bf24682d9cd488c45a5b89b5acded2e62b10`.
These upstream source references were read, not adopted or executed as an
engine. Their Apache-2.0 notices do not establish rights to Microsoft payloads.

Saved descriptors used `get.php?...&noLinks=1`, returning `url=null`,
`uuid=null`, `expire=0`, `debug=null`. No signed URL, signature query, cookie,
key or decryption secret is in the ledger. The offline database path does not
prove current availability of a Microsoft payload. Requests were bounded to
2 MiB/45 seconds; oversized Server/cumulative responses were retried with
en-us. Bounds are research limits, not evidence of absent sources.

The resolver removes/renames `_Diffs_`, `_Forward_CompDB_`, `.cbsu.cab`,
`baseless_` and express/PSF alternatives. Its public file list cannot exhaust raw
source families. Raw CompDB attributes/payload records were inspected separately.
Unsuffixed sampled UUIDs default to requested resolver revision 1; this is not
an echoed Microsoft revision or the same fact as CompDB document Revision=1.
The descriptors preserve this revision uncertainty explicitly.

## Actual sampled selections

All ten noLinks selections returned HTTP 200 on the research date. “all” is
unfiltered language/edition. Counts describe resolver-returned selections.

| Build / target | UUID (resolver default revision 1) | Selection | Files | Snapshot bytes / local SHA-256 |
| --- | --- | --- | ---: | --- |
| 15063.0 / x86 | `fd9add47-948f-4017-9571-01c6cbbf4ad7` | all | 1014 | 177177 / `b62369a62b7d2bca672d656e171dafd905453ef22f3de80b2f88eef91e98d603` |
| 16299.15 / amd64 | `0b504c39-d86f-48f2-a8be-38df4167178c` | all | 791 | 136244 / `6a34e41fcb890e54f228881119b2fc830d0b497f1ed082ab790558b1ab5c01eb` |
| 19041.1 / x86 | `3b507ad4-99b0-4630-b979-7c220b37a002` | all | 2063 | 530430 / `dafa97b8d39f4e3962523cdab2089f0fb464e597241a4c496d2c6ed15551effd` |
| 22000.1 / arm64 | `a1b78728-530f-443f-b672-d742e7c14bcb` | all | 2317 | 442284 / `0feebe279dbd4b6c55ddee75b022ff583e4e6369a2b2c32813865363da07feaa` |
| 26100.1 / amd64 | `3d68645c-e4c6-4d51-8858-6421e46cb0bb` | all | 7410 | 1915140 / `950238143f417e47e802ccf3e592ea0344544b410336d3f8da60ce6bcf12a126` |
| Server 2025 26100.1 / amd64 | `30da46b4-2ff2-4682-a9ae-23b66dd98713` | en-us | 147 | 37501 / `0a2c97b0a23f6fd53d408e23b6f68b36e876e678c9414dc7087188efb473fdc6` |
| Cumulative 26100.1 / amd64 | `82bfaf56-2ef9-49ce-89fa-daa9c9eaff11` | en-us | 190 | 48543 / `50bc9ccc8b080583ba9bc4a3f8c6b4db06eab48249fb006374a32be91d65c9cc` |
| Preview 26100.1882 / amd64 | `89da9278-1ece-4c82-b791-d624d229924d` | en-us / professional | 95 | 24177 / `9680ac93b8d578ce62d99b2ded21a2bcef1007ca3148faed700c54e8719a3e54` |
| Feature 28120.3302 / amd64 | `5486793c-ef16-4f21-b397-f0321a833424` | en-us / professional | 96 | 24389 / `235491d55fa072d4319ccb88058a9f60357ed121476ede3d5a3f08c6afa70cc6` |
| Cumulative 22000.160 / arm64 | `db8ec987-d136-4421-afb8-2ef109396b00` | en-us / updateonly | 6 | 1269 / `f777b31d9a645c502a4f0445195232ad9380d705cd875b43d6fb2842cb5267aa` |

Snapshot hashes are metadata-byte identities, **never expected reconstructed
file/image hashes**. Optional API sha256 was populated in the sampled
19041/26100 sets and null in 15063/16299/22000. Preserve the actual expected
digest algorithm; a local SHA-256 does not invent an upstream expected SHA-256.
`appxPresent=false` with app payloads, and `hasUpdates=false` on a cumulative
record, demonstrate that flags/titles cannot replace semantic inventories.

## Actual Microsoft CompDB observations

The 22000.1 ARM64 professional/en-us online response supplied a declared HTTP
metadata locator on `tlu.dl.delivery.mp.microsoft.com`. Scheme-changing to HTTPS
failed name verification (`SEC_E_WRONG_PRINCIPAL`); the declared HTTP request
succeeded, 2026-10-27 04:41:27 UTC, without weakening certificate checks.
The retained CAB was 1146246 bytes, matching the API's expected SHA-1
`fc9cd5aa6972bc862550ce1baa2f0a4a44b47e2b`. Its locally measured SHA-256 is
`245c6f6e69081a504b20a16da4566b330dc8011bd89a2747cca9dbe083a1aa21`.
Upstream SHA-256 was null; no Microsoft catalog/signature check was made. The
local hash does not strengthen the original authentication or prove HTTPS
delivery. Exact signed locators are deliberately omitted.

Built-in expand was used during prior research only, with selected metadata
members, then secure XML parsing (no DTD/resolver; 4 MiB character bound). Actual
roots are CompDB namespace `http://schemas.microsoft.com/embedded/2004/10/ImageUpdate`,
schema 1.2, document revision 1, architecture arm64. Classification uses explicit
attributes and records, not filenames. Expanded XML retained `.cab` suffixes.

| Member / explicit semantics | Direct packages and payloads | Expanded bytes / local SHA-256 |
| --- | --- | --- |
| DesktopTargetCompDB_professional_en-us.xml.cab; Type=Build, OSVersion=10.0.22000.1 | 44 packages; 44 Canonical | 24048 / `3f1705c8ed1b8a2ff5b52899929536acebe760810561de4a16877ba41343cb90` |
| DesktopBaselessCompDB_en-us.CompDB.xml.cab; Type=Baseless, OSVersion=10.0.22000.1 | 40 packages; 40 ExpressCab + 40 ExpressPSF | 43914 / `9b597e01c646d7ad93ba6f9108beeb420affebd8a4e89f9b4860a59a145f6c4b` |
| Desktop_neutral_Forward_19041.1.vb_release.191206-1406.CompDB.xml.cab; Type=Update, source OSVersion=10.0.19041.1, TargetOSVersion=10.0.22000.1 | 384 packages; 384 ExpressCab + 384 ExpressPSF | 393743 / `e3e5b55aaba55ecf3185a49a005d55ee2997e63cd014833612310288da1b8397` |

Target BuildID is `b5347a24-b65f-7c51-ac95-8bdd36d866a1`; the forward source
BuildID is `f9e033e8-a66e-de80-132f-8c8218cd941a`. They are different, so a
null-base recipe cannot stand in for the actual forward graph.

Exact unbound `PayloadHash` examples, preserved with original package provenance:

| Original payload path | Bytes | Exact XML PayloadHash (base64; algorithm attribute absent) |
| --- | ---: | --- |
| `UUP\Desktop\editionpackages\en-us\Client\Microsoft-Windows-Client-LanguagePack-Package_en-us~31bf3856ad364e35~arm64~en-us~.esd` | 15669800 | `JRCT0IiX/BEesT5qBKuJ6f8yXxJdkHqNMRy2yXFjM4Q=` |
| `UUP\Desktop\editionpackages\en-us\client\baseless\Microsoft-Windows-Client-LanguagePack-Package_en-us~31bf3856ad364e35~arm64~en-us~.cab` | 786167 | `2Z4vnr2UxUVooFSsevyYpBDpBgjL7BuVqQHffwSZK9w=` |
| corresponding baseless `.psf` | 27762169 | `uKdGDzcC4NfD9t5xglALspgM26aDh0jzsJpluURu/8w=` |
| `UUP\DeltaForge\Desktop\Build\Neutral\19041.1.vb_release.191206-1406\Forward\Diffs\arm64_Microsoft-Windows-Foundation-Package.cab` | 9573 | `Jcl5PuK/iQ6eOvWzKDDGum7qMCKkiF2ZRGX5896t7EM=` |
| corresponding forward `.psf` | 42428 | `4aBERBvmvwMj5pr2aFO66ILJmSXKUdiMRw+BS0FNZa4=` |

Those values decode to 32 bytes; length alone does not establish the schema's
hash-algorithm binding. They are not inserted as trusted `model.Digest` values
and are not output fixtures. No referenced package body was reconstructed.

## Bounded canonical package observation

The resumed research acquired an actual 21,506-byte canonical ARM64 Foundation
package ESD for 22000.1, source BuildID
`b5347a24-b65f-7c51-ac95-8bdd36d866a1`, from the same professional/en-us selection.
It matched the API's explicit SHA-1
`4004898a7fd7f2521fb2a8069a599ecf1fa6bbe3`; locally measured SHA-256 is
`34f8b978fd963d787b2c9cd0e05a981e0679c8d35ff4776cc691bf0987ac5581`.
Delivery used the API-declared Microsoft HTTP locator; no catalog/signature
authentication or redistribution rights were established. An individual matching
CompDB PayloadHash does not bind that schema's algorithm globally.

The source is a single-part/single-image WIM `0xe00`, flags `0x80002`, with one
single-chunk metadata resource and one single-chunk LZMS solid resource. The
probe parses bounded resource descriptors, the alternate chunk table and actual
flat dentry names rather than selecting fixed byte offsets. It checks metadata
and every content blob against the WIM lookup's SHA-1 identities, then resolves
the selected name through that verified metadata. The format interpretation is
based on the author's pinned
[resource layout](https://github.com/ebiggers/wimlib/blob/cd5e231c348c255ae5088873b5a66ee0eb96fa07/include/wimlib/resource.h)
and [blob descriptors](https://github.com/ebiggers/wimlib/blob/cd5e231c348c255ae5088873b5a66ee0eb96fa07/include/wimlib/blob_table.h),
not a hash-width guess. Other versions, compression shapes, split resources,
directories/reparse points/streams, nonempty security tables or missing resource
closure fail explicitly in this observation adapter.

The verified `$filehashes$.dat` is UTF-16LE with explicit `[sha1]` and `[sha256]`
sections and hexadecimal file lengths. Its `update.mum` record independently
expects 916 bytes and SHA-256
`b7025d5086ea128d3af5fbe8148d3d0d5c6555cd4e0acd9c6db869be52d4b508`.
The WIM metadata binds the same member to SHA-1
`01c1b33cc46f133a9427abc308bf7cf25e7b90e2`. This is an explicit source digest
oracle; it is stronger than a locally invented expected hash while retaining
the source's authentication limits.

An actual native amd64 Windows 19045 harness run used the pinned OS-owned
cabinet.dll RAW LZMS API for metadata (708 to 2,712 bytes) and the solid chunk
(10,394 to 26,897 bytes), checking all nine content blobs. A separate pinned
certutil invocation hashed the normalized member; bounded Go CBS inspection
observed `Microsoft-Windows-Foundation-Package`, version `10.0.22000.1`, ARM64,
public-key token `31bf3856ad364e35`, language `neutral`. The private W1 run
retains real inputs/components/native-call hashes/logs/output/reports.
`foundation-observation.json` binds these exact expectations. No foreign-target
executable, downloaded helper, image servicing or host installation was used.

This evidence remains `component-runtime` / `unverified`. It demonstrates this
specific data/algorithm path and does not establish complete canonical-family,
file metadata preservation, image roles, reference closure, other generations,
Windows servicing or ISO support. A separate source-reference replay test uses
the researcher's retained decoded buffers through an explicitly synthetic
decompression port; that replay is parser/custody validation, not native evidence.
Synthetic corrupt/framing tests never count toward Gate P/S. Optional x86/amd64
fixture attempts returned HTTP 500/429 and remain research gaps, not permanent
upstream absence. PSF/CIX/base-dependent/reference/encrypted cases remain pending.

## Family/algorithm requirements

The JSON census's `algorithms` are **requirements to establish**, not supported
algorithm claims. Every family remains unimplemented or unknown and unverified.

| Family | Actual evidence | Missing before Gate S |
| --- | --- | --- |
| Canonical CAB/ESD | Real Canonical CompDB records, legacy/modern selections, and one actually normalized ARM64 WIM/LZMS Foundation package with explicit source hashes | Broader compression/image variants, OS/setup roles, metadata preservation, complete independently expected fixture corpus |
| Reference/non-standalone WIM/ESD | [wimlib reference resource API](https://github.com/ebiggers/wimlib/blob/v1.14.5/include/wimlib.h) documents a mechanism; no instance inspected | Content-addressed reference closure, actual bodies, correct/missing/wrong-reference fixtures |
| Baseless express CAB+PSF | Actual Baseless ExpressCab/ExpressPSF pairs | Actual CIX/index/container versions, RAW/PA19/PA30 and relevant newer variants, trustworthy normalized results |
| Forward/base-dependent express | Actual source/target graph and DeltaForge records | Exact base identities and availability, base-relative forward/reverse/null behavior, verified reconstructed hashes |
| CIX/PSF | Pinned author parser references, no actual CIX | Bounds/path/index/hash checks, actual variant algorithms, native provider proof; empty-base success does not cover base-dependent data |
| Encrypted ESD | [wimlib documentation](https://wimlib.net/man1/wimapply.html) requires prior decryption | Actual encrypted ESD variant, key fingerprint/identity and independent plaintext fixture |
| ESRP delivery | [Pinned author reference](https://github.com/OSTooling/UUPMediaCreator/blob/885f2e3603d515918773c904e778f331bb239d1b/src/UnifiedUpdatePlatform.Services.WindowsUpdate/EsrpDecryptor.cs) shows metadata/AES-CBC/offset-derived-IV logic | Real safe acquisition contract and ciphertext/key identity/plaintext fixture; distinct from encrypted ESD segments |
| Traditional express/PSFX updates | ARM64 CAB/PSF update descriptors; Microsoft conceptual [differential model](https://learn.microsoft.com/en-us/windows/deployment/update/forward-reverse-differentials) | Actual generations/CIX/baselines/container reconstruction and servicing proof; generic MSDelta does not suffice |
| Checkpoint/combined MSU | Real KB5043080 and KB5043178 descriptors; [Microsoft checkpoint rules](https://learn.microsoft.com/en-us/windows/deployment/update/catalog-checkpoint-cumulative-updates) | Inner package identities, dependency ordering, compatible native servicing and inspected image results |
| App/FoD/separate WIM | APPX/APPXBUNDLE/MSIX/MSIXBUNDLE, FoD metadata and separate WIM descriptors | Actual manifests/licenses/dependency/edition rules and image roles; API app selector unresolved |
| Legacy composition | 15063 updatedb/baseless CompDB and later aggregated metadata names | Actual generation adapters, resource closure and compatible historical provider fixtures |
| Update-only selection | A real six-file update/support selection | Inspect whole-source setup/boot/OS closure before a whole UUID non-ISO-capability claim |
| Unknown/future/specialized | HCI/Server/Surface Hub titles sampled; WCOS/HoloLens names in resolver | Stratified catalog census, actual sources and per-family capability proof; unknowns remain visible |

Retained update-only identities: `windows10.0-kb5005189-arm64.cab`, 44682099
bytes, API SHA-1 `31a498992fc3f8cc327850ad7f520217643c9971`; paired `.psf`,
157251389 bytes, SHA-1 `397003ef4479d3964991d4deafe0e46b1bd3ffb6`;
`ssu-22000.132-arm64.cab`, 15450491 bytes,
`2e7f6538c343b9a4db8b78aa4fe03eb00cc67481`. No bodies/CIX were acquired.
Checkpoint selection: KB5043080 MSU, 533761740 bytes, API SHA-256
`819632610a101af11c72907fb13ff05b5fb4222c0e263ee9a03bcc1d1d5f26a4`;
KB5043178 MSU, 253169298 bytes,
`32b2c6b161aff21d0f64100497d17080dd9540b2bdf2f231dc6e04a3abbf79fe`.
These are expected **payload** identities, not reconstructed output hashes.

## Availability and proof validation

`SourceCensus.Validate()` retains separate observation, availability,
implementation, media capability, proof, metadata, missing-material and gap
fields. Observed families need actual metadata identities. Unknown/unimplemented
families cannot be marked passed. “Unavailable” requires an exact missing
identity and retained availability-report digest with a permanent removal
failure (`http-404`, `http-410`, `resolver-confirmed-removed`); a report must
describe the actual failed required material, not an arbitrary failed URL.
HTTP 429, research size caps, TLS-name errors, `SEARCH_NO_RESULTS` and app
`UNSUPPORTED_COMBINATION` cannot supply that classification. No entry currently
claims unavailable. A transient failure is still an error, not a successful
support test or a permanent absence determination.

The authoritative [host proof policy](../engineering/host-proof-policy.md)
accepts successful complete current-host functionality plus Windows
386/amd64/arm64 builds as host-architecture coverage. Other physical hardware is
optional; actual observed hosts remain truthful and portability-accepted
counterparts are reported separately. Existing bounded observations remain
unverified and cannot supply the missing full functional proof.

`SourceCensus.ValidateBuildable(family, required, evidence)` additionally
requires implemented/observed/available/ISO-capable status, concrete required
algorithms and bound Gate S cases with valid runtime evidence, delegating host
coverage to `ValidateArchitectureCoverage`. A passed family record covers only
those declared functional requirements, with observed and portability-accepted
host coverage distinguished; it does not establish unrelated target or
generation combinations, pass Gate P, or make a sampled census
exhaustive. A caller authorizing mutation must separately require all applicable
Gate P evidence and the selection's own proven family/algorithm cases.
Reference, encrypted and CIX corpus
gaps are research/implementation blockers, not evidence that Microsoft removed
their material. Gate P's native provider chain is separately pending; neither
gate can be opened by parsing metadata or passing validator unit tests.

Still required: a stratified raw-family census, concrete algorithms and complete
base/reference graphs, trustworthy positive/corrupt/missing-dependency fixture
corpora with independent output hashes, safe encryption identity handling, and
actual current-host reconstruction/servicing/media inspection records for every
required target, plus all three Windows builds. The
[toolchain ledger](toolchains.md) records the stopped runtime path and other
unfinished P1 execution requirements.
