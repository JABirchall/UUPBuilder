# Toolchain feasibility ledger

Reconciled 2026-10-28. **P1 operational acceptance remains blocked. Gate P has no
passing host/target pair; Gate S has no passing family.** The probe layer now
supports three closed component observations: installed Windows CAB metadata
extraction, one actual canonical WIM/LZMS package variant, and native IMAPI2FS
source-capsule ISO mastering. These produce retained `component-runtime`
observations, always `unverified` for the gates. All nine
x86/amd64/ARM64 logical host/target pairs remain required; additional upstream
targets remain valid values. The authoritative [host proof policy](../engineering/host-proof-policy.md)
accepts complete current-host functionality plus Windows 386/amd64/arm64 builds
as full host-architecture coverage. Other physical host hardware is optional.

Requirements: accepted `2026-10-27-uup-builder-design.md`, task P1 in
`2026-10-27-uup-builder-multi-agent-plan.md`, engine plan
`2026-10-27-uup-builder-engine-plan.md`, and G0 producer contracts. Research
provenance: the coordinator's dated `provider-research.md`,
`provider-runtime-report.md`, `adk-static-research.md` and
`source-census-research.md`, accepted `task-P1i-report.md` and
`task-P1i-quality-rereview.md`, plus `p1-servicing-provider-report.md`,
`native-winre-locale-v3-diagnosis.md`, `p1-additional-image-inputs-report.md`
and their retained native/source-comparison receipts. Research archives,
Microsoft payloads, legacy guidance and converter scripts are not product inputs
and are not copied into this tree.

## What runs, and what remains unfinished

```powershell
go test ./tests/probes -run 'Test(Required|Evidence|SourceCensus)' -count=1
go test -tags=providerproof ./tests/probes -run TestProviderPerformsCrossArchitectureServicing -count=1
```

The first command tests validator logic with explicitly synthetic in-memory
records. Its success establishes no provider capability. On an actual Windows
host the tagged command selects the current native host's applicable cases and
assesses all nine logical pairs through `ValidateArchitectureCoverage`. It currently
**fails** with an unconfigured runtime and remaining functional gaps, without
running an image tool. Separate component and private research results do not
configure these required cases. `provider_windows_test.go`
is Windows-only; running that test selection on another OS and seeing “no tests
to run” is not a proof. Non-Windows `RunCase` reports the missing native host.

`RunCase(ctx context.Context, c Case, emit model.Emit) (Evidence, error)` reads
OS-owned `RtlGetVersion` and the
native-machine output of dynamically resolved `IsWow64Process2` on Windows.
Actual process architecture remains a separate `GOARCH` value. Missing/failed/
unknown native-machine results preserve the measured build/process and return
an explicit unverified error with native architecture unset. Early Windows 10
native-identity coverage therefore remains pending; no host/target is removed.
`GetNativeSystemInfo` and legacy WOW64 answers cannot substitute for this native
identity because they can expose emulated x86/x64 details on ARM64. The
unconfigured observation has no retained workspace report. Without an explicit
`WithRuntime` request it returns `unverified`, no invocations and a nonnil
`runtime-unconfigured` error, preserving host mismatch and pending case blockers.
A canceled context remains discoverable with `errors.Is(err, context.Canceled)`.
The checked-in nine matrix cases still have no complete runnable fixtures or
provider closure and are unchanged by the extra observation descriptors.

`WithRuntime` snapshots the request's identity/path bindings; the runner copies
the complete case before callbacks. `LoadObservation` rejects unknown fields,
commands, trailing data and oversized descriptors. Explicit fixture/workspace
roots locate bytes and confer no readiness. Closed recipes generate their own
argv and fixed native API calls. Windows uses the accepted W1 owned local-NTFS
Workspace and direct ProcessRunner; no tools/planner/jobs contract or public CLI
was added. Native system component handles deny write/delete sharing throughout
execution; measured size/SHA-256 and PE machine must match the case. Original
source digest algorithms are preserved alongside locally measured SHA-256.

The earlier CAB/LZMS recipes' direct processes have fixed 30-second deadlines
and W1's bounded captured output/tree cancellation. The native LZMS observation
has a 30-second context and at most 1 MiB per input/output buffer. CAB preflight
bounds the single named member, folder/data blocks and declared output to 4 MiB
before launching expand.
Bounded Go XML inspection rejects malformed, ambiguous, deeply nested, oversized
or directive-bearing documents. The separate native ISO recipe has a five-minute
process deadline and a 5 GiB ISO output cap; its raw inspector streams outer
bytes and hashes bounded file extents. The earlier 1 MiB buffer limit does not
describe this larger recipe. Zero exit, digest width, JSON flags and declared
algorithm names cannot supply missing content/operation evidence.

Public Evidence contains logical `owned-run:` artifact references, measured
digests, a runtime digest and separate process/native-call facts. Its in-memory
RetainedWorkspace locator is excluded from JSON/TOML. The private W1 workspace
retains source/component copies, host/filesystem facts, full process/API logs,
outputs, semantic reports and run.json with frozen case/runtime, custody map and
private ownership identity. Public records omit that ownership token and private
root. Retained files are the evidence; handwritten or edited run.json is not an
attestation. `ValidateEvidence` remains a structural validator and rejects both
`component-runtime` and explicitly synthetic test observations.

For an explicitly reviewed local CAB/LZMS run, set `P1_OBSERVATION_ROOT` to the
retained own-plan fixture workspace and `P1_OBSERVATION_WORKSPACE_PARENT` to an
existing local NTFS parent, then run the separately named providerproof observation test.
Missing roots, bytes, exact host or pins fail instead of skipping. The tests
`TestProviderObservesCompDBExtraction` and `TestProviderObservesFoundationLZMS`
check only their narrow observations and explicitly assert gate rejection.

The separate providerproof test `TestProviderMastersARM64SourceCapsule` requires
`P1_ISO_PLAN_ROOT` to identify its own retained plan's acquisition manifest,
source members and owned workspace parent. `TestISOInspectRetainedARM64Capsule`
instead requires `P1_ISO_RETAINED_RUN` and reinspects the unchanged retained ISO
without rerunning its producer. Missing fixtures or changed identities fail;
neither test configures the required `RunCase` matrix or supplies full-gate proof.

The actual CAB observation on native amd64 Windows build 19045 retained two
successful process invocations, one 43,914-byte output and independent hash/XML
inspection. Its SHA-256 is
`9b597e01c646d7ad93ba6f9108beeb420affebd8a4e89f9b4860a59a145f6c4b`;
actual CompDB namespace, arm64 target, Baseless type, BuildID and OSVersion
matched the frozen descriptor. expand receives fixed owned-relative
`inputs\0.cab`, `-F:DesktopBaselessCompDB_en-us.CompDB.xml`, `outputs` under W1's
locked cwd. This installed version writes fixed `outputs/0.cab`; its physical
suffix supplies no semantic role. Certutil separately hashes that exact file
using the original absolute path. Prior failed extended-prefix/path/naming
diagnostics remain retained; there is no prefix stripping, arbitrary output
search, output renaming or zero-exit acceptance.

The canonical observation retained one native invocation with two actual RAW
LZMS decompression calls, one separate certutil invocation, one 916-byte
normalized update.mum and actual ARM64 CBS package identity inspection. The
expected SHA-256 comes from the source's explicit `[sha256]` hash manifest;
all nine WIM content SHA-1 identities were checked. This is positive bounded
source/algorithm evidence, not complete canonical-family or Gate P/S acceptance.

Native IMAPI2FS on the current native amd64 host created a 3,241,803,776-byte
source-capsule ISO, SHA-256
`f82c4b242f2a3da7dbbb04cbf082e2ae3c96c80f7ecb7882a00327109a9106fe`.
The accepted current independent Go inspector, SHA-256
`e3e33e2aa8038086845f60a9c130423082208413ace4eac9b56ab609f040774d`,
checked 48 files in ISO9660 and 48 in UDF 1.02, matching every expected size and
SHA-256, plus the El Torito catalog/FAT layout and embedded and direct ARM64
loaders with PE machine `0xAA64`. This is real native source-data
ISO/content/EFI-data mastering.
It is not complete Windows Setup media or a booted image: serviced image/setup
tree closure and actual boot proof remain pending. The retained Evidence stays
`component-runtime` / `unverified`, with zero `MasterISO` verifications; strict
Gate P/S validation still rejects it.

Automatic approval review rejected extraction/direct execution of the pinned
downloaded wimlib with only `blocked by policy`, before the orchestration
started. No helper exit code or runtime failure was observed. This route remains
stopped. Later independently authorized existing-OS probes, native ISO mastering
and elevated WinRE export/apply/capture/reapply research are separate recorded
actions; they do not reopen the rejected downloaded-helper route. The refusal is
separate from unfinished adapters and remaining source gaps.

Historical read-only observation: Windows 10 Enterprise build 19045,
native/process amd64, non-admin, local fixed NTFS N:. Native Windows x86 and
ARM64 execution remains unobserved, with no hardware requirement under the
accepted portability rule. A 386 process under WOW64 on this machine is not
native x86-host evidence. Cross-compilation and target executable emulation do
not create observed runtime records.

| Actual native Windows host | x86 target | amd64 target | ARM64 target |
| --- | --- | --- | --- |
| x86 | unverified | unverified | unverified |
| amd64 | unverified | unverified | unverified |
| ARM64 | unverified | unverified | unverified |

This table reports direct full-gate observations. Portability-accepted coverage
is also currently absent because complete current-host functional proof is
missing. Once that proof and all three Windows builds pass, report other-host
coverage as portability-accepted with the actual current-host witness, preserving
the unobserved status of execution on other hardware.

## Producer contract for R1 and later runners

`LoadCases(io.Reader) (CaseLedger, error)` accepts schema 1, bounds the complete
document to 4 MiB, rejects unknown fields/trailing data and validates the ledger.
`ValidateRequiredCases([]Case) error` requires unique cases and all nine common
Gate P pairs, each with extraction, servicing, reconstruction and ISO mastering.
It never filters future target values. `Case.Validate()` permits explicit pending
prerequisites; `Case.ValidateReady()` rejects them, missing payload fixtures,
incomplete dependency closures, missing concrete algorithms, and missing
independently expected operation outputs. All checked-in cases are pending.

`Case` binds host OS/minimum build/native/process architecture, target, family,
exact source identity and revision provenance, metadata versus payload roles,
component byte identities/dependencies, required operations/algorithms, expected
SHA-256 values/content assertions and blockers. `Case.Digest()` is SHA-256 of
the entire JSON descriptor, including order and pending requirements. It is a
binding digest, never a reconstructed-output hash. Freeze the descriptor before
execution; changing it requires new evidence.

`ValidateEvidence(required []Case, evidence []Evidence) error` requires precisely
one passed native-runtime record for every supplied requirement. It rejects an
empty required set, duplicates, unexpected/missing records, changed descriptors,
failed/unverified/unknown statuses, architecture mismatch, missing host reports,
nonlocal/non-NTFS proof workspaces, changed inputs, omitted component/DLL/driver
identities, unknown dependency closure, missing/failed/timeless invocations,
unexecuted algorithms, and missing/misbound outputs or independent inspections.
Inspection uses another pinned executable with different bytes after the producer finishes and must
agree with independently expected and produced SHA-256 values and target.
Extraction requires file/metadata inspection; servicing binds the known baseline
SHA-256 to a payload fixture input and the independent inspection, requires a
different expected after-image hash plus an observed modification; reconstruction needs content
inspection; media needs filesystem, boot catalog and target boot-resource
inspection. WIM export alone cannot satisfy servicing.

`ValidateArchitectureCoverage(required []Case, observed []Evidence)
([]ArchitectureCoverage, error)` applies the authoritative single-host acceptance
rule above this unchanged strict validator. It requires one complete suite with
matching measured host facts and exact equivalent functional requirements for
every logical pair. Each coverage entry distinguishes direct observation from
portability acceptance and identifies the actual witness. Native component
bytes are validated on the actual witness only; generic provider/rights/setup/
source/output blockers cannot be waived. Successful cross-builds remain a
separate required gate. `SourceCensus.ValidateBuildable` delegates architecture
acceptance to this evaluator after its existing family/algorithm checks.

Artifacts contain sanitized logical IDs, roles, sizes, digests and provenance.
No signed locator, key or credentials belong in them. Runtime arguments/logs
must be sanitized before creating public records. Metadata hashes cannot
satisfy payload/output roles. Measured evidence/component hashes use SHA-256;
payload identities retain the actual upstream digest algorithm. These checks
validate **record structure and binding**, not an attestation that a person
actually executed tools or that referenced bytes exist. A future trusted runner
must materialize and independently rehash retained artifacts, inspect actual
results and produce the records; handwriting a valid record is not Gate P/S
evidence. There is no shipped fake provider or sample successful proof file.

## Static wimlib candidate identities

Publisher Eric Biggers; [vendor index](https://wimlib.net/downloads/index.html),
version 1.14.5. All hashes below identify bytes acquired/read during research.
They are session measurements, **not publisher-published digests**, and none
proves runtime behavior. No publisher hash was found. HTTPS origin, PE machine
and runtime compatibility are separate evidence classes.

| Exact vendor archive URL | Bytes | Measured SHA-256 |
| --- | ---: | --- |
| https://wimlib.net/downloads/wimlib-1.14.5-windows-i686-bin.zip | 791576 | `3739eb2291b9a86d2fcc2914c4b2b53317c045de214782e46588ed8350371905` |
| https://wimlib.net/downloads/wimlib-1.14.5-windows-x86_64-bin.zip | 778747 | `2f446d6fa3866582175f1a22a7be198eeee0aec7aba5b4e04ad25c99eae2d265` |
| https://wimlib.net/downloads/wimlib-1.14.5-windows-aarch64-bin.zip | 767462 | `2c2e3e50cf21bfdd4ffd693b5052b231aa04a10c85f218ae61eb5a031dfcdd8f` |
| https://wimlib.net/downloads/wimlib-1.14.5.tar.gz | 1073578 | `84221a3abd5b91228f15f8e6065c335a336237b5738197b75bf419eea561a194` |

| Archive host; PE machine | Entry; bytes | Measured entry SHA-256 |
| --- | --- | --- |
| x86; 014C | wimlib-imagex.exe; 117774 | `597b1e5fe29b92cce7ab6955d4cd629eb2c070fad45aed2bde811b39edbd80af` |
| x86; 014C | libwim-15.dll; 531470 | `a79b428fea9d1bded38a45eab854bd72f0a31fd878c0d3132cfdfd4899498053` |
| amd64; 8664 | wimlib-imagex.exe; 112654 | `34c0c4165591ad1f592837ed99d08273c58d6ed3fe0ed6360cf34e7b0739b353` |
| amd64; 8664 | libwim-15.dll; 497678 | `ba853ee1e3fc5f5798581f02e8e066ba07a0a2375f0bf444fe981431fd508495` |
| ARM64; AA64 | wimlib-imagex.exe; 125440 | `fddb8c216732ab2a0f41064a305e07947a22f20338e36f44a2ceaffd44d8f908` |
| ARM64; AA64 | libwim-15.dll; 432640 | `b34549c6eff728a2f2fe68903a9fde28d8ac717f1b521e7f38b1e4106320c992` |

All inspected EXEs/DLLs had zero certificate-table and delay-import sizes.
The x86/amd64 EXE directly imports libwim-15.dll, ADVAPI32.dll, KERNEL32.dll
and CRT API sets `api-ms-win-crt-{convert,environment,filesystem,heap,locale,
math,private,runtime,stdio,string,time}-l1-1-0.dll`. The DLL imports ADVAPI32,
KERNEL32, ntdll, USER32 and those CRT sets plus utility-l1-1-0. ARM64 EXE
imports libwim-15, msvcrt, ADVAPI32, KERNEL32; its DLL imports ntdll, msvcrt,
ADVAPI32, USER32, KERNEL32. Static direct imports do not certify full runtime
closure or Windows API-set resolution.

Matching source adds conditional ntdll and Fltlib/FilterAttach loads, plus
vssapi/ole32 for snapshot mode. System Compression can require wof/wofadk driver
capability; ordinary WIM extraction/export must not inherit that requirement
without its operation using those paths. No driver/installer is included in
the ZIPs. ZIP extraction has no installer step; operation-specific privileges,
clean-machine prerequisites and restart behavior remain unverified. The
[publisher Windows README](https://github.com/ebiggers/wimlib/blob/v1.14.5/README.WINDOWS.md)
marks the ARM64 build environment experimental. WIM data operations do not
establish Windows package servicing or Windows WIM mounting.

Actual archives include COPYING.txt, COPYING.GPLv3.txt, COPYING.LGPL.txt and
COPYING.libdivsufsort-lite.txt. The front end/project is GPLv3-or-later; Windows
libwim may use LGPLv2.1-or-later when not linked with libntfs-3g; the
libdivsufsort-lite notice is permissive. Preserve applicable notices and resolve
corresponding-source/relinking obligations before distributing selected
components. A product distribution/linking policy is not established here.
The matching source archive above is a candidate provenance input.

## Microsoft DISM/ADK and ISO mastering

The newer coordinator `adk-static-research.md` supersedes the earlier HEAD-only
observations. Official pinned Microsoft packages contain native x86, amd64 and
ARM64 **DISM and Oscdimg**, including native ARM64 Oscdimg, for both inspected
payload sets. Bootstrappers, 133 focused deployment/imaging MSI/CAB/helper files
(90,012,567 bytes), and a documentation MSI were inspected as data. No downloaded
executable, installer, MSI custom action, imaging helper or driver was run.

| Exact official bootstrapper | Observed file version; bytes | Measured SHA-256 |
| --- | --- | --- |
| [September 2026](https://download.microsoft.com/download/8e0c0f5a-abb5-4358-a51b-168eb40b1590/adk/adksetup.exe) | 10.1.26100.9457; 2233776 | `ac6a930fdb5c2980ba5fefe606d47edaafcf5f647b4337411500d158ea77300f` |
| [Separate 28000.1 scenario](https://download.microsoft.com/download/615540bc-be0b-433a-b91b-1f2b0642bb24/adk/adksetup.exe) | 10.1.28000.1; 2236280 | `a579ea916797d32e5d0443418e3aaa70f3212911c9183d58b9997c329ecba791` |
| [Republished Windows 10 2004 kit](https://download.microsoft.com/download/3b40cb81-ff9c-4322-aacd-c78d01b2c2ed/adk/adksetup.exe) | 10.1.19041.5856; 1970056 | `79ffc10e1a7e2e699083467db601d9747f71a419981b458063de1a86fd8c47dd` |

All three bootstrappers and 133 payload files returned Authenticode `Valid` on
the research host. All payload sizes and publisher Burn-manifest SHA-1 values
matched. `adk-static/downloads.json` retains exact versioned URLs, those SHA-1
values, separate measured SHA-256 values, signers and thumbprints. Local
SHA-256 identities and historical signature observations are separate evidence
classes; neither is a fresh-machine/current-revocation check or runtime proof.
Moving fwlinks are not used as immutable content pins.

The current DISM runtime is split across OnecoreUAP and DesktopEditions MSIs.
Oscdimg DesktopEditions supplies the executable; its OnecoreUAP package supplies
boot resources. MSI package labels containing `x86` do not identify all embedded
tool architectures. The historical Deployment Tools MSI combines a larger
multi-architecture set. The focused selected packages are not the complete ADK
DeploymentTools feature; separately inspected Imaging Tools Support packages
belong to ImagingAndConfigurationDesigner and must not be inferred to be DISM
prerequisites.

| Kit | Native tool | Bytes / measured SHA-256 |
| --- | --- | --- |
| 19041.5856 | DISM x86 | 226368 / `572abf383a11d5ec8764e6e78b9c90a9b9d1c83300d4de240fca6f99c47da108` |
| 19041.5856 | DISM amd64 | 289344 / `08d46131027599b9956aefed0ef653ee41f127ace77b48002b29e5721b58d121` |
| 19041.5856 | DISM ARM64 | 322632 / `c5197f5645a4db30b31e64aac31bfa775af64f2145f832fda8b24c6e97d06364` |
| 19041.5856 | Oscdimg x86 | 117824 / `59972e5867cfad380d0fe376575221fb6abb5f6b847a4d833916680e9ecce8d9` |
| 19041.5856 | Oscdimg amd64 | 132176 / `1779ff09753a3327e66617e8eef680c7e35a428c0b0509173be356d270eb2ba4` |
| 19041.5856 | Oscdimg ARM64 | 136752 / `e54a6077cbcedc0fd6d8b70501db527d80c296f7b3b3c21ddca88f87a17936c3` |
| 26100.9457 | DISM x86 | 243648 / `522495f929771de1cb25e0c7f1bceaf00256d7c1e8ca295b6a4dbccbd8e17085` |
| 26100.9457 | DISM amd64 | 334272 / `d1c3112796a419a9abb4ea6163ecfd50204c4868628f2efcb3bff74ea7f2b8c4` |
| 26100.9457 | DISM ARM64 | 347600 / `c725948dbcb15780bd4041938141123a3992daceb9f94dd4d3837351d2bf090a` |
| 26100.9457 | Oscdimg x86 | 120272 / `b99cf18de8006f7bec5b9618eac6d2f4ba9f1700adc78a2bc49433b55629c93b` |
| 26100.9457 | Oscdimg amd64 | 154024 / `d2709f8099ddd202bc41bcb399ecd5638503c6466f416d1a321769af83a70c3a` |
| 26100.9457 | Oscdimg ARM64 | 139696 / `175e8899c9925c0a91289fa8294d6969eeb88a7c753b3b9001cd63a3b3d9a8f4` |

DISM file versions are `10.0.19041.5856` and `10.0.26100.9457`; kit versions
begin `10.1`. Oscdimg reports `2.56.0.1010` in both kits while its hashes differ.
PE machines 014C/8664/AA64 establish file architectures. All twelve front ends
returned valid signatures during the static pass; no one was launched.

The retained inventory covers 1,912 MSI file rows and 1,822 inspected PE/data
rows. Current native DISM folders contain core/API/provider/imaging DLLs,
WIMGAPI, WimServ, native setup helpers, resources and WIMMount/WofAdk plus newer
CIMFS/UnionFS components. External Burn ExePackage helpers and installed
DISM-folder helpers can share names/versions but have **different bytes**; they
remain distinct identities. The six inspected Oscdimg front ends directly
import only KERNEL32 and msvcrt and have no delay imports. This small static
surface does not establish transitive OS closure or successful mastering.

**Complete operation-specific dynamic closure remains unverified.** The selected
MSI tables do not list standalone DismHost, CbsProvider, AppxProvider or
SetupPlatform files, while native core/provider bytes contain dynamic-name
leads. Origin/load path, compatible target CBS/servicing stack, conditional OS
loads, drivers and servicing/app/package dependencies still need proof. Static
tables do not certify a minimal portable DLL set. The
[copy procedure](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/copy-dism-to-another-computer?view=windows-11)
does not settle every full-OS host/version/operation.

Actual English EULAs were obtained from bootstrapper UX cabinets and read.
Current and 28000.1 EULA RTF SHA-256 is
`3c0c45033614cd4882ff0195ca7f77c8077f2f4917806ada519855f7f87da595`;
historical is
`82acd1ca7ca2c7fb7cae8a9b843a28842bdcdc5263f665d3cdc82e318382b496`.
Current terms describe compatible client/server versions that have not reached
End of Support. Historical wording differs; exact edition/channel/ESU/LTSC/job
applicability is unresolved. The observed ADK distributable category names
sample code; historical WDK REDIST wording is not a grant for ADK DISM/Oscdimg.
No specific DISM/Oscdimg/driver redistribution entitlement is established. The
bounded runtime/documentation file-table scan found no named REDIST or third
party notices file; that does not prove every uninspected component lacks one.
Vendor-direct acquisition/use and concrete rights/notices still need review.

Official [ADK acquisition](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install)
and [offline workflow](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-offline-install)
document vendor-direct `/layout` and `OptionId.DeploymentTools`; those commands
were not run. Per-machine packages, native imaging-helper conditions, a .NET
4.5 detection/prerequisite, MSI custom actions, native driver setup, and
reboot-related exit-code metadata were inspected as data. These facts do not
prove clean-machine installation, safe cancellation/restart, privilege/license
acceptance, repair/conflicts/uninstall or repeat provisioning. The product must
manage these requirements; no manual ADK prerequisite is accepted.

The [servicing page](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-servicing)
says 26100.9457 needs no additional patch; the 28000.1 required patch route was
not inspected, so that base is not a complete provider pin. Historical provider
choice remains necessary where exact image/operation compatibility or rights
requires it. A newest-kit assumption does not cover every requested build.

The initially inventoried native System32 dism.exe is 289136 bytes, measured SHA-256
`6a2bc5111b7ea9c4c6fdca0db462187b8b9b1ef009bd2d28a2a0124e3d31b95d`;
DismCore.dll 413160 bytes,
`fbb5135de4f6a5c9422a0b218d676930db9bc9a2aea0f7219077862912455914`.
Research observed valid Microsoft Windows signatures and PE 8664 for these
files. Their legacy resource display strings say `10.0.19041.1`; fixed numeric
versions instead identify DISM/DismCore `10.0.19041.3636`, WIMGAPI
`10.0.19041.7802` and dismapi `10.0.19041.7663`. The export log agrees with the
numeric DISM version. These installed identities are not a distributable ADK
manifest or proof of newer-image servicing compatibility. The full current-host
inventory remains in private research; it must not be copied as an ADK toolchain.

Separately from the runnable Go observation recipes, ignored private WinRE
research executed inbox DISM `/Get-WimInfo` and `/Export-Image` against genuine
ARM64 22000.1 source index 2. Both completed with zero exits on elevated native
amd64 Windows 10 Enterprise 19045.7807. Export produced a standard bootable LZX
WIM (one image, boot index 1), 384,901,017 bytes, SHA-256
`87d6f001b0599e9f4acb75c517b6c6fc726ea421581f361a862dad50edc75642`.
Independent comparison checked all 8,706 original stream hash/size declarations
and the original metadata hash/size identity declaration, and actually hashed
all 3,274 uncompressed rows totalling 3,281,618 bytes. Compressed LZX content and
metadata were not independently decoded. This export alone is not image
servicing, reconstruction, full-content or boot proof. No ADK, installation,
driver setup, mount, online operation or restart was used for this export.

Later private native research completed an unserviced ARM64 22000.1 WinRE
apply/capture/reapply roundtrip on the same host. The captured standard WIM is
384,904,492 bytes, SHA-256
`ba3628eda6cabdf49a9d6f367f535eb70b0f7032e05b090604b85ad32f6ce4d5`,
version `0x10d00`, LZX flags `0x40082`, 32 KiB chunks, one image and boot index 1.

| Actual native step | PID | Exit | Elapsed |
| --- | ---: | ---: | ---: |
| Original-WIM apply | 5068 | 0 | 20,365 ms |
| Capture | 22544 | 0 | 24,805 ms |
| Captured-WIM reapply | 11352 | 0 | 18,829 ms |

Independent inspections before capture, after capture and after reapply matched
all five selected source members' SHA-1, SHA-256 and lengths: DEFAULT,
default-user NTUSER, SYSTEM, SOFTWARE and KBDUK.DLL. Parsed hives retained
WindowsPE 22000.1/ARM64 identity, both original US input configurations, and the
SYSTEM UK-layout mapping with its KBDUK payload. This is a roundtrip of the
selected source state. The raw WIM inspector checked compressed-resource framing
without independently decoding all compressed content; native apply/Verify and selected
actual-file/hive inspection do not establish whole-image content or security
metadata fidelity, servicing or boot behavior. Checks of one directory's ACL
cannot establish whole-image fidelity.

The new `native-winre-unserviced-reapply-22000/result.json`, SHA-256
`1bccaaff70bf020809f0916a5cf8b8906dd34add501c949b1e04752ca49af1b1`,
links the preserved earlier failed result, SHA-256
`87ce7a6b32b8e2bc2921dc7eb9a7abc9c516d835f27516348340857182c5c3bd`.
Its apply and capture had succeeded; the old reader incorrectly required
factory XML EDITIONID/INSTALLATIONTYPE declarations in captured output. Those
declarations are absent/null, with architecture, build and system root still
checked strictly and actual WindowsPE role independently established from hives.
No XML was patched and successful apply/capture steps were not rerun. The three
phase logs contain no foreign-servicing-session markers; that is retained-text
evidence, not proof of loaded-module absence or complete dependency closure.
The existing temporary SeBackup scan monitor verified 59 of 59 restorations in
the latest reapply run, with zero failures. No ACL/policy change, host setup or
ADK was used. Configuration, full Gate P, CBS feature/package, boot execution and
security-metadata-fidelity flags remain false. This private result adds no Go
recipe and does not make the required `RunCase` cases ready.

The separate servicing attempt in `native-winre-locale-22000-v3/result.json`
failed. Apply and the original five-member/typed-hive baseline passed, but
`/Get-Intl` exited 87 during `CPEImg::Attach` / OSVersion initialization with
`0x80070057`. No locale-set command or serviced WIM was achieved, and the five
selected source files remained unchanged. The diagnosis found correct documented
arguments and ordinary paths, with no evidence-backed small correction. The
exact internal invalid argument remains unresolved.

That failure log records automatic selection of the source image's
`Windows/SysWOW64/Dism` store, remote PID 12556 and PEProvider initialization.
The host PEProvider is absent; the selected source store contains signed x86
22000.1 providers. These facts strongly support source-image provider origin,
but exact scratch-loaded hashes and the full remote dependency graph were not
captured before tool cleanup deleted the scratch session. The attempt therefore
cannot be described as confined to the pinned inbox provider set. Microsoft's
[compatibility table](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-supported-platforms?view=windows-11)
requires appropriate Windows 11 DISM for Windows 11/WinPE 11 images on a Windows
10 host; it does not identify this internal failure or establish permanent ARM64
impossibility. A supported compatible provider, support/rights and dependency
closure remain required. No provider harvesting, ADK installation, mount,
online/reboot operation or registry-write workaround was used to resolve it.

The [source ledger](source-formats.md) separately records exact original x86 and
amd64 setup/WinRE body recovery through alternate catalogue contexts. Source
oracles and provider-store inventories establish data identities, not runtime
readiness. Additional x86/amd64 exports are being prepared; no outcome is
recorded here.

[DISM platforms](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-supported-platforms?view=windows-11)
distinguishes host/tool/image versions. WinPE-specific restrictions are not
universal full-Windows host restrictions. Microsoft's
[ARM manufacturing workflow](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/arm64-device-manufacturing?view=windows-11)
documents an amd64 technician-PC scenario, not nine-pair native proof.
[Oscdimg options](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/oscdimg-command-line-options?view=windows-11)
describe UDF/El Torito; native helper byte availability is now established by the
static inventories above. ADK mastering, complete Windows Setup media, actual
boot, and host compatibility and operation/dependency/rights closure remain
unverified. The separate IMAPI2FS source-capsule result does not certify these
ADK candidates. [W2 acquisition](acquisition.md) documents the candidate-only manager
and private synthetic ZIP backend; its component tests do not open Gate P/S.

## Differential candidates, without source-family proof

OS-owned MSDelta/PatchAPI are candidate APIs, not a PSF/CIX adapter. Current
native amd64 msdelta.dll (609120 bytes) measured
`6b5e2d20b657568be9d4f9606d582e99b21086fe62dd011d3252e17eccabd2a1`,
mspatcha.dll (72536 bytes)
`9ad286b34625805bb00f73e7623c8f908097e96bd85481a060edb690fc5b50e9`.
Neither API was invoked. [ApplyDeltaB](https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-applydeltab)
does not establish container/index/baseline/encryption/generation coverage.

Author [PSFExtractor v3.07](https://github.com/Secant1006/PSFExtractor/releases/tag/v3.07),
tag commit `b2e586f64b2a91042487776df48026b019bad651`, has these measured assets:

| Author release asset | ZIP bytes / SHA-256 | EXE bytes / SHA-256 |
| --- | --- | --- |
| https://github.com/Secant1006/PSFExtractor/releases/download/v3.07/PSFExtractor-v3.07-x86.zip | 239132 / `c10557e3c62c7b321dab82f2f27c934b59a99b801422b35705e53994081ff4dc` | 540672 / `7bb1ddcad83b1c1ca469ef5338faffe882600068d65911a6d09e88ef89d080b7` |
| https://github.com/Secant1006/PSFExtractor/releases/download/v3.07/PSFExtractor-v3.07-x64.zip | 301297 / `e7e18dffb4051bdf1fe10bb55a1374c0bed5ae688f1ad44d3b210c8b728fbcca` | 775680 / `b8a08dd9592e64843056cf5fe518e782fd7ed517d1ee32b70a99b7d7e5767f6c` |

No published digest or ARM64 asset was established for that release. Static
PEs are unsigned; imports are KERNEL32 plus delay-loaded Cabinet, with embedded
Microsoft-named mspatcha/msdelta DLLs. Source can load by basename or write
embedded DLLs to fixed temporary filenames. Their redistribution provenance
and a trusted absolute-path lifecycle are unresolved. Project/pugixml MIT
notices do not settle the embedded Microsoft-byte rights. PA19/PA30 paths use an
empty source and do not prove base-dependent forward/reverse reconstruction.

Source-only leads [jlevere/psf](https://github.com/jlevere/psf/tree/7d2c691b48923bd0bf08ba7704c704d533071766)
and [jlevere/msdelta](https://github.com/jlevere/msdelta/tree/fb5ab88843e854f3fd32d553984d8685ae643913)
declare MIT OR Apache-2.0. No build, native-host run, transitive dependency/notice
closure or fixture proof exists. The pinned MSDelta README explicitly leaves
ARM/ARM64 instruction/pdata transforms and CLI4 unsupported. Author PA31 claims
are not a Microsoft API guarantee. No candidate is silently selected as a
complete provider.

## Unfinished P1 scope

Complete image/payload extraction, servicing, reconstruction and full Windows
Setup media adapters, broader trustworthy fixture corpora and independent
expected hashes, concrete complete provider decisions, rights/dependency/
signature/acquisition/setup/restart closure, clean-machine validation,
complete current-host modified-image/media proof for every required target and all
source-family algorithm proofs remain pending. The stopped policy path is a
separate execution blocker. Future authorized work must resolve those concrete
items and retain actual inputs, outputs, commands, host observations and
independent inspection artifacts before opening Gate P/S. Green validator
tests cannot substitute for any of them.
