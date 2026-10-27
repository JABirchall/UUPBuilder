# Toolchain feasibility ledger

Recorded 2026-10-27. **P1 is BLOCKED. Gate P has no passing host/target pair.**
The checked-in work is a descriptor/validator component and an unfinished,
refusal-only execution entry point. It is not a completed provider probe or a
conversion engine. All x86, amd64 and ARM64 targets remain required on every
supported native Windows host. Additional upstream targets remain valid values.

Requirements: accepted `2026-10-27-uup-builder-design.md`, task P1 in
`2026-10-27-uup-builder-multi-agent-plan.md`, engine plan
`2026-10-27-uup-builder-engine-plan.md`, and G0 producer contracts. Research
provenance: the coordinator's dated `provider-research.md`,
`provider-runtime-report.md`, `adk-static-research.md` and
`source-census-research.md`. Research archives,
Microsoft payloads, legacy guidance and converter scripts are not product inputs
and are not copied into this tree.

## What runs, and what remains unfinished

```powershell
go test ./tests/probes -run 'Test(Required|Evidence|SourceCensus)' -count=1
go test -tags=providerproof ./tests/probes -run TestProviderPerformsCrossArchitectureServicing -count=1
```

The first command tests validator logic with explicitly synthetic in-memory
records. Its success establishes no provider capability. On an actual Windows
host the tagged command visits all nine required cases and currently **fails**
each as `UNVERIFIED`, without running an image tool. `provider_windows_test.go`
is Windows-only; running that test selection on another OS and seeing “no tests
to run” is not a proof. Non-Windows `RunCase` reports the missing native host.

`RunCase(ctx context.Context, c Case, emit model.Emit) (Evidence, error)` is
unfinished execution plumbing. It reads OS-owned `RtlGetVersion` and the
native-machine output of dynamically resolved `IsWow64Process2` on Windows.
Actual process architecture remains a separate `GOARCH` value. Missing/failed/
unknown native-machine results preserve the measured build/process and return
an explicit unverified error with native architecture unset. Early Windows 10
native-identity coverage therefore remains pending; no host/target is removed.
`GetNativeSystemInfo` and legacy WOW64 answers cannot substitute for this native
identity because they can expose emulated x86/x64 details on ARM64. The
observation has no retained host-report artifact or filesystem/privilege proof.
It returns `unverified`, no invocations, and a nonnil error. Distinct blockers
identify host mismatch, unresolved prerequisites, **adapter-unimplemented** and
**policy-execution-stopped**. A canceled context remains discoverable with
`errors.Is(err, context.Canceled)`. Event delivery reports an error, not progress
or a successful checkpoint.

Automatic approval review rejected extraction/direct execution of the pinned
downloaded wimlib with only `blocked by policy`, before the orchestration
started. No helper exit code or runtime failure was observed. This route remains
stopped. This task does not retry through tests, Go, another shell or another
launch mechanism; it does not install tools, elevate, change security, create a
VM, install drivers or service an image. The refusal is separate from the
unfinished adapter and from unavailable upstream material.

Historical read-only observation: Windows 10 Enterprise build 19045,
native/process amd64, non-admin, local fixed NTFS N:. Native Windows x86 and
ARM64 environments/fixtures remain unestablished. A 386 process under WOW64 on
this machine is not native x86-host evidence. Cross-compilation and target
executable emulation cannot fill these requirements.

| Actual native Windows host | x86 target | amd64 target | ARM64 target |
| --- | --- | --- | --- |
| x86 | unverified | unverified | unverified |
| amd64 | unverified | unverified | unverified |
| ARM64 | unverified | unverified | unverified |

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

Installed, not executed: native System32 dism.exe version 10.0.19041.1, 289136
bytes, measured SHA-256
`6a2bc5111b7ea9c4c6fdca0db462187b8b9b1ef009bd2d28a2a0124e3d31b95d`;
DismCore.dll 413160 bytes,
`fbb5135de4f6a5c9422a0b218d676930db9bc9a2aea0f7219077862912455914`.
Research observed valid Microsoft Windows signatures and PE 8664 for these
files. Installed signatures/bytes are not a distributable ADK manifest, proof of
newer-image compatibility, or runtime success. The full current-host inventory
remains in `provider-research.md`; it must not be copied as an ADK toolchain.

[DISM platforms](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-supported-platforms?view=windows-11)
distinguishes host/tool/image versions. WinPE-specific restrictions are not
universal full-Windows host restrictions. Microsoft's
[ARM manufacturing workflow](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/arm64-device-manufacturing?view=windows-11)
documents an amd64 technician-PC scenario, not nine-pair native proof.
[Oscdimg options](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/oscdimg-command-line-options?view=windows-11)
describe UDF/El Torito; native helper byte availability is now established by the
static inventories above. Mastered filesystem, target boot resources/catalog,
bootability, host compatibility and operation/dependency/rights closure remain
unverified. [W2 acquisition](acquisition.md) documents the candidate-only manager
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

The execution/inspection adapter, trustworthy fixture corpus and independent
expected hashes, concrete complete provider decisions, rights/dependency/
signature/acquisition/setup/restart closure, actual native x86/ARM64 hosts,
clean-machine validation, nine real modified-image/media proofs and all
source-family algorithm proofs remain pending. The stopped policy path is a
separate execution blocker. Future authorized work must resolve those concrete
items and retain actual inputs, outputs, commands, host observations and
independent inspection artifacts before opening Gate P/S. Green validator
tests cannot substitute for any of them.
