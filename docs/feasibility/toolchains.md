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
`provider-runtime-report.md` and `source-census-research.md`. Research archives,
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

Official [ADK acquisition](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install)
and [offline/silent workflow](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-offline-install)
document vendor-direct `/layout` and `OptionId.DeploymentTools`. These commands
were **not run**. HEAD-only redirect observations, dated 2026-10-27:

| Candidate kit | Official route | Resolved destination; reported length |
| --- | --- | --- |
| 10.1.26100.9457 | https://go.microsoft.com/fwlink/?linkid=2289980 | https://download.microsoft.com/download/8e0c0f5a-abb5-4358-a51b-168eb40b1590/adk/adksetup.exe ; 2233776 |
| 10.1.28000.1 | https://go.microsoft.com/fwlink/?linkid=2337875 | https://download.microsoft.com/download/615540bc-be0b-433a-b91b-1f2b0642bb24/adk/adksetup.exe ; 2236280 |
| Windows 10 2004 republished | https://go.microsoft.com/fwlink/?linkid=2120254 | https://download.microsoft.com/download/3b40cb81-ff9c-4322-aacd-c78d01b2c2ed/adk/adksetup.exe ; 1970056 |

No setup/package hashes, signatures, EULA/REDIST list, complete feature layout,
native x86/amd64/ARM64 file chain, installer privilege/return/restart behavior or
Oscdimg bytes were inspected. A kit label or HEAD length is not a helper digest.
Moving fwlinks cannot be an unvalidated moving-latest manifest. The
[ADK servicing page](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-servicing)
lists version-specific patch requirements; the base kit alone is not necessarily
the selected package closure. Version-specific rights/notices and allowed
vendor-direct acquisition or redistribution remain gates. Download availability
does not establish a redistribution entitlement.

The dependency inventory still required per native provider/version/operation
includes dism.exe/DismApi, DismCore/CorePS/Prov/Host, applicable imaging/CBS/
edition/international/driver/Appx provider DLLs, resources, WIMGAPI, native OS
dependencies, WIMMount/compact-image drivers/native setup when used, and
compatible target CBS/servicing-stack/package/app dependencies. The
[Microsoft copy procedure](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/copy-dism-to-another-computer?view=windows-11)
demonstrates why dism.exe alone is insufficient; it is not a certified complete
full-OS recipe for every version. Native setup may need elevation and driver/
restart handling; none was attempted. Historical tool versions must remain
available when required by image/operation compatibility.

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
describe UDF/El Torito, not native helper availability or verified bootability.
No concrete native ISO provider/dependency/rights closure is complete.

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
