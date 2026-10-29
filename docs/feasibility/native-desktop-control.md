# Authentic native desktop control input

Observed 2026-10-28. This freezes a Microsoft-published Media Creation Tool
(MCT) **media-input ESD** for read-only control preparation. It is not an ISO,
a UUP update identity, or passing source-family/provider/servicing/boot evidence.

## Public provenance and verified source bytes

The current [Microsoft Windows 10 page](https://www.microsoft.com/en-us/software-download/windows10)
links to [MCT 22H2](https://go.microsoft.com/fwlink/?LinkId=2265055).
The actual tool was retained as inert data: 19,463,448 bytes, SHA-256
`690c8a63769d444fad47b7ddecee7f24c9333aa735d0bd46587d0df5cf15cde5`,
version 10.0.19041.572, current Authenticode Valid/Microsoft Corporation.
Its embedded SetupMgr.dll also reported Valid/Microsoft Windows; its SHA-256 is
`45c2ee2387026a50f0c6b9c9119f39b6d2b6505312dbdf352399fd41e8deb78f`.
That member contains the current [public manifest route](https://go.microsoft.com/fwlink/?LinkId=841361),
which redirected to an HTTPS Microsoft products.cab. Observed SHA-256 pins:

- Manifest CAB: `7677dd6247c5768737b643911894374939aac5ae2dea158c272511fdd2ac52bf`.
- Extracted products.xml: `76fcc8eeacb7da966441a7e0ac8b79cc095f13682abb92ee5a614c52f72ce54c`.

The manifest is unsigned; its exact en-us/x64/Professional entry publishes an
HTTP Microsoft delivery locator, the size and SHA-1 below. The original locator
was used unchanged. One HTTP 200 response supplied the complete body; no redirect
or retry was needed. Locators and source bodies remain private research data.

| Source property | Verified observation |
| --- | --- |
| Original filename | `19045.3803.231204-0204.22h2_release_svc_refresh_CLIENTCONSUMER_RET_x64FRE_en-us.esd` |
| Actual disk length | `4164077935` bytes |
| Independently published SHA-1, matched on disk | `e35f49be74010d22e1bf9d2f200e48f3f7fd0a66` |
| Locally computed and reread SHA-256 | `0c8cc284d29d6b9bee19daa3fbb7bafd7536d98069c2cd0cc7055e2703eda7e9` |

SHA-256 is a local retained-byte identity, **not a vendor-published expectation**.
The earlier direct ISO selection returned SentinelReject and was not retried;
no claim is made that this ESD matches that ISO's published SHA-256.

## Actual image metadata

Bounded reads found WIM magic, version `0x00000e00`, flags `0x00080082`, chunk
size 131,072, part 1 of 1, ten images and boot index 3. The plain UTF-16LE XML
resource is 22,746 bytes; its SHA-256 is
`e9099831a67cfaf9d90c3ac23bf10eee48a09ac7ccf9d84a53bfdf0807a12d6e`.

| Actual index | XML image identity |
| --- | --- |
| 1 | Windows Setup Media; XML has no Windows architecture/version fields |
| 2 | Microsoft Windows PE (x64); WindowsPE |
| 3 | Microsoft Windows Setup (x64); WindowsPE; header boot index |
| 4–8 | Home, Home N, Home Single Language, Education, Education N |
| **9** | **Windows 10 Pro; Professional; Client** |
| 10 | Windows 10 Pro N; ProfessionalN; Client |

Indices 2–10 report ARCH `9` (amd64), language/default `en-US` and XML version
**10.0.19041.3803**. Separately, the actual Pro SOFTWARE hive reports
CurrentBuild/CurrentBuildNumber `19045`, UBR DWORD `3803`, DisplayVersion `22H2`,
EditionID `Professional` and InstallationType `Client`. Its ProductName is
`Windows 10 Enterprise`; this differing label is retained without inventing a
cause or overriding the XML/EditionID selection.
Pro index 9 reports 28,568 directories, 103,379 files and 15,625,575,440 total
bytes. Index selection came from these observed fields.

The actual Pro and Setup-media metadata streams were decompressed with measured,
installed System32 cabinet.dll. Their expanded SHA-1s matched their embedded
lookup descriptors: Pro `be87f06707e88a3df19a6a77a8ac8efe99c1a35c`;
Setup media `a75f99074ce00311899fdcae5fdc646e74a4e9d2`.
Bounded tree enumeration matched the XML directory/file counts.

## Verified source members and baseline data

An explicit 22-file metadata-selected allowlist was extracted as inert data.
Every actual length/SHA-1 matched its embedded stream expectation before reading
the result; selected output totaled 89,112,211 bytes. The private reader used
measured installed cabinet.dll, bounded 64 MiB chunks and one cached chunk under
a 512 MiB process memory cap; measured peak commit was 254,328,832 bytes.
Representative actual member pins (SHA-256 is locally measured):

| Image/member | Actual bytes | Local SHA-256 |
| --- | --- | --- |
| 1: `setup.exe` | 74184 | `30043368051ccaad512558f0c08a3f3da57f15967f38a76208f64eff06ee8043` |
| 1: `sources/setup.exe` | 294256 | `cc71d6622206ab0814a9b043573750994af7f5119a1e01086a6ae749ad4b3fc8` |
| 1: `efi/boot/bootx64.efi` | 1590656 | `c9e35a2dcc23fbe1a60e4ca5cadae4da3813ad4440c5837c7326c4794324d7fc` |
| 1: `efi/microsoft/boot/efisys.bin` | 1474560 | `1525b5abccdc2c298693de4de64af208edb080e3068fcd6533967d2e2cf6cb4e` |
| 9: OEM/default Professional `license.rtf` | 140135 | `d7b69005eb679f71c2961225bf26e789c312596808d017a3f434eaa691fb52d1` |

The selected Setup/EFI binaries, TrustedInstaller and source IntlProvider,
OSProvider, CbsProvider and wimgapi DLLs all reported PE amd64 and current
Authenticode Valid/Microsoft signers when read as data. Their versions differ;
static pins are not executed-provider/dependency closure.

The actual ServicingStack_3745 MUM identifies KB5032907/version 19041.3745.1.0;
the actual 22H2Enablement MUM identifies version 10.0.19041.1799. Their matching
SOFTWARE CBS package keys both contain CurrentState DWORD `112`. Those raw facts
do not establish CBS operation or full package/reference closure.

Four verified source hives were inspected with a bounded offline data parser;
none was loaded into the host registry. Both the DEFAULT and default-user hives
contain `Keyboard Layout\Preload`, value `1`, REG_SZ `00000409`, with empty
Substitutes keys. Their International Locale is `00000409`, LocaleName `en-US`.
SYSTEM Select Current is DWORD `1`; ControlSet001 Nls InstallLanguage/Default
are REG_SZ `0409`. These baseline values do not establish a later servicing
operation's complete before/after semantics.

The OEM/default license texts are byte-identical. Their terms distinguish
acquisition channels and reference separate volume agreements; the short Volume
text conditions use on a validly acquired license and its governing agreement.
No terms were accepted and no entitlement or redistribution right is inferred.

## Retained failures and proof gaps

Installed signed System32 wimgapi.dll returned Win32 193 from the documented
read-only WIMCreateFile call with flags zero, before image load/extraction.
That limited reader result does not establish that ESD extraction is impossible.
The separately authorized bounded solid reader supplied the selected data above;
no undocumented native flag was tried. The original ESD was rehashed unchanged
after extraction. No complete image/resource closure is claimed from 22 streams.

No downloaded code, source DLL, setup, image mount/apply/servicing or elevated
operation ran. Native provider/dependency closure, independent configuration
before/after expectations, modification persistence, complete media mastering,
actual boot and UUP-family acceptance all remain unverified.

## Prepared fixed control runner

The private `nativecontrol` probe now prepares a sealed request and protected
local NTFS bundle, journal, provider scratch/log and reapply scopes. Preparation
only reads the pinned ESD, installed DISM, compiled runner, host/token and retained
hives; it starts no image operation or elevation. The opt-in run entry requires
the exact executable/request identities and a measured same-user elevated token.
It uses J1 durable intent, genuine owned mount claims and one retained process
session for a fixed export/copy/mount/input-locale/commit/export/reapply graph.

[DISM input servicing](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-languages-and-international-servicing-command-line-options?view=windows-11)
documents the intended input-profile change. The independent default-user hive
assertion is a prebound hypothesis: Preload value `1` must durably become
`00000809`, with no substitution, after reapply. DEFAULT input observations are
retained without assuming they change; identity and en-US UI/system/user-locale
invariants remain required. The bounded pure-Go REGF reader rejects dirty,
corrupt, ambiguous and unsupported selected data without host hive loading.

Failure recovery intersects the sealed request, exact interrupted J1 intent,
original directory identities and actual image/index/path inventory. Unknown
state preserves resources. It offers only exact owned discard, with no global
cleanup or interrupted mutation resume. Provider and applied trees are retained.
Sampled process/module facts and DISM logs support diagnosis; neither static
inventory nor sampled observations establish complete dependency closure.
The compiled private runner and action/recovery proposal await review and a
separate concrete execution approval. No native control success is claimed.
