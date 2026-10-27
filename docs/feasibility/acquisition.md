# Pinned acquisition component — W2 remains BLOCKED

Recorded 2026-10-27. This is a partial candidate catalogue and byte-materialization
component. It is not a release-ready tool provider. Full W2 acceptance and Gates
P/S remain blocked by the unresolved P1 runtime, dependency, rights, native-host
and application-managed prerequisite work described in [toolchains.md](toolchains.md).
Every upstream target remains visible, including architecture values beyond
`x86`, `amd64`, and `arm64`.

## Public boundary

`internal/tools` provides:

```go
func DefaultManifest() (TrustedManifest, error)
func LoadTrustedManifest(data []byte, expectedSHA256 string) (TrustedManifest, error)
func (m TrustedManifest) Digest() string
func (m TrustedManifest) Select(req Requirement) (Selection, error)
func NewManager(opts Options) (*Manager, error)
func (m *Manager) Ensure(ctx context.Context, req Requirement, emit model.Emit) (Toolchain, error)
func (m *Manager) Close() error
```

`Requirement` fixes `Host model.Host`, `Target model.Architecture`,
`Operations []Operation`, and `ManifestDigest string`. Supported operation
identifiers are `extract`, `inspect`, `service`, `reconstruct`, and `master-iso`.
The host build must be Windows 10 or later. Selection uses native host
architecture even when process architecture differs. An open-ended target is
retained in the returned selection and capability diagnostics. Selection copies
caller-owned operation slices and returns copied candidate facts.

`Selection` contains the original requirement, candidate identities and explicit
blockers. Candidate `IntentOperations` describes documented investigation scope;
it is never a supported-operation claim. Missing operations and native providers
produce explicit diagnostics. Static machine types and versions cannot establish
host compatibility, supported image generation, source-family coverage, or actual
operation success.

`Options` borrows an actual W1 `*windows.Workspace` and the D4 port:

```go
type Fetcher interface {
    FetchOne(context.Context, model.Payload, model.Locator, model.Emit) (download.CachedFile, error)
}
```

Keep the workspace and the fetcher's cache alive until `Close` returns. One
manager exclusively leases the tool workspace through a Windows kernel file
lock. `Close` cancels and waits for its work, then releases the lease. It does
not close borrowed handles or delete provider versions. The caller owns durable
workspace-identity persistence and eventual removal. There is no TUI executable
path input and no source/planner/controller substitute.

**Every valid `Ensure` request currently returns a zero `Toolchain` and a
`*BlockedError` wrapping `ErrUnverified`.** It does so before FetchOne, ZIP
materialization, any process launch, or setup. A wrong manifest digest returns
`ErrManifestDigest`; malformed requirements and closed/canceled calls have their
own errors. `Toolchain` has read-only copy accessors for verified file snapshots,
operations, manifest digest and provider IDs, but schema 1 never produces a
nonzero operational toolchain. No production readiness or approval switch exists.

The actual W1 `ProcessRunner`/`Invocation` contract remains the required future
execution boundary. This partial manager has no runner injection or implemented
probe lifecycle because it never executes anything. A future readiness mechanism
must bind trustworthy retained runtime evidence, exact source/target generation,
operation closure and prerequisites before exposing paths to metadata/engine
consumers. P1's structural `Evidence` validation alone supplies no attestation.

## Trust and static candidate facts

The embedded `manifests/v1.json` is checked against a SHA-256 constant reviewed
with the source, using LF line endings independently of Git checkout policy.
External loading requires an exact byte digest from trusted
application code. Accepting a digest delivered alongside an untrusted document
would supply no independent trust. This component does not verify detached
signatures or current Authenticode/revocation policy.

The loader limits JSON to 4 MiB, rejects unknown fields, duplicate keys
(including case variants), trailing documents, unsafe/duplicate file names,
invalid digests, ambiguous provider identities and moving/insecure acquisition
URLs. Schema 1 requires explicit pending blockers for every provider. Manifest
content identity cannot imply permission or operational readiness.

The catalogue records 15 native candidates: wimlib 1.14.5 for three hosts, and
DISM/Oscdimg from each of the pinned 10.1.19041.5856 and 10.1.26100.9457 kits for
three hosts. Microsoft packages labelled `x86` contain the separately measured
native x86, amd64 and ARM64 tools. Oscdimg's unchanged file version does not
collapse different bytes across kits. The 28000.1 base is excluded while its
required patch closure remains uninspected.

Pins preserve exact public vendor URLs, measured sizes/SHA-256 values,
separately attributed Microsoft Burn-manifest SHA-1 values, and dated signature
observations/signers. Local SHA-256 measurements are not independently published
publisher hashes. Historical `Valid` signature observations used the research
host's trust state; they do not represent a fresh-machine signature check.
wimlib's inspected native PE files were unsigned. Its per-file `version` denotes
the enclosing publisher release; Microsoft's denotes observed file-version
metadata. Neither proves runtime compatibility.

The catalogue is deliberately a focused inventory. Microsoft companion CABs,
the complete DeploymentTools feature, all runtime files and the dynamic/target
stack closure are not represented as complete. wimlib companion EXE/DLL bytes
are pinned; the observed four notice filenames are retained but their file pins
are not complete. All providers remain blocked. Metadata facts were transcribed
from the coordinator's `provider-research.md`, `adk-static-research.md` and their
retained JSON inventories; research archives, MSI/CAB files and legacy scripts
are not application resources.

## Private ZIP backend

`materializeZIP` is private and unreachable from `Ensure`. Unit tests call it
only with invented text in synthetic archives. No checked-in candidate is
extracted or launched through it. It currently handles one pinned ZIP, with no
installer, prerequisite, driver, UAC, reboot, repair or uninstall behavior.

The backend requires an exact SHA-256/size for every declared file, companion
reference and retained notice. It calls D4 FetchOne with a stable public-vendor
payload identity and runtime locator, verifies the returned identity, then
rehashes the opened archive itself. Per-file verification checks actual bytes,
exact size and SHA-256; the backend never loads a PE or treats a successful
byte hash as a capability probe.

ZIP validation rejects traversal, absolute/UNC/drive/ADS/device paths, Windows
case collisions, file/directory conflicts, symbolic links and nonregular file
types. Limits are 512 MiB compressed/per-file, 2 GiB declared total expansion,
and 4,096 entries. All entries are validated; only pinned files are copied.
Each copied file is bounded while reading and hashed before publication.

W1 handle-relative operations keep writes under the private workspace. A random
staging directory receives the entire verified set before files are published
with W1 atomic replacement. Provider directories include ID, version, full
manifest digest and native architecture, so versions coexist. A completion
marker binds provider content and manifest identity and is published last.
Interrupted partial publication has no trusted marker; later work rehashes the
complete set. Unexpected files, modified companions or inconsistent markers
cause integrity errors. This is not an operation journal or a power-loss
durability guarantee. Cleanup removes only exact staging files and empty
directories and reports cleanup failures; no recursive removal or host DISM
replacement occurs.

## Rights, prerequisites and acceptance still required

Preserve the four wimlib COPYING files and applicable GPLv3-or-later,
LGPLv2.1-or-later and libdivsufsort notices, and resolve corresponding-source or
relinking obligations for the concrete product model. The matching source URL,
size and measured digest remain recorded as provenance; no distribution policy
or compliance certification is supplied.

The actual current and historical Microsoft EULAs were inspected during static
research. Current use wording includes compatibility and End-of-Support
conditions; the older wording differs. ADK sample-code and WDK provisions do
not establish a DISM/Oscdimg redistribution grant. Exact per-job applicability,
additional notices and permission for the selected acquisition/use model remain
unresolved. Public download availability alone supplies no entitlement.

Microsoft's vendor-direct `/layout` and `OptionId.DeploymentTools` route is a
candidate for application-managed acquisition. It has not been implemented or
exercised. Required license acceptance, privileges, native helper/driver setup,
.NET detection, return codes, pending/forced reboot, cancellation, repair,
conflicts, uninstall and repeated provisioning must be proved per chosen kit.
The product must manage those requirements; a manual ADK prerequisite is not an
accepted solution. Adequate installed DISM may be preferred only after validating
its complete operation-specific identity/compatibility/closure; that validation
is not implemented here.

Automatic approval review previously rejected affected pinned wimlib
extraction/direct execution with only `blocked by policy`. That route remains
stopped and was not retried through Go, tests, another shell, tool or host.
No actual vendor helper/installer was extracted or executed by this component's
verification work. Clean-machine native x86, amd64 and ARM64 acquisition probes
were not run. The full requested Ensure digest/companion-file return acceptance,
complete pinned provider readiness, managed prerequisites, current signature
verification and all nine native host/target operation proofs remain unfulfilled.
Passing `go test ./internal/tools -count=1` proves only component behavior with
synthetic safe data and refusal boundaries.
