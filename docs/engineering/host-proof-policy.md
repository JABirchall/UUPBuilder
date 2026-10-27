# Host architecture proof policy

On 2026-10-27 the user decided: "Go is cross platform for x86 and arm, so is windows. If it all works correctly on this host, consider that as full proof."

Successful complete functional evidence on the available native Windows host,
together with successful Windows builds for Go `386`, `amd64` and `arm64`,
satisfies host-architecture coverage for P1, W1, W2 and R1. Physical x86/ARM64
hardware is optional corroboration and its absence is no longer a blocker.
This policy supersedes earlier clauses requiring execution on every physical
host architecture. All advertised host/target choices and nine common logical
pairs remain required.

Record actual execution truthfully. `Case.Host` describes the actual native
execution requirement; `Evidence.Host` records the observed OS, Windows build,
native/process architecture and filesystem. WOW64 or emulation is not a native
x86 observation. Never relabel evidence to claim execution on untested hardware.

`ValidateEvidence` retains its strict observed-record contract. The separate
`ValidateArchitectureCoverage(required, observed)` returns each required case,
host and target, its actual witness case/host, and either `observed` or
`portability-accepted` basis. Every witness must pass `ValidateReady` and strict
`ValidateEvidence` against its own exact frozen descriptor. Counterparts must
match gate, OS/minimum build, target, exact source/revision/family, immutable
inputs, operations/algorithms and expected output digests/content assertions.
Native component bytes/closure and host architecture labels are not claims of
execution on other hosts. Counterpart pending prerequisites fail except the
existing explicit `native-host-not-established` code.

Use one available host for the complete functional suite; partial suites with
different measured host facts cannot be pooled. Separate runs can have different
host-report artifact identities. Each retained report is strictly validated;
the evaluator groups the reported host facts and does not independently attest
unique physical-machine identity. Runners and operators retain responsibility
for truthful provenance and actual retained byte/host checks.

The tagged provider gate selects the current physical host's applicable native
cases, then evaluates all nine logical pairs. Cross-builds remain a separate
explicit required build gate, not a field or runtime-readiness flag:

```powershell
$env:GOOS = 'windows'
$env:CGO_ENABLED = '0'
$env:GOARCH = '386'; go build ./...
$env:GOARCH = 'amd64'; go build ./...
$env:GOARCH = 'arm64'; go build ./...
```

Successful builds alone establish no runtime functionality. Failed, skipped,
unverified, component-only, synthetic and cross-compile-only observations cannot
be full proof. Synthetic validator tests establish only validation behavior.
Actual current-host source/target coverage, payload/reference closure,
algorithms, reconstruction, real Windows servicing, independently expected and
inspected outputs, ISO/boot checks, dependencies, rights, acquisition, setup,
clean-machine and release checks remain required. Source-family acceptance uses
this same architecture rule without inferring unrelated sources or targets.
Remaining functional gaps continue to block full P1/Gate P/S and release.
