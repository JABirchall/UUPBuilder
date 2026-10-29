# Shared engineering contracts

**Authoritative scope amendment (2026-10-29)**

[The user's reduced scope](2026-10-29-scope-amendment.md) specifies ISO-file-only output and supersedes recovery, R17 UI/terminal and bootability-testing requirements in this historical contract. New orchestration need not implement Recover/List/Discard or restart discovery; active operation ownership, cancellation and resource cleanup still apply. Existing types and completed implementations are not removed merely to edit this document.

G0 establishes the dependency-free `uupbuilder` module with Go 1.27.0. There is
no `go.sum` until a task introduces a real external dependency. Only the
coordinator changes these shared contracts after G0; consumers use public model
types rather than guessing another package's internal representation.

| Contract | Representation and boundary |
| --- | --- |
| `model.Architecture` | Open string; known targets include `x86`, `amd64`, `arm64`. `arm` and future values survive. `ArchitectureFromGo("386")` explicitly maps the Go host name to `x86`. Host architecture never filters target choices. |
| `model.SourceIdentity` | Opaque, complete `UpdateID` including its revision, descriptive `BuildLabel`, target architecture and language. No URLs. `NewSourceIdentity` validates without parsing or rewriting the upstream ID. |
| `model.Selection` | `UpdateID string`, `Architecture Architecture`, `Language string`, `Editions []string`. `Validate` requires a nonempty edition set without duplicate identifiers. Unknown editions remain requests for applicability checking. |
| `model.PayloadIdentity` | Comparable digest algorithm/value, `Size int64`, original `PackageProvenance{Source, Name}`, and optional `EncryptionIdentity{Method, Fingerprint}`. No nullable download UUID or encryption secret. `Key` hashes all identity fields. Validate before using it. |
| `model.Payload` | Identity plus canonical slash-separated logical relative `Destination`. `NewPayload` validates both. |
| `model.PayloadManifest` | Source, selected payloads and deterministic lowercase SHA-256 `Digest`. `NewPayloadManifest` copies/sorts its payload slice and rejects Windows destination collisions. Treat a constructed manifest as frozen; `Validate` detects content changes. Digest version 1 hashes canonical JSON of `{version, source, payloads}` without its own digest, URLs or expiry. |
| `model.Locators` | Runtime `map[PayloadIdentity]Locator`, with URL and optional expiry. Neither the map nor an individual `Locator` allows JSON serialization. Locator fields are excluded from TOML. Never include runtime locators in persisted/public records. |
| `model.ResolvedSettings` | Typed conversion, app, driver, edition, output, storage and download policies. Structural validation preserves explicit requests; source/host/tool applicability belongs to later resolution. No zero-value defaults are silently supplied. |
| `model.Host` | Windows build, process and native architecture, and filesystem name/locality/ACL/stream/reparse/hard-link capabilities. |
| `model.Event` | Job/stage IDs, kind, message, optional completed/total byte/item counters and timestamp. Nil totals mean indeterminate progress; no fabricated percentage or ETA. |
| `model.Emit` | `func(Event)`. The coordinator supplies a thread-safe sink. Journal durability must not depend on UI event delivery. |
| `model.Artifact` | Output kind, path, lowercase SHA-256, size, verification/report paths and source/plan identity. An artifact descriptor is not proof of verification. |
| `model.Diagnostic` | Stable code, severity, source file/key/line/column, message, optional selection and policy key. Source locations use one-based line/column when available; zero means unknown. |
| `model.SettingApplicability` | Setting key, canonical public requested/effective values, supported/automatic booleans and a concrete reason. An unsupported explicit request retains its original requested value. No secrets in either value. |

`Digest` supports MD5, SHA-1, SHA-256, SHA-384 and SHA-512 source metadata, with
canonical lowercase hexadecimal values and the exact algorithm-specific length.
`NewDigest` canonicalizes letter case; `Validate` rejects noncanonical direct
struct values. Supporting a legacy algorithm does not establish metadata trust;
download ingestion must verify the source digest/size and compute SHA-256 for
the internal cache. Encryption fingerprints are SHA-256; an unencrypted payload
has both encryption fields empty. Original package provenance is retained even
when its name differs from the destination.

`ValidateRelativePath(value string) (string, error)` performs lexical Windows
validation on every host. It rejects empty/traversal components, absolute/UNC
and drive paths, alternate data streams, invalid Windows characters, controls,
NUL, trailing spaces/dots and reserved device names (including extension forms).
It normalizes backslashes to slashes. W1 must independently check resolved
filesystem containment and reparse points before privileged IO; lexical checks
do not establish that a physical path stays inside an owned root.

## Settings policy vocabulary

| Area | Fields and values |
| --- | --- |
| Output | Kind `iso`, `image`, `directory`; format `wim`, `esd`, `swm`; split size MiB; directory, filename, label, edition order. SWM requires a positive split size. Filename/label can retain the `auto` policy marker. |
| Updates | `integrate`, `external`, `omit`; servicing `auto`, `per-edition`, `shared-base`; cumulative/checkpoint expansion independently `auto`, `expand`, `preserve`; enablement packages `auto`, `include`, `omit`. |
| Cleanup | Component cleanup boolean; reset-base `off`, `auto`, `on`; retain reference ESDs and storage intermediate-data policy. |
| Features/recovery | .NET 3.5, WinRE inclusion and boot-file update booleans; WinRE updates `auto`, `include`, `omit`. |
| Construction | Boot-WIM engine `auto`, `wimlib`, `dism`; reference handling `auto`, `reuse`, `export`; cumulative MSU handling `auto`, `expand`, `keep`. These values express requests, not claims that every source supports every engine. |
| Drivers | Enabled, source directory and explicit `os`, `winpe`, `winre`, `shared` targets. Enabled integration requires source and targets. Disabled settings remain present. |
| Apps/Edge | App mode `default`, `custom`, `none`; optional preset; stable included package families; stub preference `auto`, `stub`, `full`; Edge `default`, `include`, `exclude`. Availability is checked against real source inventories later. |
| Editions | Selected editions live in `Selection`; requested derived editions, edition servicing strategy and temporary preservation of required bases live in conversion edition settings; final order lives in output settings. |
| Storage/downloads | Workspace/cache path or `auto`, retention booleans, positive parallel file count, nonnegative retries. Proxy mode `system`, `direct`, `explicit`; explicit URL is an HTTP/HTTPS/SOCKS5 origin without credentials/query/fragment. Runtime credentials must be kept outside frozen snapshots. |

These are typed product policies, not arbitrary tool commands. Structural
validation does not silently override an explicit unsupported setting; a later
resolver emits applicability diagnostics or fails before mutation. Preset/app
families, derived editions and paths remain intact for that process. Defaults,
versioned TOML parsing, atomic persistence, migration and comment handling belong
to D1, not this bootstrap.

## Producer interfaces

The public producer signatures below are fixed. Their concrete producer-owned
types are defined by their respective task, not by model scaffolding.

```go
// G0, internal/app
func Run(ctx context.Context, args []string) error

// D1, internal/config
func Load(path string) (Config, error)
func Save(path string, cfg Config) (SaveResult, error)
func (cfg Config) Validate() error
func (cfg Config) Request() (model.Selection, model.ResolvedSettings, error)

// D2, internal/catalog
func New(client *http.Client, baseURL string) *Client
func (c *Client) Search(ctx context.Context, query string) ([]Build, error)
func (c *Client) Languages(ctx context.Context, updateID string) ([]Language, error)
func (c *Client) Editions(ctx context.Context, updateID, language string) ([]Edition, error)
func (c *Client) Files(ctx context.Context, updateID, language, edition string) (FileSet, error)

// D4, internal/download
func (m *Manager) Fetch(ctx context.Context, manifest model.PayloadManifest, locators model.Locators, emit model.Emit) (Materialized, error)
func (m *Manager) FetchOne(ctx context.Context, payload model.Payload, locator Locator, emit model.Emit) (CachedFile, error)

// M1, internal/metadata
func Inspect(ctx context.Context, req InspectRequest) (Inventory, error)

// D3, internal/source
func (r *Resolver) Resolve(ctx context.Context, selection model.Selection, settings model.ResolvedSettings) (Resolution, error)
func (r *Resolver) RefreshLinks(ctx context.Context, frozen model.PayloadManifest) (model.Locators, error)
func Refresh(ctx context.Context, frozen model.PayloadManifest, fresh Resolution) (model.Locators, error)

// W2, internal/tools, using W1's Windows direct runner
func (m *Manager) Ensure(ctx context.Context, req Requirement, emit model.Emit) (Toolchain, error)

// E2, internal/planner
func (p *Planner) Resolve(ctx context.Context, req Request) (ReadyPlan, error)

// J2, internal/jobs
func (c *Controller) Start(ctx context.Context, plan planner.ReadyPlan) (JobView, error)
func (c *Controller) PauseDownloads(ctx context.Context, jobID string) error
func (c *Controller) Resume(ctx context.Context, jobID string) error
func (c *Controller) Cancel(ctx context.Context, jobID string) error
func (c *Controller) Recover(ctx context.Context, jobID string) (JobView, error)
func (c *Controller) Subscribe(ctx context.Context, jobID string) (<-chan model.Event, error)
```

`catalog.FileSet` separates identities and runtime locators.
`download.Materialized` maps payload identity to an app-owned verified path.
`metadata.Inventory` exposes source roles, package graph, image properties,
apps/frameworks/licenses and source family. `source.Resolution` combines frozen
manifest, runtime locators, metadata inventory and source classification.
`planner.Request` carries selection, settings, source resolution, host and draft
revision. `ReadyPlan` owns an immutable operation graph, tool requirements,
resolved settings, estimates, draft revision and content digest, with deep-copy
read access and no persisted runtime locators, secrets or proxy credentials.
E2 owns the typed `planner.Operation`, extended by E4/E5. `jobs.JobView` is a
read-only state/stage/error/artifact/action snapshot.

The G0 executable validates `--config PATH` or `--config=PATH`, resolves an
absolute path (default `%LOCALAPPDATA%\UUPBuilder\config.toml`), and returns
initialization/cancellation errors. Unknown/positional/duplicate arguments and
empty paths fail. It does not read/write configuration, start a UI or perform
work yet. Relative application paths from a loaded TOML file will be resolved
against that file's directory by D1. The bootstrap binary is not a completed
builder.
