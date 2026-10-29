# UUP Builder design

**Current development plan (2026-10-29):** [User workflow implementation plan](../plans/2026-10-29-uup-builder-user-workflow-plan.md) is the sole active task queue. It replaces the five previous plans, starts with app-loading rate limiting, and retains the completed implementation. Historical context and proposals below are subordinate to the scope amendment and current plan.

**Authoritative scope amendment (2026-10-29):** [Reduced scope](../../engineering/2026-10-29-scope-amendment.md) removes recovery, original R17 Review/Start/progress/terminal work and bootability testing. It supersedes conflicting clauses below; historical text is retained as design history.

Date: 2026-10-27

Status: Accepted as the product design baseline on 2026-10-27, when the user requested a multi-agent plan using GPT-6.1 Sol at xhigh. Implementation is in progress; current integrated state and remaining tasks are recorded in the user workflow implementation plan.

**Authoritative host-proof amendment (2026-10-27):** The user accepts successful complete functionality on the available native Windows host plus Windows `386`/`amd64`/`arm64` builds as full host-architecture coverage. The [host proof policy](../../engineering/host-proof-policy.md) supersedes earlier mandatory physical-host execution clauses throughout this design and its plans, including P1/W1/W2/R1. Unavailable x86/ARM64 hardware is no longer a blocker. Preserve all nine logical common pairs and actual host facts; distinguish observed from portability-accepted coverage. All functional, source/target, provider, servicing, media, dependency, rights and setup requirements remain.

## Intent

Build a Windows terminal application in Go using Charm. A user downloads one executable, browses UUP Dump, selects a Windows image, changes conversion settings and Store app selection, and produces bootable installation media. The app manages downloads, supporting tools, image construction, progress, and recovery.

The purpose is to offer the whole UUP-to-ISO workflow in one managed application, without manual tool installation, script editing, or separate commands. This is a full project that includes a new conversion engine.

## User decisions

- Go implementation with a Charm TUI.
- One executable for the user to download and run. Helpers may be extracted or downloaded behind the scenes, with the app managing their complete lifecycle.
- Browse and search builds from UUP Dump, then choose architecture, language, and editions.
- Customize the conversion configuration and custom Store apps list.
- Use TOML for application configuration.
- Treat the existing files in this directory as guidance. Do not consume, copy into the product, modify, or execute them as application resources.
- Implement the conversion pipeline in Go and call individual tools directly. Do not use an upstream conversion script as the engine.
- Cover all builds available in UUP Dump.
- Run on Windows 10 and later, supporting the x86 and Arm architecture families.
- Allow every build target on every supported host. Do not restrict available targets to a smaller host/target compatibility matrix.
- Use the Workspace interface direction selected in the visual preview and accepted with “Looks good.”

## Author proposals included for approval

These are proposed implementation choices, not additional requirements attributed to the user.

- Working name: UUP Builder.
- Ship native Windows executables for `386` (32-bit x86), `amd64` (x64), and `arm64`. Each user downloads one executable matching their machine. Interpret Arm as ARM64; an ARM32 host build is not included in this proposal.
- Keep the host architecture separate from the ISO target. Select or implement appropriate providers for every required host/target combination; the host CPU does not filter the target choices.
- One job builds one architecture and one language, with one or more editions. Run one conversion job at a time, with parallel network transfers.
- Use Go HTTP downloads, Bubble Tea v2, Bubbles v2, and Lip Gloss v2. Pin compatible dependencies during implementation.
- Use TOML for editable settings and resolved job snapshots. Keep journals and payload manifests as separate machine-managed records.
- Resume downloads and reuse verified completed stages. Restart interrupted mutating stages from clean checkpoints.
- Let users choose output and working directories; default scratch work to local NTFS storage.
- Run browsing, editing, and ordinary downloading without elevation. Use the same executable as an elevated worker when image operations require it.
- Provide an interactive TUI and `--config`. A separate unattended/CI product interface is outside the first complete release.

## Goals and scope

The app must start on a clean Windows 10+ system without a separately installed runtime or terminal application; discover sources; validate settings; provision helpers; download and verify payloads; assemble and service images; create media; report real progress; recover interrupted work; and produce a verified artifact, SHA-256 digest, and build report.

### All-build compatibility

Catalog coverage is exhaustive. Do not hide older releases, Insider builds, Server, LTSC, specialized editions, or architectures because they are inconvenient to implement. The engine must cover all ISO-capable UUP source formats in that catalog through source-generation adapters, without an arbitrary Windows 11-only or current-release-only allowlist.

A catalog entry may be update-only, have removed/expired payloads, or represent a product without standard installation-media sources. Keep it discoverable, identify the missing requirement, and allow downloading available payloads. Do not label an incomplete artifact a working ISO, invent absent boot/setup files, or silently substitute another build.

An implementation gap is different from unavailable upstream source material. Display that distinction. Implementing only some valid source formats remains incomplete delivery of the requested engine. Unknown future formats may require an app update; catalog visibility alone must never be presented as successful conversion support.

### Cross-architecture requirement

Every supported host must offer every target advertised by UUP Dump. For ISO-capable sources, the required common architecture combinations are:

| Host executable | x86 target | x64 target | ARM64 target |
| --- | --- | --- | --- |
| Windows x86 / `386` | Required | Required | Required |
| Windows x64 / `amd64` | Required | Required | Required |
| Windows ARM64 / `arm64` | Required | Required | Required |

Additional target architectures exposed upstream follow the same rule when their source can produce installation media. This table states required behavior, not completed validation. The user explicitly chose this requirement after the builder reviewer asked whether a restricted compatibility matrix would be acceptable.

Go and its helpers may inspect, reconstruct, and service another architecture's image as data; they must not assume target executables can run natively on the host. The plan must prove suitable providers for these combinations early. A missing provider is an unresolved engineering/release blocker, not permission to hide a target or narrow the agreed product. Present actual runtime/source failures truthfully while retaining all target choices. Do not add a hosted builder or require the user to set up a different machine as an unapproved workaround.

### Non-goals

- Reusing or launching the supplied downloader or an upstream all-in-one converter.
- Installing Windows on the host, writing USB devices, activating Windows, or changing host Windows settings as image-customization steps.
- Making a non-ISO-capable payload into an installer without necessary source material.
- Combining multiple target architectures or languages into one ISO initially.
- A web service, graphical desktop interface, or separate hosted build system.

### Failure conditions

Manual helper setup; TOML acting merely as a wrapper over the supplied batch workflow; silently ignored settings; successful status for incomplete media; unnecessary loss of verified downloads; reuse of partly modified images; or all-build claims based only on catalog listing/cross-compilation all count as failures.

## Context and evidence

The initial directory contains downloader/configuration examples, not a Go project or the complete converter. It is not currently a Git repository. Existing values must not be imported automatically: create a new typed configuration model and defaults.

The visual reference is the Workspace variant in `C:/Users/owner/.codex/visualizations/2026/10/27/01a17b69-703d-7eb2-85fd-9d3102de76fa/uup-builder-layouts.html`. It contains sample data and simulated progress. Its illustrative app restrictions and TOML are superseded by this document where more precise.

Primary references:

- [UUP Dump JSON API](https://git.uupdump.net/uup-dump/json-api): catalog, language, edition, and payload endpoints.
- [UUP Dump FAQ](https://git.uupdump.net/uup-dump/misc/src/branch/master/FAQ.md): official API host, update-only sets, and derived editions.
- [UUP Dump resolver source](https://git.uupdump.net/uup-dump/api/src/branch/master/get.php): package selection and app sets.
- [Go Windows support](https://go.dev/wiki/Windows) and [Charm v2](https://charm.land/blog/v2/): host targets and TUI libraries.
- [DISM overview](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/what-is-dism) and [supported platforms](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-supported-platforms?view=windows-11): offline operations and host/tool/image compatibility.
- [Windows ADK](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install) and [wimlib distributions](https://wimlib.net/downloads/index.html): candidate individual tool providers.
- [Packaged app provisioning](https://learn.microsoft.com/en-us/windows/msix/desktop/deploy-preinstalled-apps): dependencies and offline app inputs.
- [Oscdimg](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/oscdimg-command-line-options?view=windows-11): UDF filesystems and boot catalogs.

The installed Go 1.27 toolchain lists `windows/386`, `windows/amd64`, and `windows/arm64`. Runtime/helper compatibility has not been tested. A read-only live request to the official `listid.php` endpoint succeeded on 2026-10-27 after the sandboxed request encountered its blocked proxy. It returned JSON API version `0.2.3` and architecture-specific feature/update records for build `26300.9807`. Its `builds` value was an object with sparse numeric keys, rather than the array shown in the example documentation. Languages, edition/app resolution, and payload links have not yet been exercised live. No image tools have been installed or executed for this design.

## Approaches

| Approach | Benefit | Cost | Choice |
| --- | --- | --- | --- |
| Go app managing the upstream converter | Retains existing source-generation rules; smaller initial implementation | Behavior, progress, and input formats remain coupled to an external converter script | Offered, not selected |
| Go engine calling individual image tools | Owns typed configuration, planning, progress, validation, and recovery | Must implement and maintain source-format, servicing, edition, app, and boot logic | Selected by user |

Helpers remain acceptable, but hiding a full external converter behind the TUI does not satisfy the chosen approach.

## Workspace interface

Keep persistent navigation and a current-build summary, with Builds, Image, Apps, Conversion, Review, and Progress areas. UI navigation is separate from job state.

### Builds and Image

Show loading, catalog freshness, retry, and failure states. Search using supported upstream queries, debounce requests, cache results, respect rate limits, and allow explicit refresh. Locally filter already retrieved data where useful.

Display available build identifiers, architecture, and source type without inventing channel metadata. Group architecture records only when known to describe the same release, retaining each exact update UUID/revision. Changing architecture resolves the corresponding source record and refreshes available languages/editions.

Choose one language and one or more editions. Show downloadable bases and valid derived editions together, identifying derivations. Download necessary base sources without forcing those bases to appear as final image indices. Build/architecture/language changes explicitly invalidate dependent selections; do not carry unavailable selections unnoticed.

### Apps

Load the app inventory from package/composition metadata appropriate to the selected source and edition. Offer search, individual toggles, select-all, defaults, presets, and dependency information. Persist stable package-family identities, not translated display names.

Support `default`, `custom`, and `none` modes, inclusion presets where meaningful, and stub/full policy where supported. Resolve required frameworks, dependencies, and licenses automatically. Derive required/unavailable/incompatible states from real rules; the visual mockup's Store/Security/App Installer badges are not universal restrictions.

Some source families lack separate app payloads. Define their actual customization behavior explicitly, inspecting provisioned apps after image materialization when necessary. Do not infer app identity only from filenames or pretend absent apps are selectable. Requested unavailable selections are validation issues, not silently dropped settings.

### Conversion

Group settings with descriptions, applicability, ordinary/advanced controls, and effective values for automatic policies. Support the behavior represented by the reference configuration, expressed as typed product concepts:

| Area | Configuration behavior |
| --- | --- |
| Output | ISO, image-only, or prepared directory; WIM/ESD/SWM; split size; output directory/name/label; edition order |
| Updates | Integrate, include externally, or omit; servicing/edition-upgrade strategy; cumulative/checkpoint update expansion policy; applicable enablement packages |
| Cleanup | Component cleanup; supported reset-base policies; retention of reference ESDs and intermediate data |
| Features/recovery | .NET 3.5 where supported; WinRE inclusion and update policy; boot-file updates |
| Construction | Automatic/explicit supported boot-WIM engine; reference-image handling; applicable cumulative-update MSU behavior |
| Drivers | Integration on/off; source directory; OS/WinPE/WinRE/shared targets |
| Apps/Edge | App mode/preset/custom families; stub/full preference; build-applicable Edge inclusion/exclusion policy |
| Editions | Selected/derived editions, servicing strategy, output order, and temporary preservation of required bases |

App interactions replace script-only auto-start/pause-on-exit controls. Mutually exclusive formats become enums, not conflicting booleans. Invalid combinations fail before mutation. Rules may resolve `auto`, but an explicit request cannot be silently overridden or ignored.

### Review and Progress

Review the exact source UUID/revision, target, editions, apps, effective settings, output paths, download size, estimated peak scratch space, and required elevation. Distinguish measured sizes from estimates. Resolve small metadata and run preflight before large downloads where practical. Provide a clear Start action and actionable preflight failures.

Show actual stages, per-stage progress, transferred bytes/rate, completed/pending work, and readable logs. Use percentages only with real denominators; otherwise show a concrete operation and indeterminate progress. Do not fabricate an overall ETA. Pause applies to downloading; mutating operations use safe cancellation. Completion shows the artifact location, checksum, and report.

Support keyboard navigation, search focus, Space toggles, Enter selection/continuation, Esc back, cancellation, contextual help, and mouse where available. Work in legacy Windows console hosts and Windows Terminal, with compact layouts and ASCII/reduced-color fallback. A running job retains its immutable settings while users browse or edit a future job.

## Configuration and persistence

Use a typed, versioned TOML schema. Default path: `%LOCALAPPDATA%\UUPBuilder\config.toml`; support TUI save/load and `--config`. Resolve relative paths against the config file's directory. Example shape:

```toml
schema_version = 1

[catalog]
endpoint = "https://api.uupdump.net"

[image]
update_id = ""
architecture = "amd64"
language = "en-us"
editions = ["professional"]

[conversion]
updates = "integrate"
servicing_strategy = "auto"
cleanup = true
reset_base = "off"
netfx3 = false
include_winre = true
winre_updates = "auto"
update_boot_files = false
cumulative_update_policy = "auto"
boot_wim_engine = "auto"
edge_policy = "default"
keep_reference_esds = false

[conversion.drivers]
enabled = false
source = ""

[apps]
mode = "custom"
preset = ""
stub_policy = "auto"
include = ["Microsoft.WindowsNotepad_8wekyb3d8bbwe"]

[output]
kind = "iso"
image_format = "wim"
split_size_mib = 3800
directory = ""
filename = "auto"
label = "auto"
edition_order = []

[downloads]
parallel_files = 4
retries = 5
proxy = "system"

[storage]
workspace = "auto"
cache = "auto"
keep_downloads = true
keep_intermediates = false
```

The full schema covers the behavior table, including advanced policies. Exact field organization is left to the builder. This is not an arbitrary command passthrough.

Reject unknown keys, wrong types, unsupported schema versions, and invalid enums with useful file/key locations. Save atomically. Never replace malformed config with defaults silently. Back up before migration. Preserve manually maintained comments when supported; otherwise explain normalization and back up before rewriting an existing file.

Freeze each job's resolved settings as TOML. Store source identities, manifest/tool digests, stage outputs, owned mounts/processes, and recovery state separately. Shareable reports redact signed URLs and credentials.

## Architecture

One executable provides the TUI and a private elevated worker mode:

```text
Charm TUI
  -> typed config and validation
  -> catalog client and metadata inventory
  -> capability rules and immutable build planner
  -> job coordinator and checkpoints
       -> Go downloads and verified content cache
       -> helper/toolchain manager
       -> Go conversion stages and Windows worker
       -> artifact verification and report
  <- structured progress, logs, errors, recovery choices
```

Suggested responsibility boundaries: config, catalog, metadata, capabilities, planner, download, tools, engine, platform/windows, jobs, and tui. Exact package organization is a builder decision; do not scaffold everything before proving a useful vertical slice.

The TUI does not launch tools directly. Engine stages emit typed events for stage changes, bytes, completed items, warnings, errors, and checkpoint commits. Network/tool operations accept cancellation and appropriate bounded retries/timeouts.

## Source resolution and downloading

Use the official JSON API by default: `listid.php`, `listlangs.php`, `listeditions.php`, and `get.php`. Validate envelopes/status/errors, update identifiers/revisions, sizes, and hashes. Respect 429/backoff and Retry-After when supplied.

Normalize both array-shaped and object-shaped build collections, preserving record identities independently of numeric keys. Treat the reported API version as informational; validate capabilities and actual contracts instead of expecting a conventional version string.

Resolve selected base editions separately if necessary, union their payloads, and deduplicate using trusted identities/digests. Resolve app sets and package/dependency metadata before finalizing the app plan. The catalog API is not assumed to return a ready-made app inventory; validate the app-specific contract during initial integration rather than generating website download scripts.

Freeze UUID plus revision, architecture, language, and package identities as job inputs. Link refresh may replace expired URLs only when payload identities remain the same. Source changes create a new plan.

Use composition databases, package/update manifests, and WIM metadata to identify setup, OS editions, language, recovery, apps/frameworks/licenses, drivers, and servicing roles. Do not assume a fixed ESD index or trust filenames as applicability evidence.

Cover canonical ESD/CAB sets, reference/express/differential layouts, and applicable PSF/CIX/update forms. Encrypted sources require valid decryption information and correct integrity checks. Never pass encrypted or partially expanded payloads to image creation as if they were complete.

Downloads use bounded concurrency, streaming checksums, partial files, range requests where valid, retries, and expired-link refresh. Restart an affected file when range/validator behavior is incompatible. Verify source digest and size; compute SHA-256 for internal cache identity even if upstream provides an older digest. Cache reuse requires established identity and integrity.

Validate API filenames and archive destinations; reject traversal and unexpected absolute paths. All materialization remains inside job/cache roots.

## Managed helpers and Windows integration

| Responsibility | Planned mechanism |
| --- | --- |
| Networking, metadata, planning, orchestration | Go |
| WIM/ESD inspection, reference resolution, export/split/compression | Compatible wimlib-imagex helper |
| Offline servicing, features, drivers, edition operations, apps | Compatible DISM executable/API provider |
| CAB/archive expansion | Windows facilities and a pinned extraction helper where necessary |
| Differential/PSF reconstruction | Narrow native helper/API adapter, orchestrated by Go |
| Offline registry/BCD | Windows APIs or individual tools targeting explicit offline stores |
| UDF/El Torito mastering | Compatible Oscdimg provider from an approved Microsoft distribution channel |

Maintain a versioned tool manifest with publisher/source, download location, SHA-256, archive layout, host architecture/minimum OS, target capabilities, companion libraries/drivers, and notices. A job pins its tool identities. Do not fetch an arbitrary moving latest binary during a build.

Use an adequate existing Windows DISM after checking compatibility; automatically provision other providers when necessary. Do not assume one newest ADK handles every historical image/host. All acquisition, extraction, prerequisite setup, and validation is application-managed. A full external converter is not a fallback.

Release requires a concrete official acquisition/redistribution route and functioning dependency chain for each helper/host combination, particularly DISM and ISO tooling. If appropriate redistribution is unavailable, use a documented application-managed vendor acquisition path. Any necessary imaging-component setup is performed and reported by the app; a manual ADK installation cannot replace this requirement.

Tool selection is an implementation responsibility under the full cross-architecture requirement. Validate provider capabilities across all required targets for each host executable. A tool's current restrictions do not authorize a permanent host-based target restriction in the product.

Invoke absolute helper paths with argument arrays, without cmd/Bash or user-configurable command strings. Capture output and hide supporting console windows. Track owned children with Windows process/job facilities.

Use a local NTFS scratch location for Windows filesystem semantics. Treat remote/removable final output separately: construct and validate locally, then publish with copy verification. Handle spaces and Unicode in user paths, using an app-owned compatible staging alias where a specific helper requires it.

Elevate the same executable through normal Windows facilities only when needed. Communicate through an access-restricted local pipe, revalidate the frozen job in the worker, and expose no generic elevated command runner. Privileged work targets app-owned jobs, explicit offline images/stores, and necessary tool prerequisites.

## Go-owned conversion pipeline

### Resolve and preflight

Resolve source/app/edition dependencies and effective settings. Validate host/tool/source compatibility, disk space, local filesystem, path handling, permissions, and job locks. Estimate compressed inputs, materialized images, servicing scratch, and publication space separately.

### Acquire and normalize

Download/verify sources and helpers, expand archives, reconstruct differential content, and inventory actual payloads. Preserve verified source downloads as immutable inputs. Normalize metadata into engine-owned structures while retaining originals for diagnosis.

### Assemble base images

Discover metadata/setup/OS/recovery roles semantically, inspect WIM metadata, resolve references, and assemble appropriate base edition images. Preserve Windows ACLs, reparse points, streams, hard links, and registry contents through correct imaging operations, not ZIP-like copying.

Construct a matching setup/media tree and source-generation-specific boot-WIM/WinRE images, including matching setup resources and offline configuration. Do not substitute boot files from an unrelated build.

### Service and specialize

Plan valid dependency order for servicing stacks, cumulative/checkpoint updates, enablement packages, language resources, features, drivers, recovery, and apps. Keep generation-specific rules in versioned capability modules with fixtures and provenance.

Derive editions only through valid package/edition relationships. Use shared-base servicing only where valid for the generation and preserve per-edition feature/app differences. Resolve apps, frameworks, architecture compatibility, and licenses. Perform cleanup/reset-base and boot/recovery updates at the configured supported points. Verify resulting image inventories against the requested/effective plan.

### Prepare output and master media

Order final indices; export WIM, ESD, or SWM; construct matching boot resources and offline BCD configuration. Use target-appropriate BIOS/UEFI boot entries, including ARM64's appropriate UEFI path. Master UDF-capable installation media with correct large-file handling, El Torito catalog, and file ordering. Validate image-only/directory output without claiming an ISO was made.

### Verify and publish

Check setup/boot files, target language/architecture, edition indices/properties, servicing/app results, image readability/integrity, and ISO filesystem/boot structure. Tool exit status alone is insufficient. Write a temporary artifact, calculate SHA-256, and publish only after verification. Never silently overwrite an unrelated output.

The report records source identity, requested/effective settings, tools, checks, warnings, and output digest. Reproducible input identity and provenance are required; byte-identical results across mutable upstream metadata or different tools are not promised.

## Cancellation and recovery

Persist intent before each mutating operation; commit checkpoints only after validating their outputs. Checkpoint identity includes input digests, effective config, relevant rules, tools, and predecessor outputs. Work in stage-owned directories and do not mutate committed checkpoints in place.

Job states include draft, resolving, ready, downloading, paused, preparing, assembling, servicing, mastering, validating, completed, cancelling, cancelled, failed, and recovery-required. Page navigation does not change job state.

Settings/tool/rule changes invalidate affected stages and dependants while preserving compatible verified downloads. On cancellation, stop scheduling work, request safe termination of active operations, and clean owned mounts when possible. Do not indiscriminately kill DISM, clear all system mounts, or remove in-use workspaces.

After a crash/forced stop, inspect the actual filesystem and owned mounts, validate checkpoints, and offer Resume or Discard Job. An incomplete mutating stage restarts cleanly. Discard affects only that app-owned job; never delete driver sources, unrelated downloads, or unrelated mounts. Retain useful diagnostics, with credentials/signed links redacted.

## Verification and release evidence

- API contract fixtures: envelopes/errors, array/object build collections, revisions, language/edition availability, app sets, removed links, rate limits, and malformed responses. Extend live validation beyond the successful catalog request to language, edition, app, and payload resolution.
- Meaningful unit/integration checks for config validation, metadata layouts, dependency/edition planning, archive paths, payload integrity, interruption, and checkpoint invalidation.
- Real helper adapters tested against suitable fixtures. Simulated helper success is not image-conversion evidence.
- Recovery checks covering interrupted downloads, worker loss during mutation, mount cleanup/restart, and source retention.
- Cross-build all three Windows host executables and complete actual functionality on the available native Windows host under the host proof policy. Cross-compilation alone is not runtime support; other physical host runs are optional corroboration.
- Verify cross-architecture creation on the available host for every required x86/x64/ARM64 ISO-capable target and other required upstream target formats/source families. Cover all nine logical common pairs through strict actual witness evidence and explicitly reported portability acceptance.
- Real images across distinct source/servicing families: legacy/current client, Server/specialized ISO-capable sets, x86/x64/ARM64, multiple languages, base/derived multi-edition media, apps, updates, drivers, and supported WIM/ESD/SWM output.
- Boot representative images in matching BIOS/UEFI VMs/hardware; check Setup edition discovery, image application, and representative installed app/feature results.
- Maintain a compatibility ledger of host, target, source layout, tools, settings, and actual validation. Catalog discoverability and build-validation evidence remain distinct.
- Test clean-machine provisioning without existing ADK/helpers; non-admin startup; legacy console operation; small terminal layout; spaces/Unicode paths; low space; and supported output locations.

The implementation plan may order vertical slices and source families, but a partial milestone is not the final all-build deliverable. Compatibility gaps and missing validation remain visible until addressed.

## Left to the builder

The builder may choose exact package/files, dependency patches, TOML library, journal serialization, cache index, helper progress parsing, concurrency limits, and schema field organization while preserving documented behavior/versioning.

Resolve source algorithms, helper acquisition/dependencies, and generation rules using primary documentation and focused feasibility work. Those choices may not replace the Go engine with an existing converter or require manual setup. Bring a concrete essential incompatibility back to the user instead of silently narrowing scope.

## Builder review

A fresh Windows/Go/UUP builder reviewer read the draft and raised one consequential question: must every host build every target, or is a restricted host/target matrix acceptable? The user answered “Allow every build target.” This document incorporates full cross-architecture coverage as a requirement. The review raised no other consequential product questions.

After user approval of this document, invoke the writing-plans skill before implementation. The directory currently has no Git repository, so the design is saved as a file and has not been committed.

The user subsequently requested a multi-agent implementation plan with `gpt-6.1-sol` and `xhigh` reasoning effort. Preserve those settings for planning specialists, implementation workers, and reviewers. Plan creation is authorized; implementation awaits review of the resulting plan.
