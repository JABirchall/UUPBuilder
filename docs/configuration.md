# Configuration

UUP Builder uses TOML schema version `1`. The default configuration path is
`UUP\config.toml` beside the application executable, regardless of the process
working directory or `LOCALAPPDATA`; the executable also accepts `--config PATH`.
The Charm Workspace connects configuration loading and saving
to its Conversion area. Edit the TOML path there, then activate Load or Save.
Load replaces the current draft; Save checks structural validity, creates the
selected configuration directory if needed, and reports normalization and any
backup path. View TOML (`t`) shows the current draft without writing it. Image
selection and app requests remain part of the same saved document.

The deliverable is an ISO file. Conversion exposes update, edition, .NET,
driver, internal image, download and storage policies for that ISO. WIM, ESD and
SWM are representations inside its contents; standalone image/directory
deliverables and recovery/WinRE work are excluded. Source-matching Setup and
boot files remain part of normal ISO contents; this does not claim boot or
Setup execution testing. Saving a structurally valid draft does not establish
source applicability, helper availability or executable conversion support.

Build preparation uses the selected source's inspected image metadata and
contents. Update IDs, release numbers, languages, image indices and reference
counts do not select a fixed product recipe. Managed helper distributions retain
their integrity pins. The current canonical adapter discovers a media/WinPE/OS
image container and verifies its actual Setup files, edition mappings, app
manifests and servicing packages. Other layouts or unresolved package
applicability report the specific missing adapter or provider; they are not
silently replaced with a different Windows build.

Every document must contain `schema_version = 1`. Omitted settings receive the
defaults below. Explicit `false`, `0`, empty strings and empty arrays remain
explicit; invalid values return diagnostics instead of being reset. Unknown
keys (including case-mismatched names), wrong types, invalid policy values and
unsupported versions are rejected with the filename, full key and one-based
line/column when available. Missing keys have no invented source position.
Version migration is not implemented: another schema version fails without
rewriting the file. New drafts and omitted recovery fields use
`include_winre = false` and `winre_updates = "omit"` for the current ISO scope.
Older minimal schema-1 files that omit these fields receive these current
defaults too. Explicit legacy `true`, `auto` and `include` values remain
readable and survive load, save and request creation unchanged.

`Defaults()` and minimal documents allow an incomplete image selection for
browsing. `Config.Validate()` checks structural syntax; `Config.Request()` also
requires a source ID, target architecture, language and at least one unique
edition. The complete source ID, including its revision, is opaque and retained.
Unknown upstream architectures, edition identifiers, app families and presets
remain available for later applicability checks. The host architecture does not
filter target choices.

The Image screen offers additional editions after selecting their downloadable
base. Pro enables ProfessionalWorkstation, ProfessionalEducation, Education,
Enterprise, ServerRdsh, IoTEnterprise and IoTEnterpriseK. Pro N enables
ProfessionalWorkstationN, ProfessionalEducationN, EducationN and EnterpriseN.
These choices are labelled with their base and saved in
`conversion.editions.derived`; downloadable choices stay in `image.editions`.
Directly advertised editions appear once and use their catalog download.
Removing a base retains selected derivatives as unavailable requests that must
be removed or have their base reselected before continuing. Build preparation
verifies each requested conversion against the selected source's inspected
edition mappings before native Set-Edition runs.
Other manually configured derived identifiers remain requests for source
validation; these eleven selection offers do not restrict that existing path.

This is the default document. The output directory `"."`, app mode `"default"`
and preservation of required temporary edition bases are builder-chosen
defaults. The accepted design's empty output-directory example was illustrative;
a usable directory is required by the shared settings contract.

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
cumulative_update_policy = "auto"
checkpoint_updates = "auto"
enablement_packages = "auto"
cleanup = true
reset_base = "off"
netfx3 = false
include_winre = false
winre_updates = "omit"
update_boot_files = false
boot_wim_engine = "auto"
reference_images = "auto"
cumulative_msu = "auto"
keep_reference_esds = false

[conversion.drivers]
enabled = false
source = ""
targets = []

[conversion.editions]
derived = []
strategy = "auto"
preserve_required_bases = true

[apps]
mode = "default"
preset = ""
stub_policy = "auto"
include = []
edge_policy = "default"

[output]
kind = "iso"
image_format = "wim"
split_size_mib = 3800
directory = "."
filename = "auto"
label = "auto"
edition_order = []

[downloads]
parallel_files = 4
retries = 5

[downloads.proxy]
mode = "system"

[storage]
workspace = "auto"
cache = "auto"
keep_downloads = true
keep_intermediates = false
```

The schema groups reuse the public typed policies from `internal/model`. The
proxy is a table, and Edge policy lives under `apps`; these organize the full
schema beyond the design's abbreviated example.

| Key | Allowed values or meaning |
| --- | --- |
| `catalog.endpoint` | HTTP/HTTPS API base URL; no credentials, query or fragment. The default uses the official HTTPS API. |
| `image.update_id`, `architecture`, `language`, `editions` | One exact source/revision, one target, one language and ordered unique edition identifiers. Empty selections are drafts. |
| `conversion.updates` | `integrate`, `external`, `omit` |
| `conversion.servicing_strategy` | `auto`, `per-edition`, `shared-base` |
| `conversion.cumulative_update_policy`, `checkpoint_updates` | Independently `auto`, `expand`, `preserve` |
| `conversion.enablement_packages` | `auto`, `include`, `omit` |
| `conversion.winre_updates` | Legacy `auto`, `include`, `omit` remain readable; dedicated WinRE servicing is excluded. Current default: `omit`. |
| `conversion.cleanup` | Component-cleanup boolean |
| `conversion.reset_base` | `off`, `auto`, `on` |
| `conversion.netfx3`, `update_boot_files` | .NET 3.5 inclusion and ISO boot-file update booleans |
| `conversion.include_winre` | Legacy recovery policy boolean; dedicated WinRE work is excluded. Current default: `false`. |
| `conversion.boot_wim_engine` | `auto`, `wimlib`, `dism` |
| `conversion.reference_images` | `auto`, `reuse`, `export` |
| `conversion.cumulative_msu` | `auto`, `expand`, `keep` |
| `conversion.keep_reference_esds` | Retain reference ESDs boolean |
| `conversion.drivers.enabled`, `source`, `targets` | Boolean, source directory and unique targets. ISO customization targets are `os`, `winpe`, `shared`; legacy `winre` remains readable with an excluded-scope explanation. Enabled integration structurally requires a source and at least one target. |
| `conversion.editions.derived`, `strategy`, `preserve_required_bases` | Unique requested derived editions; `auto`/`per-edition`/`shared-base` servicing; retain necessary bases temporarily even when excluded from final output. |
| `apps.mode` | `default`, `custom`, `none` |
| `apps.preset`, `include` | Optional preset and unique stable package-family identities, not translated display names. |
| `apps.stub_policy` | `auto`, `stub`, `full` |
| `apps.edge_policy` | `default`, `include`, `exclude` |
| `output.kind` | Current deliverable: `iso`. Legacy `image` and `directory` remain readable, with an excluded-scope explanation. The TUI offers only `iso`; activating a loaded legacy kind explicitly changes it to `iso`. |
| `output.image_format` | `wim`, `esd`, `swm`: internal image format inside the ISO, not a separate deliverable. |
| `output.split_size_mib` | Nonnegative integer; must be positive for SWM. |
| `output.directory`, `filename`, `label`, `edition_order` | Directory, Windows-safe single filename or `auto`, label or `auto`, unique final edition order. |
| `downloads.parallel_files`, `retries` | Positive parallel file count; nonnegative retry count. |
| `downloads.proxy.mode`, `url` | `system`, `direct`, `explicit`; explicit mode requires an HTTP/HTTPS/SOCKS5 origin without credentials, query or fragment. Omit `url` in other modes. |
| `storage.workspace`, `cache` | Directory or `auto`; automatic locations use the `UUP` directory beside the executable. |
| `storage.keep_downloads`, `keep_intermediates` | Retention booleans. |

The interactive Build ISO action checks inbox tool files and managed tool
availability, then opens Review. It does not resolve source payloads, create
build workspaces, download packages or run DISM. Review shows the requested
source, settings, output and tools to download. Use up/down or page up/down for
details, or `t` for the complete draft. Changing the draft invalidates Review.

Select Start build in Review to open Progress and begin source resolution,
tool acquisition, downloads, inspection and building. Those stages stream their
logs to Progress. Up/down and page up/down scroll the retained log history;
End follows the latest output. Press `c` to cancel and wait for active work and
cleanup. Source applicability and integrity checks still run inside the confirmed
build. Headless `--plan-iso` remains an explicit deep-planning command.

Startup and Review only resolve the portable location; they never create it.
Start build (or an explicit headless preparation command) creates a missing
`UUP` directory when automatic storage is requested. The build's private cache,
download workspaces and native scratch live beneath that directory. An explicit
workspace override also controls native scratch; a cache override controls the
download cache. Existing local NTFS requirements still apply to these workspaces.
An unavailable or unwritable portable location returns an error with its path;
there is no automatic fallback to AppData or the working directory. Explicit
Save creates its chosen configuration directory as described above. Existing
AppData files are never migrated or deleted automatically.

`auto` and all explicit source-dependent choices survive decoding and request
creation. For example, an explicit WinRE-update request survives when WinRE is
disabled, and custom app families survive in `none` mode. The later engine
resolver must report excluded output/recovery requests as unsupported and must
either support other requests or report a concrete applicability failure before
mutation. The Conversion area labels excluded recovery controls and WinRE driver
targets explicitly, and retains their requested values. A scope explanation
takes precedence over any stale applicability display. Structural validation
does not claim support for a particular source, host or helper. Loading a saved
image selection also requires its exact catalogue record, language and editions
to be checked again; app applicability remains unchecked until semantic
validation succeeds.

Relative driver, output, workspace and cache directories resolve against the
configuration file's directory, independent of the process working directory.
With the default config, the default output directory `.` therefore means the
portable `UUP` directory. With `--config`, relative output and explicit storage
paths still follow that selected config; automatic storage remains beside the
executable.
Parent-directory paths such as `../output` are valid user-selected directories.
Storage `auto`, an empty disabled driver source, output filename and label remain
policy values. Windows device names, alternate streams, control characters,
drive-relative/root-relative paths and device namespaces are rejected. Normal
absolute and UNC paths are accepted. Filesystem capability, containment and
reparse-point checks remain a later privileged-I/O boundary.

`Decode(data, filename)` leaves relative paths editable. `Load(path)` reads,
decodes and resolves paths without writing anything; a missing file returns
`os.ErrNotExist` and a malformed file remains byte-for-byte unchanged.
`ResolvePaths(cfg, configPath)` resolves an in-memory configuration explicitly.
`Request()` returns independent copies of every mutable selection/settings
slice. Configuration, resolved settings and backups must never contain runtime
proxy credentials or signed download URLs.

Saving writes normalized TOML; comments and original formatting are not
preserved in the new document. `Save(path, cfg)` validates first, then writes,
syncs and closes a unique temporary file in the destination directory. Before
replacing an existing file it also writes, syncs and closes an exact backup at
`<filename>.bak-<unique suffix>`, preserving comments and bytes. Existing backups
are never overwritten. Identical canonical bytes are a no-op. The containing
directory must already exist; save does not initialize application directories.
An explicit save can replace a malformed file only after making that backup;
load never silently substitutes or saves defaults.

On Windows, publication uses a single
[`SetFileInformationByHandle(FileRenameInfo)`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)
operation with the architecture-aligned
[`FILE_RENAME_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
buffer. The replacement stays on the same filesystem; no copy/delete fallback
is used. `ReplaceIfExists` is true for an existing configuration and false for
initial creation, so an appearing file cannot be overwritten during initial
creation. The native rename handles namespace publication; synced file contents
do not establish a universal hardware/power-loss durability guarantee for every
filesystem or remote server. A sharing violation or unsupported rename returns
an error with the original and completed backup intact. This avoids
[`ReplaceFileW`'s documented partial-failure states](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew).
Portable development hosts use same-filesystem rename for replacement and an
exclusive hard link for initial creation.

`SaveResult.BackupPath` identifies a completed backup, including when publication
subsequently fails. `SaveResult.Normalized` is true after a successful rewrite
of different existing bytes, and false for new files, no-ops and failed saves.
The TUI uses these fields to explain normalization and show the backup path.
Save is intended for one application writer; atomic publication does not merge
concurrent manual edits or provide a cross-process settings lock.
