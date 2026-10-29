# Scope amendment — 2026-10-29

The user removed recovery, the planned R17 Review/Start/progress/recovery and terminal-behavior work, and testing whether the generated image boots. They then specified an ISO file as the deliverable, without a separate installation-media creation workflow, and moved TUI work ahead because they want to test it now.

This decision supersedes conflicting requirements in the accepted design, shared contracts, host-proof policy, older plans and remaining-work plan. It does not mark omitted work implemented or tested.

## Removed requirements

- Crash/restart job recovery, startup job discovery, recovery/discard choices, interrupted-job replay and recovery acceptance suites. Existing downloader pause/resume and cache behavior may be reused without adding job-restart recovery.
- New WinRE/recovery-image construction, servicing, customization and recovery-target driver work. Preserve source material where ordinary assembly requires it; do not add dedicated recovery features. Existing schema-1 configuration remains readable; future planning reports explicitly requested omitted features as unsupported rather than pretending to apply them.
- All of original task R17: dedicated Review/Start/progress/recovery screens, subscriptions/display work, additional terminal-mode behavior and console-acceptance campaigns. Keep existing completed browsing/configuration behavior. R15 still supplies the minimum existing application entry needed to execute a validated conversion; this is not a replacement UI project.
- Bootability acceptance testing, including BIOS/UEFI VM or hardware boots, installed-OS boot tests and boot/Setup execution campaigns. Missing boot evidence does not block this reduced scope.
- USB/DVD/physical-disk writing or burning, installation/boot execution workflows and standalone WIM/ESD/SWM/directory deliverables. The deliverable is a Windows ISO file; its normal source-matching Setup/image files remain inside the ISO. WIM/ESD/SWM work may be used internally to construct its contents.

## Retained work

Conversion, source-family handling, image customization outside recovery, internal Windows image generation and ISO-file packaging remain in scope. Include the source-matching files needed for a normal Windows ISO without adding a separate installer/media-creation project. Verify actual produced contents, filesystem/security metadata, requested image state, byte integrity and publication. Including source boot files does not assert that the ISO was boot-tested.

Keep native provider/source/algorithm evidence for the remaining operations, ordinary tests, current-host functional checks, clean-machine provider provisioning and Windows 386/amd64/arm64 builds. No new physical-host matrix is required.

Keep operation ownership, authorization, intent records needed by current operations, safe cancellation and cleanup limited to resources created by the active operation. Releasing an active owned mount is basic resource cleanup, not a recovery feature. Unknown state preserves resources and reports an error. Do not broaden this into restart/replay/discovery facilities.

Historical implementations, test results, failures and validators remain truthful. Old strict proof records must not be relabeled passing: define reduced operation-specific requirements explicitly before later capability/release acceptance. Reports identify bootability and recovery as excluded, not passed.

## Immediate execution effect

R3a2b's existing review findings about runner/request custody and active mount-directory custody still apply to eventual execution. Retain in-flight inert fixes in place; stop native-control development/preparation while TUI testing is the priority. When resumed, finish only necessary custody/run integration, remove recovery modes from proposals and retain shared internal code solely for active cleanup. No native image operation or elevation is authorized by this scope amendment.

Prioritize completed R1/R2 preview delivery and R16a app-editor/view work before backend/provider tasks. R16b later binds actual R6/R13 metadata; missing backend data must appear unavailable, never be fabricated for the preview. This does not reinstate the removed R17 project. The native TUI preview was launched for the user in Windows Terminal on 2026-10-29.

The user tested that preview, said it looked good, and identified a mismatch with the earlier Charm style. Their supplied purple Workspace screenshot confirms the existing accepted visual direction. R16s visual fidelity now precedes R16a: apply that layout/palette/control treatment to the working Charm TUI and deliver a new preview. Preserve real data and behaviors; the reference's illustrative data/progress are not product features.

Task IDs stay stable: R17 is recorded as removed, not completed. R11/R13/R14/R15/R18 and their dependencies are revised in the remaining-work plan. Existing schema-1 settings remain readable; excluded output/recovery choices are not silently claimed as supported. Completed R1/R2 and other reviewed checkpoints are not re-run or rewritten.
