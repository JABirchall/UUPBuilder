# Source metadata planning implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the user's selected source without update-ID, language, build-number, payload-digest or image-index allowlists.

**Architecture:** Extend the existing Go engine and its individual managed tools. Discover image roles and edition mappings from verified source content, inspect actual update packages, and bind resulting decisions to the frozen source manifest. Tool binary integrity pins remain; source versions do not select a hardcoded product fixture.

**Tech stack:** Go, existing WIM/CAB/Appx inspectors, managed wimlib and DISM, current checkpoint pipeline.

**Spec:** ../specs/2026-10-27-uup-builder-design.md (accepted all-build compatibility), amended by the user's 2026-10-30 instruction that the builder must not be pinned to any version.

## Global constraints

- Keep the exact selected source, language, architecture, editions, apps and update policy.
- Do not substitute another build or invoke an upstream converter.
- Preserve source integrity, immutable plans, ownership, cancellation and result verification.
- Check actual provider/format capabilities; do not claim unsupported operations succeeded.
- Recovery and boot execution testing remain excluded.

## Review focus

- Same-format sources with different build IDs, languages, baseline versions and image indices must take the same path.
- Missing or ambiguous Setup/OS content must still produce a concrete blocker.
- Update applicability must come from package metadata and dependencies, never a KB allowlist.
- Invalid source identities, changed payloads and unavailable native providers must still fail.
- Requested edition/app policies must survive planning and must not be silently discarded.

### Task 1: Dynamic source inventory

**Files:** internal/source/media_*.go and focused tests; reuse selected-source app helpers.

**Interfaces:** Export DetectMedia(inv metadata.Inventory, selection model.Selection) (MediaLayout, error), where MediaLayout contains Payload model.PayloadIdentity and OSIndex, MediaIndex, PEIndex int. Export ResolveMedia using the existing catalogue/app/fetcher inputs and an InventoryCompleter callback. Export NativeInspector bound to a managed WIMLib path and owned workspace, with Complete(ctx, *inventory, materialized) error. No fixed product data in the new path.

- [ ] Write/run failing tests for alternate source identity, language and image indices; ambiguous/missing media; metadata-bound edition/update observations.
- [ ] Resolve exact selected payload/app closure and inspect WIM XML and actual image contents. Read EditionMappings.xml and update CBS metadata from verified source bytes.
- [ ] Verify focused source tests and report remaining actual format/provider limits.

### Task 2: Generation and managed-tool decisions

**Files:** internal/engine/rules/registry.go, internal/planner/servicing.go, internal/tools/selected_windows.go, internal/engine/service/edge_windows.go and tests.

- [ ] Write/run regression tests showing that changing build/source/language does not fail a version allowlist.
- [ ] Derive servicing capabilities from inspected Windows versions and provider functionality; retain valid policy constraints.
- [ ] Keep exact tool distribution integrity pins, remove fixed source allowlists, derive source Edge identities and provider files from verified source content.
- [ ] Verify rule/planner/tool/service tests and report capability limits precisely.

### Task 3: Assembly from source metadata

**Files:** internal/worker/assembly_windows.go and tests.

- [ ] Write/run regression tests for changed indices and different reference counts.
- [ ] Inspect verified materialized WIM inputs, call source.DetectMedia, derive reference sets from the exact manifest, and replace fixed source IDs/digests/counts/indices with inspected choices.
- [ ] Preserve existing byte verification, source-matching Setup content, checkpoint and ownership rules.
- [ ] Verify focused worker tests.

### Task 4: Application integration and delivery

**Files:** internal/app/build_windows.go, internal/app/selected_windows.go, docs/configuration.md and integration tests.

- [ ] Route build requests through generic metadata-based preparation, retaining injected test ports where appropriate.
- [ ] Acquire managed inspectors and call source.ResolveMedia with the native completer; remove build/language allowlist routing and fixed reporting metadata.
- [ ] Run focused integration tests, full Go suite and Windows architecture compile checks; independently review the diff.
- [ ] Build a fresh executable, verify the user's exact config reaches the appropriate planning path, and report remaining native/build evidence honestly.
