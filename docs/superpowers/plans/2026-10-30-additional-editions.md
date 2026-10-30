# Additional Editions Implementation Plan

> **For agentic workers:** Implement in this checkout using test-driven-development and verification-before-completion.

**Goal:** Allow the eleven requested editions to be selected alongside their downloadable Pro / Pro N bases.

**Architecture:** Extend the Image screen's edition choices; store downloadable editions in `image.editions` and derivatives in `conversion.editions.derived`. Keep the existing source-bound EditionMappings inspection, base downloads, native Set-Edition and output verification authoritative during building.

**Tech Stack:** Go, Bubble Tea, existing source resolver and servicing planner.

**Spec:** User request; `docs/superpowers/specs/2026-10-27-uup-builder-design.md`, Image selection and edition servicing sections.

## Constraints and review focus

- Pro enables ProfessionalWorkstation, ProfessionalEducation, Education, Enterprise, ServerRdsh, IoTEnterprise and IoTEnterpriseK.
- Pro N enables ProfessionalWorkstationN, ProfessionalEducationN, EducationN and EnterpriseN.
- Match edition identifiers without case sensitivity and retain catalog spellings for downloadable sources.
- Do not duplicate directly advertised editions or submit derived identifiers to the download catalog.
- Retain unavailable requests visibly and block continuation; support removing them.
- Include derivatives in summaries and Review; preserve them through configuration saving.
- Require source-inspected edition mappings at build time; selection alone does not establish applicability.
- Preserve other configured derivations as pending source-validation requests; these offers are not an allowlist.

## Task 1: Edition selection

**Files:** Add `internal/tui/editions.go`, `internal/tui/editions_test.go`; modify `image.go`, readiness consumers, `layout.go`, `build_views.go`, and `docs/configuration.md`.

**Interfaces:** Keep catalog discovery unchanged; expose merged choices and model readiness, with selected targets persisted through existing `EditionSettings.Derived`.

- [x] Write workflow tests for all eleven choices, Pro/N boundaries, unavailable bases, case-insensitive removal, directly advertised editions, keyboard toggling, persistence and Review.
- [x] Run the tests and observe the missing-selection failure.
- [x] Implement merged choices, correct storage, availability checks and summaries.
- [x] Run focused tests and inspect the rendered edition screen.
- [x] Document the selection behavior.

## Task 2: Verification

- [x] Run source-package tests, application vet checks and build the application.
- [x] Review the diff for download/servicing separation and stale selection handling.
- [x] Report results and any limits of verification.

## Verification results

- `go test ./cmd/... ./internal/... ./tests/...`: passed for all source packages.
- `go vet ./cmd/... ./internal/...`: passed.
- `go build -o uupbuilder.exe ./cmd/uupbuilder`: passed; portable executable rebuilt.
- Independent code review: no remaining actionable findings. Added regression coverage for configured derivations outside the offers and saved unavailable download IDs masked by derived offers.
- Repository-wide `go test ./...` cannot enumerate an existing protected generated image under `output`; source directories were tested explicitly instead.
- Broader vet includes six pre-existing unkeyed `ISOExpectedFile` literal warnings in `tests/probes/iso_additional_windows.go`, `iso_windows.go` and `iso_windows_test.go`.
- No native ISO conversion was requested or executed for this selection change.
