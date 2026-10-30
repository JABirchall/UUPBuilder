# Review before build implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement inline.

**Goal:** Open Review after inexpensive tool checks, and run all downloads and native work only after Start, with live Progress logs.

**Architecture:** Separate the interactive tool check from existing deep Prepare.
Freeze the reviewed BuildDraft and stream model.Event values from preparation and
execution into a bounded Progress history. Retain immutable ReadyPlan validation.

**Tech Stack:** Go, Bubble Tea, existing managed tool and worker providers.

**Spec:** ../specs/2026-10-30-review-before-build-design.md

## Global constraints

- No network, source inspection, workspace creation or executable launches in the interactive tool check.
- Preserve exact requested selection/settings; validate the deep plan after Start.
- Keep cancellation, ownership and source/artifact integrity checks during execution.
- No real conversion or recovery work is required by this implementation.

## Review focus

- A source server must see zero requests while opening/cancelling Review.
- Draft edits and late messages must not authorize a stale build.
- Download and native events must appear while work is active, including errors.
- Cancellation and closing the UI must unblock event producers and await backend cleanup.
- Missing inbox tools must block; managed downloads must be shown as pending acquisition.

### Task 1: Review gate and progress state

**Files:** internal/tui/build_action.go, internal/tui/build_views.go,
internal/tui/model.go, internal/tui/layout.go, internal/tui/navigation.go,
internal/tui/build_action_test.go.

**Interfaces:** BuildToolChecker.CheckTools(context.Context, BuildDraft) ([]string, error);
EventBuildService.PrepareWithEvents(context.Context, BuildDraft, model.Emit) (planner.ReadyPlan, error)
and ExecuteWithEvents(context.Context, planner.ReadyPlan, model.Emit) (BuildResult, error).

- [x] Write and run failing tests for Review without Prepare/Execute, explicit Start, edited/cancelled drafts, and live sanitized/scrollable logs.
- [x] Implement the review gate, reviewed snapshot validation, event delivery, Progress rendering and cancellation.
- [x] Run focused TUI tests and review compact layout/control behavior.

### Task 2: Cheap tool checks and production event routing

**Files:** internal/app/build_tools_windows.go, internal/app/build_windows.go,
internal/app/selected_windows.go, internal/source/media_native_windows.go,
internal/jobs/controller.go and focused tests; docs/configuration.md.

- [x] Write and run failing tests proving tool checks touch no source server/workspaces and events reach subscribers.
- [x] Check inbox executable/library presence and managed recipe availability without launching tools.
- [x] Route preparation/download/native/worker stage events to Progress after confirmation.
- [x] Run the complete tracked package test suite, Windows architecture compile checks, and build a fresh executable.
- [x] Review the complete diff and record verification results.

## Verification

- Initial regression failed because Build ISO called Prepare once and CheckTools
  zero times; the corrected gate passes with no preparation or execution.
- Production CheckTools test confirms zero source HTTP requests, no workspace or
  output files, no selected runtime acquisition, and cancellation handling.
- Actual fixture downloads produce Progress events after confirmation. TUI tests
  cover Start, immutable plan identity, stale/cancelled review, active cancellation,
  bounded sanitized logs, scrolling and visible cleanup failures.
- `go test ./cmd/... ./internal/... ./tests/...`: passed for all tracked packages.
  The broader `go test ./...` glob cannot traverse a pre-existing access-denied
  source-image artifact directory under output; no historical artifacts were changed.
- `go build ./cmd/uupbuilder` with Windows GOARCH amd64, 386 and arm64: passed.
  Fresh amd64 executable: `output/uupbuilder-review.exe`.
- Luna reviewed the complete implementation and found no P1/P2 issues. Existing
  UUP source reconstruction limitations were outside this workflow correction.
- User preference: use Luna for reviews. Native headless deep planning remains
  unchanged; interactive source-dependent checks run after Start.
