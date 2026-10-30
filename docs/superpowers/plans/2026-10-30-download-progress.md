# Per-file download progress

Authorized scope: download events and the TUI Progress screen. Keep signed URLs out of events and display the frozen logical destination instead. Preserve existing generic byte events.

Implementation sequence:
1. Add failing real HTTP/event and TUI rendering regressions.
2. Add optional download identity/state to events; emit bounded-frequency byte updates and explicit verified completion, failure and cancellation.
3. Maintain bounded per-file state in the TUI, redraw bars with percentages and byte sizes, prioritize active files, and reset state for a new build.
4. Run focused regressions and the available package suite; report verification evidence here.

Implemented optional `Event.Download` metadata with a stable opaque identity, the frozen logical destination, and explicit lifecycle state. Transfers retain identity through retries and resume; byte updates run at most once per 100 ms after the first sample, with initial, retry, verification and terminal events preserved. Completion is emitted only after verified publication or verified cache reuse. Cancellation/failure preserve the latest byte count even when intermediate samples were throttled.

Progress keeps at most 128 file entries, updates them in place without filling the log, prioritizes active transfers over completed history, and clips rows to the available terminal cells. Bars show percentage and binary byte sizes; unknown and unverified zero totals remain indeterminate. Long filenames yield space to lifecycle status. New builds reset file state; terminal build results settle unfinished rows without inventing verified completion.

Verification (2026-10-30):
- Observed intended failing regressions for missing per-file event metadata/lifecycle, unthrottled events, dropped counters, absent bars, long-name status clipping, history displacing active transfers, and idle row sizing.
- `go test ./internal/tui ./internal/download ./internal/model -count=1` passed (TUI 2.629s, download 11.826s, model 0.018s).
- `git diff --check -- internal/model/events.go internal/download internal/tui` passed; Git printed only the repository's LF/CRLF conversion notices.
- Updated the existing pause/Resume serialization test to wait for a nonzero persisted-byte event. Initial lifecycle events now precede network IO; the original unconditional first-event gate no longer established an active request. Both pause regressions pass.
- Root owns the final combined package suite, platform builds and review. Historical output artifacts can make `go test ./...` fail during directory traversal; use `go test ./cmd/... ./internal/... ./tests/...` without changing those artifacts.

Bounds: extreme concurrency beyond 128 file entries evicts the oldest active row after all retained completed history has yielded. Short terminals show the files that fit plus a hidden-count summary; very small terminals cannot display all details. Generic byte emitters remain supported but need explicit download lifecycle metadata to claim verified completion. Headless output is unchanged.
