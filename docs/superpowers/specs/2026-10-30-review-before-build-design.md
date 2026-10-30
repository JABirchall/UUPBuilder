# Review before build

The Build ISO action checks required tool availability and opens Review without
network requests, downloads, source inspection, workspace creation or native tool
execution. Review shows the exact selected source, edition/app/conversion/output
requests and tools that will be acquired when Start build is pressed. It reviews
requested settings; source applicability is established during the confirmed run.

Start build freezes that reviewed draft, opens Progress, then performs existing
source resolution, managed tool acquisition, inspection, planning and execution.
Downloads and native helper output share a thread-safe event stream displayed in
Progress. Existing integrity checks remain inside execution. Back/cancel in Review
starts no work; edits invalidate Review. Active cancellation waits for cleanup.

## Approach

Keep the existing Prepare/Execute backend boundary for headless callers. Add a
read-only tool-check interface and event-aware preparation/execution methods for
the interactive workflow. Reusing a fully resolved ReadyPlan for Review was
rejected because obtaining it requires downloading and inspecting the source.
Removing integrity checks was rejected because they are needed when building.

This implements the user's explicit Review/Progress request; it does not expand
conversion source support, reinstate recovery or authorize a real ISO build.
