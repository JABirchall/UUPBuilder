# DISM offline provider and cleanup failure

Captured evidence from the user's failed build (historical go-run temporary
directory disappeared after the runner exited; no preserved resources were reused):

- Managed DISM 10.0.28000.3481 received valid `/Image`, `/Add-Package`,
  `/PackagePath` syntax. Image servicing stack was 10.0.26100.1.
- `dism.log` at 16:32:24 loaded `wcp.dll` successfully from the image's servicing
  stack; CSI reported a 284-character path. The mount prefix was 166 characters.
- At 16:32:25, `CDISMPackageManager::CreateCbsSession` failed with
  `0x8007007a` (insufficient buffer), followed by CBS provider initialization
  failure, then "No providers were found that support the command(add-package)".
- Discard unmount ran 16:32:26–16:36:21 (235 seconds), exceeding the cleanup's
  60-second context while `CancelWait` correctly waited for natural completion.
  Exit zero was incorrectly reported as a cleanup failure due solely to the
  elapsed context deadline.

The path-length cause is supported by that evidence; elevated servicing A/B
could not be replayed because this session is not elevated, and the temporary
runtime/image subsequently disappeared. No claim of successful Add-Package or
completed ISO validation is made.

Changes:

1. Resolve claimed mount directories through native 8.3 lookup, verify the alias
   against the original owned directory identity, and retain original ownership
   validation. Use that spelling consistently for Mount, Unmount and `/Image`.
   Data stays in the selected workspace; no links or system policy changes.
   Reject a resulting ordinary mount alias of 260 or more UTF-16 units before
   mounting, including unchanged/partially shortened native results. Real native
   boundary fixtures with irreducible short components accepted 259 and rejected
   260/300 units; the two unsafe cases were observed red before this review fix.
2. Inspect only bounded direct WinSxS entries and reject actual CBS core paths
   still exceeding ordinary Win32 limits, with a shorter-workspace remedy.
3. Record whether the process exit code was actually observed. Only discard
   unmount may accept an observed natural zero exit when cancellation is the
   sole error. Commit, nonzero exits, unknown exits, overflow and other native
   observation errors remain failures. Global `CancelWait` behavior is unchanged.

Regression tests were observed red before implementation for long arguments,
unsafe CBS-path launch, and false failure after a delayed natural zero exit.
Native short-name resolution shortened a fresh owned fixture from 234 to 81
characters while preserving the same directory identity. Full servicing remains
an elevated native validation requirement.

Focused verification: `go test ./internal/engine/service ./internal/platform/windows
-count=1` passed (`service` 10.776s; `windows` 11.189s). Additional assertions
retain unknown-exit, nonzero-exit and joined observation errors, and distinguish
real completed process exits from a process never launched. The existing global
CancelWait cancellation regression remains unchanged and passed in this run.
After the mount-alias boundary review fix, the same focused command passed again
(`service` 9.967s; `windows` 11.627s).
