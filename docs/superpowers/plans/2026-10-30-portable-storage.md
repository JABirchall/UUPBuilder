# Portable storage implementation and verification

User-authorized scope: use `UUP` beside the application executable for the
default config and automatic build data. Keep explicit config/storage overrides,
read-only startup and Review, owned-workspace cleanup, and local NTFS constraints.
Do not migrate or remove existing AppData contents.

Implementation:

1. Add a shared read-only executable-relative directory resolver in config.
2. Compose the planner with those defaults and propagate location errors.
3. Initialize the automatic parent only during confirmed preparation. Place
   selected native scratch under the resolved workspace alongside transfers.
4. Update configuration contracts and ignore generated root `UUP` data.

Regression tests are written before implementation. They exercise working
directory/AppData independence, first-run browsing without writes, tool Review
without writes, actual portable workspace initialization, explicit workspace
and cache selection, native scratch containment, and a blocked portable directory
with no fallback. Tests needing sibling data use a disposable copied executable,
so a persistent test executable's real config/data are never modified.

Red verification: new portable tests failed against the previous AppData/Temp
behavior for all four storage cases and the default config path.

Green verification: `go test ./internal/config ./internal/app -count=1` passed
(`config` 7.027s; `app` 43.190s). The cancellation/preservation fixture now
identifies its transfer directory by its actual workspace owner marker, since
native scratch shares the workspace parent. Its focused rerun passed (0.277s).
Root coordinates the full tracked-package suite and Windows architecture builds;
bare `go test ./...` has an existing access-denied output-tree traversal limitation.
