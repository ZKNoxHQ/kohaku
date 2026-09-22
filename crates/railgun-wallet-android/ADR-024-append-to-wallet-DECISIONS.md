Append to `crates/railgun-wallet/DECISIONS.md`, after ADR-023.

---

## ADR-024: one dispatch, two transports

The front's API was written directly as axum handlers. The Android host has no socket (ADR-025),
so it needs the same calls without HTTP.

`src/ipc.rs` now holds the dispatch: `dispatch(&Ctx, path, body) -> Result<Value, ApiError>`,
with the paths and JSON bodies unchanged, and `ipc::boot`, which installs the log subscriber and
spawns the engine thread. `src/api.rs` keeps the routes, the `Origin`/`Host` middleware, the CSP
and the two static assets, and each handler is a call into `dispatch`. The crate gains a `[lib]`
and an `http` feature, on by default, which carries axum and the daemon binary.

The alternative was a second thin API in the mobile crate. Rejected: the two would drift, and the
front is shared between the two hosts, so a difference would show up as a bug on one of them
only. `ApiError` carries the HTTP status on purpose, so the mobile shim can rebuild the response
the front already knows how to read.
