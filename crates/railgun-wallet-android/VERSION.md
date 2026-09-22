# Changelog

## 0.11.1 (2026-09-22)

APK built in CI, so the Android toolchain is not needed locally (ADR-031).

* `.github/workflows/android-apk.yml`: JDK 17, the runner's SDK and NDK, `aarch64-linux-android`,
  `build-dist.sh`, placeholder icons, `cargo tauri android init` if `gen/android` is absent, then
  `cargo tauri android build --apk --debug --target aarch64`. The APK is an artifact, downloaded
  and installed from the phone. `gen/android` and `icons/` are uploaded too: commit them after
  the first run and the generation step disappears.
* `scripts/patch-android-project.py` merges into the generated project what `android init` cannot
  know: the permissions, the `dataSync` service, `configChanges` and `singleTask` on the activity
  and `EngineService.kt`. Idempotent, verified on a template manifest, output parses as XML.
* Workspace root: dependencies optimised in the `dev` profile. A debug-signed APK is what CI can
  produce without a keystore, and a debug-profile Groth16 prover would measure nothing.

Signature caveat: Gradle generates a fresh debug keystore per runner, so the app has to be
uninstalled before a newer build is installed.

## 0.11.0 (2026-09-22)

First Android host. Skeleton: it has never been compiled, the workspace snapshot it was written
against is partial (`crates/railgun` ships without its `Cargo.toml`, `kohaku-db` and the other
members are absent). Treat every file here as a starting point to `cargo check`, not as a build.

* `railgun-wallet` becomes a library. `src/ipc.rs` holds the whole API dispatch, free of any
  transport, plus `ipc::boot` which installs the log subscriber and spawns the engine thread.
  `src/api.rs` is now an axum wrapper around it, same routes, same JSON, same `Origin`/`Host`
  checks. The daemon behaves exactly as in 0.10.1.
* `crates/railgun-wallet-android`: Tauri v2 host. One `invoke("api", { path, body })` command
  routed to `ipc::dispatch`, no socket. `engine.rs`, `keys.rs`, `db.rs` and `shared.rs` are used
  unchanged.
* `dist/tauri-shim.js` rewrites the front's `fetch("/api/...")` into that command, errors and
  status codes included, so `static/index.html` stays the single source of the UI. `mobile.css`
  is a layout-only overlay: 44 px touch targets, one column, sticky action bar, no renamed id.
* `scripts/build-dist.sh` builds `dist/` from `../railgun-wallet/static` by injecting those two
  files into `<head>`. The js-waku bundle is copied as is and keeps running inside the WebView,
  which is what makes the legacy transport possible on Android.
* Android side: manifest additions (`dataSync` foreground service, camera for QR, biometric) and
  `EngineService.kt`, to merge into `gen/android` after `cargo tauri android init`.
* `keystore.rs` is three commands that return an error. The sealing of the phrase by Android
  Keystore is specified in ADR-026 and deliberately not approximated.
