# railgun-wallet-android

Android host for the wallet core, Tauri v2. The desktop daemon keeps working exactly as before.

**Nothing here has been compiled.** The snapshot this was written against holds four crates and
no `Cargo.toml` for `crates/railgun`, so `cargo check` was impossible. Expect the first pass in
the real worktree to be a round of import and signature fixes, particularly in `ipc.rs`, which
was cut out of `api.rs` by reading it.

## What it does

The front is not forked. `static/index.html` talks to the wallet through one function,
`api(path, body)`, which calls `fetch`. `front/tauri-shim.js` replaces `fetch` for `/api/*` with
`invoke("api", { path, body })` and rebuilds a `Response` with the status the daemon would have
returned, so every error path in the front behaves the same. `front/mobile.css` is layout only.
`scripts/build-dist.sh` assembles `dist/` from `front/` and the desktop `static/` at every build (`dist/` is generated and git-ignored), which is
what keeps the two hosts from drifting.

On the Rust side, `ipc::dispatch` is the API with no transport (ADR-024), `axum` moves behind a
feature, and the Tauri host calls the dispatch directly (ADR-025). `engine.rs`, `keys.rs`,
`db.rs`, `shared.rs` are untouched.

js-waku runs inside the WebView, as it runs in the tab on desktop, so the legacy transport is
possible on Android as soon as the process is kept alive (ADR-028).

## Build without installing anything

`.github/workflows/android-apk.yml` builds the APK on a GitHub runner (ADR-031). Run it from the
Actions tab, or push the branch. It generates `gen/android` and the icons on the first run and
uploads them as an artifact: commit both, and later runs skip that step.

On the phone: download `railgun-wallet-apk` from the run's artifacts, unzip it, open the `.apk`,
allow installation from unknown sources. The signature changes between runs, so uninstall the
previous build before installing a new one.

The APK is debug-signed and built with the `dev` profile, with dependencies optimised
(`[profile.dev.package."*"]` in the workspace root), so proving times are meaningful.

## Build locally, if the toolchain is installed anyway

Toolchain, once:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install tauri-cli --version '^2' --locked
# Android Studio, then SDK + NDK. Export these in ~/.bashrc:
#   export ANDROID_HOME=$HOME/Android/Sdk
#   export NDK_HOME=$ANDROID_HOME/ndk/<version>
```

Then, from the worktree:

```sh
cd ~/Desktop/github/kohaku-railgun-wallet/crates/railgun-wallet-android
sh scripts/build-dist.sh          # every time the front changes: Tauri does not run it for you
cargo tauri android init          # generates gen/android, once
cargo tauri android dev           # device over adb, or an emulator
cargo tauri android build --apk --release
```

`build-dist.sh` is not wired as a `beforeBuildCommand`: Tauri runs those from the parent of the
config's directory, so the relative path breaks. The CI calls it as its own step, and locally it
is one line before the build.

`cargo tauri android init` writes `gen/android`. Merge `android/AndroidManifest.additions.xml`
into `gen/android/app/src/main/AndroidManifest.xml` and copy `android/EngineService.kt` next to
the generated `MainActivity.kt`.

Release builds only: Groth16 proving in debug is unusable on a phone, more so than on a laptop.

## What is left, in the order the risk sits

1. **Compile.** Fix `ipc.rs` against the real `engine.rs` and `shared.rs`, check that the daemon
   still builds and runs unchanged (`cargo run --release -p railgun-wallet`), then the mobile
   crate on the desktop target before touching Android.
2. **Measure the prover on a device.** Witness time, proving time, peak RSS per circuit shape, on
   a mid-range phone. Everything else depends on the answer (ADR-029). Pin the prover to the big
   cores through the rayon pool; a background thread on a little core is several times slower.
3. **Artefacts.** Where the zkeys come from (bundled, or downloaded once with an integrity check),
   how much storage that is, and what happens on a shape whose key is missing when the user hits
   send.
4. **Keystore plugin** (ADR-026). Until it lands, every unlock is 24 words typed on a phone.
5. **Foreground service wiring.** Two Tauri commands, start and stop, driven by the job list, plus
   `POST_NOTIFICATIONS` at first run.
6. **Sync budget.** Time to first balance on mainnet is the number that decides whether this is
   usable. Resume, wifi-only option, and a progress indication that is not the log pane.
7. **QR.** Scan and display of 0zk addresses. 127 characters are not typed, and the plugin is
   already declared in `src/lib.rs`.
8. **Backup and restore** of `ephemeral_senders.jsonl` and, once it exists, of the sealed phrase
   (ADR-027).
9. **Packaging.** 16 KB page size for native libraries on Android 15, signing, reproducible build.

Not in scope here: iOS. It forces a native witness generator (no executable pages) and gives no
way to keep js-waku alive in the background, so the legacy transport would go with it.
