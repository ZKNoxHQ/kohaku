# Architecture decisions, Android host

Continues the numbering of `crates/railgun-wallet/DECISIONS.md`. ADR-024, which splits the API
dispatch out of axum, belongs to that crate and is in `ADR-024-append-to-wallet-DECISIONS.md`.

## ADR-025: no socket on Android, Tauri IPC instead

The daemon's security rests on binding `127.0.0.1` and refusing foreign `Origin`/`Host`
(ADR-001). Neither holds on Android: any installed application can connect to a loopback port
belonging to another, and a native caller sets whatever headers it likes. The header checks stop
a web page, not an app.

So the Android host opens no port. `invoke("api", { path, body })` crosses the WebView bridge,
which is scoped to this application, and lands on `ipc::dispatch`. The paths and bodies are the
ones the daemon serves, so the front is shared rather than forked, and `crates/railgun-wallet`
keeps `axum` behind the `http` feature, off on mobile.

Remaining exposure: the WebView itself. It loads no remote page and its CSP allows only the Waku
fleet over wss, as on desktop.

## ADR-026: the phrase is sealed by Android Keystore, or it is not stored at all

The desktop wallet keeps keys in daemon memory and asks for the phrase at every unlock. Typing
24 words on a phone is not viable, so storage has to exist, and a file in the app sandbox is not
storage: a rooted device, a cloud backup or an ADB dump all read it.

Target: an AES-GCM key generated inside Android Keystore with
`setUserAuthenticationRequired(true)`, StrongBox where the device has it, sealing the phrase. The
key never enters this process and a biometric prompt gates every unseal. `tauri-plugin-biometric`
only gates the call; the sealing is a small Kotlin plugin, which is the work this ADR schedules.

Until that plugin exists the three commands in `keystore.rs` return an error and the front falls
back on typing the phrase. An intermediate step with a passphrase-derived key was rejected: it
would be the version that ships, and it protects nothing against an attacker who already has the
file and can run the derivation.

## ADR-027: sandboxed data directory, and `ephemeral_senders.jsonl` must survive

`app_data_dir()` replaces `~/.railgun-wallet`. The modes of ADR-007 (0700, 0600) are irrelevant
there and the sandbox does the same work, but two properties must be kept deliberately.

`ephemeral_senders.jsonl` holds the key of every 7702 sender a native unshield funds (ADR-016).
Funds can be stranded on one of them. A file lost with an uninstall, a "clear data", or a device
change is lost money, so it is the one file that has to be in the backup set and in the export
the wallet offers. It cannot go in the Keystore-sealed vault of ADR-026 either: it must be
readable without a biometric prompt while a job is running.

The database keeps the filesystem store of ADR-007 for now, one file per hashed key. Thousands of
small files on a phone is a measurement to make, not a redesign to do before the first run. If
sync time or backup size says so, redb is the replacement, and the `Database` trait makes it a
local change.

## ADR-028: the Waku node stays in the WebView, held up by a foreground service

ADR-015 put js-waku in the wallet tab and accepted that the legacy transport only works while
that tab is open. On Android the same bundle runs in the app's WebView, and the equivalent
condition is the process staying alive: Doze, a screen lock or the user switching apps would
otherwise drop the fleet connection and lose a broadcaster's answer.

`EngineService` is a `dataSync` foreground service started when a job starts and stopped when the
job list goes idle, which is also what the user is entitled to see in a notification while a
proof runs. It is not left running: Android 15 caps `dataSync` at six hours a day, and a wallet
that holds that budget for nothing has none left when it matters.

The activity declares `configChanges` for rotation, because recreating the activity tears down
the WebView and with it the Waku node, its peers and the offers.

A native Waku client was considered and rejected: no maintained Rust light client exists, and
nwaku through its C bindings is a cross-compilation project of its own for a transport that
already works in JavaScript.

## ADR-029: keep the wasmer witness calculator on Android, measure before replacing it

The proving path uses ark-circom, whose witness calculator runs the circom wasm under wasmer.
Wasmer compiles and needs executable pages; Android allows that for an application, iOS does not,
which is why Wasmer 5.0 brought iOS support only through interpreted backends.

For an Android-first version there is therefore nothing to change, and changing it blind would
cost a witness generator port before a single number is known. What has to be measured on a real
device, before deciding: witness time, proving time and peak RSS for the shapes the wallet uses,
on a mid-range phone rather than a flagship.

The replacement, when the measurements or iOS ask for it, is a native witness generator
(circom-witnesscalc, rust-witness) and, if the prover itself is too slow, rapidsnark, which is
already packaged for mobile. Both keep the same inputs and the same proof format, so this is a
substitution behind `Groth16Prover`, not a redesign.

The engine thread's 64 MiB stack (`engine::spawn`) is explicit and stays: on Android the default
pthread stack is far below what the prover recurses through.

## ADR-030: expert controls stay, behind a disclosure

The front exposes the gas margin, the fee ceilings, the trusted signer list and the direct
debug transport. The temptation on a phone is to drop them and ship a send button.

They stay, collapsed. The fee ceilings are what makes broadcasting without a confirmation step
acceptable (ADR-014), and the margin is the knob that stops an operation before it is sent
(ADR-017). Hiding them would remove the safety the design rests on; collapsing them is a layout
decision, made in `mobile.css` with no change to the ids the front drives.

## ADR-031: the APK is built in CI, not on the development machine

The Android toolchain is a JDK, the SDK, the NDK and Gradle, installed for a target that cannot
be judged on the machine that builds it: an x86_64 emulator runs the prover on the laptop's
cores, so it measures nothing that matters (ADR-029). What is actually needed is an APK on a real
phone.

`.github/workflows/android-apk.yml` builds it on a runner that already has the SDK and the NDK,
and uploads the APK as an artifact the phone downloads directly. Nothing is installed locally,
and the build is reproduced by anyone with the repository.

Consequences, all of them accepted:

* The APK is debug-signed. A release APK needs a keystore, which means a secret, which is a
  decision to make when there is something to distribute rather than to test. Gradle generates a
  fresh debug keystore per runner, so the signature changes between runs and the app has to be
  uninstalled before a new build is installed.
* The Rust profile is `dev`, so the workspace optimises dependencies in dev
  (`[profile.dev.package."*"] opt-level = 3`). Without it the measurement of ADR-029 would be off
  by an order of magnitude and would say nothing.
* `gen/android` is generated by the first run and patched by `scripts/patch-android-project.py`.
  Once it is committed the patch becomes a no-op, which is what the script's idempotence is for;
  until then the CI regenerates it every time and the Gradle cache is cold.
