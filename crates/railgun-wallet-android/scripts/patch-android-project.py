#!/usr/bin/env python3
"""Merges what `cargo tauri android init` cannot know into the generated project.

Idempotent: safe to run on every CI build, and a no-op once `gen/android` is committed with the
edits already in it.

  * the permissions and the `dataSync` foreground service (ADR-028),
  * `configChanges` and `singleTask` on the activity, so a rotation does not tear down the
    WebView and the js-waku node with it,
  * `EngineService.kt` next to the generated `MainActivity.kt`.
"""

import pathlib
import re
import shutil
import sys

CRATE = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = CRATE / "gen/android/app/src/main/AndroidManifest.xml"
PACKAGE_DIR = "com/zknox/railgunwallet"

PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.CAMERA",
    "android.permission.USE_BIOMETRIC",
]

SERVICE = """    <service
            android:name=".EngineService"
            android:exported="false"
            android:foregroundServiceType="dataSync" />
    """

ACTIVITY_ATTRS = {
    "android:configChanges": "orientation|screenSize|screenLayout|keyboardHidden|uiMode",
    "android:launchMode": "singleTask",
}


def fail(message):
    print(f"patch-android-project: {message}", file=sys.stderr)
    sys.exit(1)


def patch_manifest(text):
    missing = [p for p in PERMISSIONS if p not in text]
    if missing:
        block = "".join(
            f'    <uses-permission android:name="{p}" />\n' for p in missing
        )
        match = re.search(r"([ \t]*)<application\b", text)
        if not match:
            fail("no <application> in the manifest")
        text = text[: match.start()] + block + text[match.start() :]

    if ".EngineService" not in text:
        if "</application>" not in text:
            fail("no </application> in the manifest")
        text = text.replace("</application>", SERVICE + "</application>", 1)

    match = re.search(r"<activity\b[^>]*android:name=\"\.MainActivity\"[^>]*", text)
    if not match:
        fail("no MainActivity in the manifest")
    activity = match.group(0)
    patched = activity
    for name, value in ACTIVITY_ATTRS.items():
        if name in patched:
            patched = re.sub(rf'{name}="[^"]*"', f'{name}="{value}"', patched)
        else:
            patched += f'\n            {name}="{value}"'
    return text.replace(activity, patched, 1)


def main():
    if not MANIFEST.exists():
        fail(f"{MANIFEST} not found: run `cargo tauri android init` first")
    MANIFEST.write_text(patch_manifest(MANIFEST.read_text()))

    java_root = MANIFEST.parent / "java" / PACKAGE_DIR
    kotlin_root = MANIFEST.parent / "kotlin" / PACKAGE_DIR
    target = java_root if java_root.is_dir() else kotlin_root
    if not target.is_dir():
        fail(f"neither {java_root} nor {kotlin_root} exists")
    shutil.copy(CRATE / "android/EngineService.kt", target / "EngineService.kt")

    print(f"manifest patched, EngineService.kt copied into {target}")


if __name__ == "__main__":
    main()
