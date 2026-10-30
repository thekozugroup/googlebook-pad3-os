# Strict Photos-only spoof source

This component reconstructs an independently maintained Pixelify source revision and applies the locked strict patch. It changes process-local Build identity and feature answers only for the exact package `com.google.android.apps.photos`. The shared policy, early/ready callbacks and both spoof entry methods enforce that restriction. Manager scope cannot enable spoofing for other packages. The default profile is Pixel XL; actual Android release, API, incremental and security patch versions remain unchanged, including when old version-override preferences are imported.

The module requires Modern libxposed **API101**. Enablement, scope readback, a Pixel profile, local field readback or a Photos banner does not establish successful runtime hooking or Google server quota eligibility. Quota entitlement is unverified. Injector compatibility and device testing require separate evidence.

**Upgrade limit:** upgrades of this locally signed strict fork require the same signer. An upstream APK may use a different signer and different scope. Upstream auto-update is not qualified for this fork. Preserve the signing key privately and rebuild the locked strict source for a reviewed update.

## Inputs and provenance

`source-lock.json` pins the upstream commit/archive URL, archive SHA-256, exact patch SHA-256, changed source files and original license/notices. The chosen source is later than the published 1.4.1 release and includes Android17 fallbacks. `photos-strict.patch` is unchanged from the built proof. The original MIT license, fork notice, third-party notices and Apache license are preserved byte for byte.

The tested tool versions are JDK17, Gradle8.11.1, AGP8.10.1, Kotlin2.1.0, SDK36, installed NDK30.0.16248370 and CMake3.22.1. The NDK30 substitution is explicit in the patch and lock. A previous signed proof passed 299 Android JVM tests and compiled JNI for arm64-v8a, armeabi-v7a and x86_64. Those are build/JVM results, not device or quota results.

## Reconstruct and verify without building

Choose a disposable local workspace outside this component and cloud-sync roots. Python3, Git and standard libraries are sufficient:

```sh
python3 -B components/photos-spoof/prepare.py "$WORK" --archive "$LOCKED_SOURCE_ARCHIVE"
python3 -B components/photos-spoof/verify.py "$WORK/source"
PHOTOS_SOURCE_ROOT="$WORK/source" TMPDIR="$WORK/tmp" \
  python3 -B -m unittest discover -s components/photos-spoof/tests -v
```

Create the temporary directory before the test command. Omit `--archive` to fetch the locked source into the workspace; size and SHA-256 are checked before extraction. Existing edited source is never overwritten. The lightweight tests reject broad eligibility, missing entry guards, security-version writes and additional scope packages. The patch also retains the JVM exact-package boundary test; the full Android JVM suite runs during a build.

## Build with existing local tools

Set `ANDROID_SDK_ROOT`, `JAVA_HOME`, `CMAKE_HOME`, `GRADLE_BIN` and `PHOTOS_DEBUG_KEYSTORE` to existing local installations and the established private debug signing key. No machine or signing paths are embedded here. The existing SDK must contain platform36, build-tools35.0.0 and NDK30.0.16248370; the supplied CMake directory must contain CMake3.22.1 and Ninja.

```sh
components/photos-spoof/build.sh "$WORK"
```

The build uses explicit `cmake.dir` and places source, Maven downloads, Gradle user/project caches, Kotlin state, Android state, native staging and APK/test outputs under the supplied workspace. Maven resolution may access the network; set `PHOTOS_OFFLINE=1` for a warm cache. `PHOTOS_READ_ONLY_GRADLE_CACHE` optionally names a shared cache directory containing `modules-2`; it is read-only and is never copied. `PHOTOS_SOURCE_ARCHIVE` optionally reuses the locked archive. No SDK/NDK install is performed. Limits are two Gradle workers, a 1536MiB Gradle heap, one test fork and a 768MiB test heap.

The APK is under `outputs/app/outputs/apk/debug/` and XML unit results are under `outputs/app/test-results/testDebugUnitTest/`. Preserve the APK, signing identity and private build evidence before removing the disposable workspace. APKs, provider ZIPs and machine-specific build/signing evidence belong outside this source component.
