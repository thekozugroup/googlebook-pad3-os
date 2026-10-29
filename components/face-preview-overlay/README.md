# Face enrollment preview overlay

This resource-only RRO targets `com.android.settings` and sets exactly
`bool/config_face_settings_should_manage_preview=false`. The pinned Google
Settings caller then supplies its TextureView Surface through FaceUpdater and
FaceManager to FaceEnrollClient / `ISession.enrollWithOptions.surfacePreview`.
Settings leaves camera ownership with the native face HAL. The existing challenge,
hardware authentication token, foreground user and enrollment callbacks remain in
that path. This does not change camera metadata or global orientation.

## Build

Reuse the installed SDK: build-tools 36.0.0 and platform android-37.2. This build
uses only aapt2 and zipalign; it needs no Java compilation, Gradle or downloads.
Create an active CleanOS task for this checkout and pass its real scratch path:

```sh
python3 -B build_face_overlay.py --scratch "$TASK_SCRATCH" \
  --certificate "$OWNER_PUBLIC_CERTIFICATE_DER" --sdk "$ANDROID_HOME"
FACE_OVERLAY_TEST_SCRATCH="$TASK_SCRATCH" python3 -B -m unittest test_build_face_overlay
```

The certificate must be a complete canonical X.509 DER public certificate. Its
SHA-256 identifies the expected final signer in the receipt; it is not embedded
in the unsigned APK. The helper neither requests nor uses a signing key. It emits
one aligned `face-preview-overlay/GooglebookPad3FacePreview-unsigned.apk` and a
`build-result.json` under scratch, refuses replacement, and removes intermediates.
All SDK paths and certificate input are external; none are stored in source.

## Parent integration in the next system_ext image

1. Sign the unsigned APK externally with the owner certificate supplied to the
   helper. Verify its final signer fingerprint against the receipt and record
   the signed APK's new hash. Keep the target Settings APK and its signer intact.
2. Place the signed APK at
   `system_ext/overlay/GooglebookPad3FacePreview/GooglebookPad3FacePreview.apk`.
3. Merge `overlay-config-entry.xml` into the existing
   `system_ext/overlay/config/config.xml` root. Preserve its wallpaper entry and
   every other existing entry. If an entry for this package exists, update it
   once rather than adding a duplicate. Check later overlays do not override
   the same resource. The expected entry is enabled and immutable.

The pinned target has no overlayable declarations. A preinstalled system_ext
overlay can therefore use the normal preinstalled admission policy without
matching the Settings signer; omit `targetName`. A data-installed overlay is not
equivalent. Because this partition already has OverlayConfig, a manifest-only
static setting does not establish enablement. No added permissions, SELinux
rules, framework replacement or signing-policy bypass are required by this RRO.
Recheck these assumptions if the target APK changes.

## Required device evidence, collected by the parent

Verify idmap admission and the effective target boolean for the credentialed
foreground user, then start a fresh enrollment activity. A retained sidecar can
retain the previous flag. Confirm a non-null valid Surface reaches the native
face session, Settings no longer opens a competing camera, and the previous
`enrollWithOptions invalid previewSurface!!` error is absent. Test real human
enrollment, stored enrollment and subsequent unlock, including retry,
cancellation and activity recreation. Keep real challenge/token verification.
Shell or emulator completion is not evidence of human face enrollment.

The Google path uses a 750 ms start delay rather than Lineage's explicit
surface-ready callback. This RRO selects the correct path; device testing must
still exclude a Surface lifecycle race. Check face UI and preview orientation
physically in normal landscape and supported rotations. Both general camera
previews were already confirmed upright; do not change global camera/sensor
orientation to compensate for the face UI.

Primary reference: [AOSP runtime resource overlays](https://source.android.com/docs/core/runtime/rros).
Exact pinned caller and native evidence, with inspection times, are retained in
`reports/v9-compatibility-audit.json` and `.md`.
