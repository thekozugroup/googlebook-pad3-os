# Pad 3 Diagnostics metrics adapter

This Modern libxposed API101 module corrects the exact audited Google Diagnostics APK inside that app's process. It requires the exact package, system appId and APK hash in `source-lock.json`. Source drift leaves the app untouched. The original Google APK and platform APIs in other processes remain unchanged. Vector and its Zygisk provider must be active; the owner installation uses explicit personal-user scope.

The adapter uses Android's band-aware Wi-Fi channel conversion, raw OS `totalMem - availMem` and `totalMem`, and explicitly labeled binary memory units. CPU history contains collected interval samples only; the first reading seeds the baseline. Missing readings display Unavailable. Battery state of health comes from the actual OEM gauge, preserving a valid existing Android reading. It does not substitute a fixed percentage or infer health from a capacity ratio. The ROM's shared client supplies measured/design capacity in uAh through three narrowly labeled, read-only battery telemetry files.

Factory cache, memory, charge and other laptop vendor routines remain unsupported. Their failure is not evidence of defective tablet hardware. The module supplies metrics, not hardware certification. Camera frames, physical peripherals and external displays require separate hardware checks. Relaunch Diagnostics after enabling, disabling or updating this module.

Build with existing JDK21, SDK platform36/build-tools36.0.0, the pinned compile-only API JAR extracted from the verified AAR, and the established external component key/certificate. No Gradle, NDK, SDK download or signing-key creation is needed. All generated output must use an active owned CleanOS task outside cloud sync.

```sh
python3 -B build_diagnostics_compat.py --scratch "$TASKROOT" --api "$API_JAR" \
  --key "$PRIVATE_KEY" --certificate "$CERTIFICATE" --sdk "$SDK" --jdk "$JDK" \
  --output "$TASKROOT/DiagnosticsCompat.apk"
```

The builder runs the metric/scope self-tests, keeps the API compile-only, checks the signer/package/scope and writes a source-bound receipt. Host results do not establish actual hooking, readable sysfs labels, UI values or stability; verify those on the device before including a release. Keep compiled APKs, dependency archives, private signing inputs and runtime logs outside this source component.
