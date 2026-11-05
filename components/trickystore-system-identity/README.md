# TrickyStore system application identity correction

This offline recipe corrects one application-ID branch in the existing
TrickyStore OSS compatibility path. Android reserves the attestation application
ID `AndroidSystem`, version 1, with no signature digests for exact UIDs 0 and
1000. The affected module instead enumerates their ordinary shared-UID packages.
Android's companion-device verifier requires the reserved identity when verifying
a system-owned key. Ordinary app UIDs retain the module's original package and
signature resolution. Other-user UIDs are not treated as UID 1000.

The patch adds one small helper and changes only the implementation of
`w6.c(KeyPair,v6,o90,int,int,KeyPair)`. It preserves the method's metadata, register
count and ordinary-UID branch. The build disassembles the supplied original class
itself; no upstream DEX, full smali, module binary or key material is vendored.

## Supported input and tools

Only this exact `classes.dex` is accepted:

```
SHA-256 47d2350898e50696a653f5a5d0ee199b1b147053d253f832c84f55d08d80376e
Format  DEX039
```

It was captured from TrickyStore OSS v3.1.0
`199-dda5277-release`. The hash, not the displayed version, is authoritative.
Other inputs fail before creating output. Review changed layouts and upstream
fixes rather than weakening this pin.

Use Python 3.11+, an installed JDK 21, Android SDK D8, and the installed JADX
1.5.6 all-in-one JAR, which includes smali, baksmali and dexlib2. The tested SDK
build-tools version is 36.0.0. No downloads, Gradle, SDK copy, device connection or
new dependencies are needed. The receipt records source and tool file hashes.
That tested toolchain reproduces the runtime-tested DEX byte for byte:

```
SHA-256 9423c17ede744ce2ad2a29e28d9a52560da87a7e78903c27888855aea7da0798
```

## Build

Run from the repository. Supply your own external private input and installed
tool paths. Set `JAVA_HOME` to the selected JDK and `JADX_ALL_JAR` to its installed
all-in-one JAR. `D8` is the installed SDK `d8` launcher. Do not put generated
outputs in this component, the repository, a cloud-synced folder or a task root.

Create an owned task as described in `MAINTAINING.md`: CleanOS on macOS, or
`maintenance_workspace.py init` on Linux. Set `TASK_SCRATCH` to its canonical
physical path. macOS additionally verifies backup-copy exclusion. The output
child must not already exist; existing files are never overwritten.

```sh
python3 -B components/trickystore-system-identity/build.py \
  --input-dex "$PRIVATE_INPUT/classes.dex" \
  --java-home "$JAVA_HOME" \
  --jadx-jar "$JADX_ALL_JAR" \
  --d8 "$D8" \
  --scratch "$TASK_SCRATCH/system-identity-build"
```

All compiler output, generated smali, temporary files, logs and DEX files stay in
that external output child. Java uses two active processors and bounded heaps.
The deliverables are `classes.dex` and `validation.json`; `build.log` and generated
`w6.smali` support private review. Clean the owned build directory after preserving
the requested output and receipt. This recipe does not install or restart a module.

Every successful run checks:

- Exact input digest and DEX039 input/output headers.
- A unique expected method and insertion branch, unchanged register count, and
  no pre-existing helper or duplicate classes.
- Host tests for exact root/system DER, fresh arrays, and unchanged ordinary UID
  behavior; unknown-input and unsafe-output boundary tests.
- Canonical baksmali equality for all 3,307 other original classes and all other
  `w6` methods and metadata. Only the helper class is added.

The initial maintainer runtime test recorded local peer-verification result 0,
bad-challenge result 8, an established companion channel, and actual AppCast video
and input. Those observations are separate from an offline rebuild. A rebuild
does not qualify another module version, phone, device or future service update.

## Limits and integration

This remains an existing TrickyStore compatibility path. It does not create
factory trust, certification, Strong Integrity, genuine hardware provisioning or
an attestation keybox. The standard Android peer verifier remains untouched; the
patch does not disable verification, local binding, challenge or ownership checks.

Target configuration is a separate, user-private installation prerequisite. This
component contains no target list, keybox, private IDs or automatic device action.
It does not configure feature flags or their persistence. Keep exact rollback
bytes and qualify the live module separately before deployment. Updating or
reinstalling TrickyStore overwrites this DEX patch; an unreviewed new module is
deliberately rejected. Prefer an equivalent upstream source correction when
available. This component is not a full module distribution or redistribution
license grant.

References:

- [AOSP system attestation application ID](https://android.googlesource.com/platform/system/security/+/refs/heads/android17-release/keystore/keystore_attestation_id.cpp)
- [AOSP peer-device ownership verification](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android17-release/services/core/java/com/android/server/security/AttestationVerificationPeerDeviceVerifier.java)
- [TrickyStore OSS](https://github.com/beakthoven/TrickyStoreOSS)
