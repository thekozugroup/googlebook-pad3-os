#!/usr/bin/env python3
"""Create a reviewed source candidate; never copy Git history or publish anything."""
import argparse
import ast
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tempfile
import zipfile


OWNER = "googlebook-pad3-public-export/v1"
MANIFEST = ".public-export-manifest.json"
ROOT = Path(__file__).resolve().parent
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_DEPTH = 4
PUBLIC_REPOSITORY = "thekozugroup/googlebook-pad3-os"
PUBLIC_FEED = "https://raw.githubusercontent.com/" + PUBLIC_REPOSITORY + "/refs/heads/main/updates/erhai/stable.json"

# These are exact paths, not directory globs. New agent output needs review here.
ROOT_FILES = """
android_disk.py assemble_port.py bootanimation_geometry.py build.sh
build_dsu_diagnostic.py build_native_rom.py build_native_userspace.py build_oplus_pen.py build_pen_dsu.py build_secilc.sh build_updater.py build_face_overlay.py
patch_taskmanager.py build_taskmanager_metrics.py build_diagnostics_compat.py test_diagnostics_compat.py
build_photos_native.py test_build_photos_native.py build_photos_boot.py test_build_photos_boot.py
check_policy.py check_sukisu_layout.py check_updates.py cold_build_dsu.py
desktop_repair_gate.py erofs_overlay.py erofs_sanitize.py ext4_source.py flash_test.py inputs.json
package_port.py pen_policy.py port_changes.py prepare_inputs.py stability_probe.py
validate_candidate.py UpdateDsuImages.java VerifyDsuImages.java
test_android_disk.py test_bootanimation_geometry.py test_build_dsu_diagnostic.py
test_build_native_rom.py test_build_oplus_pen.py test_build_pen_dsu.py test_build_updater.py test_build_face_overlay.py test_check_sukisu_layout.py
test_build_native_userspace.py test_native_r5_userspace.py test_initial_install.py test_engine_libraries.py test_source_copy.py
test_patch_taskmanager.py
test_check_updates.py test_cold_build_dsu.py test_desktop_repair_gate.py
test_erofs_overlay.py test_erofs_sanitize.py test_flash_test.py test_pen_policy.py test_port_changes.py
test_prepare_inputs.py test_stability_probe.py export_public.py test_export_public.py
PUBLIC_RELEASE.md LAUNCH_READINESS.md COMMUNITY_NOTES.md tablet_state.py test_tablet_state.py
AGENTS.md MAINTAINING.md PRIVACY_AUDIT.md
discover_updates.py test_discover_updates.py privacy_audit.py test_privacy_audit.py
propose_update.py test_propose_update.py maintenance_job.py test_maintenance_job.py
maintenance_workspace.py test_maintenance_workspace.py
""".split()
COMPONENT = "components/oplus-pen/"
COMPONENT_FILES = """
LICENSE upstream-manifest.json donor-inputs.json toolchain.json
build-support/CompileApi.java build-support/compile-api.txt build-support/dex_api.py
integration/default-permissions_org.lineageos.pen.xml integration/pen_app.cil integration/pen_attachment.cil
integration/requirements.json integration/write-settings-contract.json integration/system_ext_mac_permissions.xml.template
integration/system_ext_seapp_contexts.template patches/googlebook.patch
tests/ProtocolSelfTest.kt tests/PenRuntimeSelfTest.kt tests/PeakCapSelfTest.kt
""".split()
UPSTREAM_FILES = """
interfaces/aidl_api/vendor.oplus.hardware.touch/2/.hash
interfaces/aidl_api/vendor.oplus.hardware.touch/2/vendor/oplus/hardware/touch/IOplusTouch.aidl
interfaces/aidl_api/vendor.oplus.hardware.touch/2/vendor/oplus/hardware/touch/IOplusTouchEventCallback.aidl
interfaces/aidl_api/vendor.oplus.hardware.touch/2/vendor/oplus/hardware/touch/OplusTouchInfo.aidl
interfaces/aidl_api/vendor.oplus.hardware.touch/2/vendor/oplus/hardware/touch/OplusTouchStatus.aidl
packages/Pen/Android.bp packages/Pen/AndroidManifest.xml
packages/Pen/default-permissions_org.lineageos.pen.xml packages/Pen/proguard.flags
packages/Pen/res/drawable/ic_stylus.xml packages/Pen/res/values/config.xml
packages/Pen/res/values/strings.xml
packages/Pen/src/org/lineageos/pen/BootCompletedReceiver.kt
packages/Pen/src/org/lineageos/pen/PenGattSession.kt
packages/Pen/src/org/lineageos/pen/PenProtocol.kt
packages/Pen/src/org/lineageos/pen/PenRelay.kt
packages/Pen/src/org/lineageos/pen/PenService.kt
packages/Pen/src/org/lineageos/pen/TouchHal.kt
sepolicy/qti/private/pen_app.te sepolicy/qti/private/seapp_contexts
""".split() + ["packages/Pen/res/values-" + language + "/strings.xml" for language in """
az bg ca ckb cs cy de el en-rAU en-rCA en-rGB en-rIN es fa fr ga-rIE hu in it iw
ja ka ko nn-rNO pl pt-rBR pt-rPT ro ru sc-rIT sl sq ta ug vi zh-rCN
""".split()]
PROFILE = "profiles/erhai-crdroid-20261025/"
PROFILE_FILES = """
profile.json policy/odm/odm_sepolicy.cil policy/vendor/genfs_labels_version.txt
policy/vendor/plat_pub_versioned.cil policy/vendor/plat_sepolicy_vers.txt
policy/vendor/vendor_sepolicy.cil
""".split()
NATIVE_FILES = """
avb.py fstab.py layout.py payload.py public_image.py product_cleanup.py r5_userspace.py initial_install.py engine_libraries.py install-sukisu-manager.sh tools/avbtool.py
patch_sukisu_module.py
donor-extractor/README.md donor-extractor/LICENSE donor-extractor/source-lock.json donor-extractor/native-lz4.patch
source-pins.json sukisu-layout-baseline.json plan.example.json tools.example.json
review.example.json bootcontrol/build_probe.py bootcontrol/NativeBootControlProbe.java
plan.schema.json review.schema.json slot-state.example.json slot-state.schema.json
bootcontrol/aidl/android/hardware/boot/IBootControl.aidl
bootcontrol/aidl/android/hardware/boot/MergeStatus.aidl
manager/ManagerDecision.java manager/SukiSUManagerCheck.java manager/build_checker.py
""".split()
UPDATER_FILES = """
AndroidManifest.xml donor-api.json toolchain.json feed-empty.json
build-support/android/os/SELinux.java build-support/android/os/SystemProperties.java
build-support/android/os/UpdateEngine.java build-support/android/os/UpdateEngineCallback.java
integration/native-properties.txt integration/required-access.te
src/org/googlebook/pad3/updater/MainActivity.java
src/org/googlebook/pad3/updater/ActiveProfile.java
src/org/googlebook/pad3/updater/NativeIdentity.java
src/org/googlebook/pad3/updater/ManifestCodec.java
src/org/googlebook/pad3/updater/RootInstaller.java
src/org/googlebook/pad3/updater/UpdateCore.java
src/org/googlebook/pad3/updater/UpdateService.java
src/org/googlebook/pad3/updater/WindowMode.java
src/org/googlebook/pad3/updater/RootWindowMode.java
src/org/googlebook/pad3/updater/LayoutTileService.java
tests/WindowModeTest.java
tests/FeedOrderTest.java tests/UpdateCoreTest.java tests/ProducerConsumerTest.java tests/ManifestCodecTest.java
""".split()
FACE_FILES = """
AndroidManifest.xml README.md overlay-config-entry.xml res/values/bools.xml res/xml/overlays.xml
""".split()
TASKMANAGER_FILES = """
.gitignore
README.md
build-support/GraftClient.java
compile-api/vendor/google/libraries/desktop/serviceability/ServiceabilityManager.java
src/vendor/google/libraries/desktop/serviceability/TaskManagerCompat.java
src/vendor/google/libraries/desktop/serviceability/NativeProcStats.java
tests/vendor/google/libraries/desktop/serviceability/MetricsSelfTest.java
native/README.md native/main.c native/metrics.c native/metrics.h native/host_tests.c
native/NativeProcStatsSelfTest.java native/googlebook_taskmanager_metrics.rc
native/taskmanager_metrics.cil native/file_contexts
""".split()
PHOTOS_FILES = """
README.md LICENSE FORK_NOTICE.md THIRD_PARTY_NOTICES.md licenses/Apache-2.0.txt
source-lock.json photos-strict.patch prepare.py verify.py build.sh
build-support.gradle tests/test_contract.py
""".split()
DIAGNOSTICS_FILES = """
README.md LICENSE AndroidManifest.xml source-lock.json
META-INF/xposed/module.prop META-INF/xposed/java_init.list META-INF/xposed/scope.list
src/org/googlebook/pad3/diagnostics/MetricValues.java
src/org/googlebook/pad3/diagnostics/DiagnosticsModule.java
tests/MetricValuesSelfTest.java
""".split()
PHOTOS_NATIVE_FILES = """
README.md LICENSE source-lock.json boot-paths.json
src/com/android/internal/util/googlebook/PhotosCompat.java
tests/PhotosCompatSelfTest.java build-support/GraftFramework.java
device-test/PhotosNativeProbe.java
""".split()
ALLOWLIST = tuple(sorted(ROOT_FILES + [COMPONENT + n for n in COMPONENT_FILES]
                         + [COMPONENT + "upstream/" + n for n in UPSTREAM_FILES]
                         + [PROFILE + n for n in PROFILE_FILES]
                         + ["native_install/" + n for n in NATIVE_FILES]
                         + ["components/updater/" + n for n in UPDATER_FILES]
                         + ["components/face-preview-overlay/" + n for n in FACE_FILES]
                         + ["components/taskmanager-compat/" + n for n in TASKMANAGER_FILES]
                         + ["components/photos-spoof/" + n for n in PHOTOS_FILES]
                         + ["components/diagnostics-compat/" + n for n in DIAGNOSTICS_FILES]
                         + ["components/photos-native/" + n for n in PHOTOS_NATIVE_FILES]
                         + ["maintenance/upstream.json", "maintenance/job.example.json"]
                         + [".github/workflows/" + n for n in ("source-checks.yml", "upstream-watch.yml", "native-maintenance.yml")]
                         + ["qa/serve_probe.py", "qa/test_serve_probe.py", "qa/tablet-probe.html"]))
JSON_TRANSFORMS = {COMPONENT + n for n in ("toolchain.json", "donor-inputs.json", "integration/requirements.json")} | {
    "components/updater/toolchain.json", "native_install/tools.example.json", "native_install/plan.example.json"}
INTEGRATION_DIRS = ("native_install", "components/oplus-pen", "components/updater", "components/face-preview-overlay", "components/taskmanager-compat", "components/photos-spoof", "components/photos-native", "components/diagnostics-compat")
ANNOUNCED_BUILDERS = ("build_face_overlay.py", "patch_taskmanager.py", "build_native_userspace.py")
ANNOUNCED_TESTS = ("test_build_face_overlay.py", "test_patch_taskmanager.py", "test_build_native_userspace.py")
PRIVATE_CAPTURE = "native_install/capture-manifest.json"

# Only these non-runtime pin fields may leave the otherwise excluded reports.
METADATA_SELECTION = {
    "reports/dsu-staging-report.json": {
        "output": "profiles/build-seed.json", "fields": ["image_sha256.system", "image_sha256.system_ext", "image_sha256.product"]},
    "reports/lineage-source-review.json": {
        "output": "profiles/lineage-sources.json", "fields": ["branch", "current_kernel_source",
            "heads.device_erhai", "heads.sm8750_common", "heads.kernel", "heads.modules", "heads.devicetrees"]},
}
MANUAL_REVIEW = [
    "Rerun after active native/updater/pen/face/taskmanager edits settle; resolve every pending integration path.",
    "Supply the complete current private pattern files; review any additional credentials and identifying metadata.",
    "Review root licensing, upstream attribution, native policy provenance and proprietary firmware redistribution rights.",
    "Validate hardware, boot, pen and power behavior separately; investigate every skipped input/tool-dependent test.",
    "Extract and review all final release images; private diagnostic bundles include host authorization material.",
    "Review signed artifact certificate identity; public verification certificates do not disclose private keys.",
    "Only the parent may initialize fresh public history and populate the public repository after review.",
]

GENERATED = {
    ".gitignore": """artifacts/
backups/
reports/
build-inputs/
__pycache__/
*.py[cod]
.DS_Store
.env
.env.*
*.key
*.keystore
*.p12
*.pfx
*.pem
*.der
*.jks
adbkey*
id_rsa*
id_ed25519*
*.apk
*.aab
*.apks
*.zip
*.img
*.ko
*.jar
*.dex
native_install/capture-manifest.json
""",
    "README.md": """# GoogleBook Pad3 OS experimental developer preview

Experimental Googlebook Android desktop porting tools for the OnePlus Pad 3.
This source export is for review. It does not establish hardware compatibility,
pen functionality, standby reliability, or permission to redistribute donor images.
The native boot, vendor and ODM partitions are preservation requirements.

Keep this checkout in a local development folder such as
`$HOME/Developer/googlebook-pad3-os`. Run commands from the checkout root.
Read [LAUNCH_READINESS.md](LAUNCH_READINESS.md) before inviting new installs.
Read [PUBLIC_RELEASE.md](PUBLIC_RELEASE.md), [BUILDING.md](BUILDING.md),
[TESTING.md](TESTING.md), and [UPDATING.md](UPDATING.md) before building.
See [MAINTAINING.md](MAINTAINING.md) for portable update jobs and automation,
and [PRIVACY_AUDIT.md](PRIVACY_AUDIT.md) for the publication audit and its limits.

No firmware, APK, owner credential, ADB authorization key, signing private key,
owner certificate file, raw device report, backup, or prior Git history is included.
Pinned upstream pen sources and their Apache 2.0 license are retained under
`components/oplus-pen`. Review third party licensing before redistribution.
""",
    "BUILDING.md": """# Local build inputs

Use an existing local SDK and JDK; do not copy full toolchains into this checkout.
On macOS, create a CleanOS task for disposable build output and verify its
backup-copy exclusion. On Linux, use maintenance_workspace.py to create an
explicitly owned private task. See MAINTAINING.md for both host paths.
Pass that task's resolved scratch path to builders that require it.
Install prerequisites separately; this source export downloads and installs nothing.

The portable toolchain lock retains exact dependency hashes. It refers to
`build-inputs/kotlin`, `build-inputs/android-sdk` and `build-inputs/jdk-21`.
Configure these private, ignored locations to use verified existing dependencies.
The donor lock refers to `build-inputs/donor-images/system_a.img`; preserve all
pinned input hashes and acquire firmware separately under its applicable terms.
`GOOGLEBOOK_INPUTS` can select another local image input root for the pen builder.

Diagnostic image builds require an explicit external ADB public authorization
file through `GOOGLEBOOK_ADB_PUBLIC_KEY`. This is host authorization material;
keep generated diagnostic images private. Public release images need a separate
review that removes host authorization and owner data. Do not publish an existing
diagnostic ZIP just because its source passes this exporter.

The pen layer builder requires an external public certificate via
`GOOGLEBOOK_CERTIFICATE`, defaulting to `build-inputs/component-certificate.der`.
Its certificate, APK and base-image verification pins remain unchanged. Replacing
the signer requires a coordinated reviewed build, new legitimate input pins and
matching SELinux mappings. No placeholder is accepted as a functioning signer.
Signing private keys remain external. The owner DER file is deliberately omitted.

The builders preserve their existing safeguards and experimental status. Consult
their CLI help, inspect the inputs, and review each generated result before use.

The build2-to-native3 UAPI 5-to-6 transition requires a separate one-time install
of the pinned official 41100 daemon after OTA apply and before the first reboot.
The updater did not perform that migration. Read the prerequisites, exact order
and qualified runtime record in [PUBLIC_RELEASE.md](PUBLIC_RELEASE.md#native3-runtime-record-and-one-time-root-migration).
The manager's boot-time self-upgrade does not migrate the shared daemon or
establish automatic compatibility with future SukiSU versions.
""",
    "TESTING.md": """# Source verification

From the checkout root, use a local temporary directory outside cloud sync:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -p 'test_*.py'
```

Some checks need local SDKs, compiler tools, pinned images, or certificates and
will skip or fail when those private build inputs are absent. Inspect the results.
These checks do not establish that the tablet can boot or that the pen works.
The source exporter tests use synthetic nonmaterial credentials only.
Owner PIN tests and device capture output are excluded from public source.

Device checks require an explicit `--serial` or `ANDROID_SERIAL` for
`stability_probe.py`. Keep its output private and outside the public source tree.
Flashing, DSU activation, rebooting and hardware tests require a separate procedure.
""",
    "UPDATING.md": """# Reviewing upstream changes

Use [MAINTAINING.md](MAINTAINING.md) for the update workflow, runner setup,
private input handoff, qualification and release procedure. The daily hosted
workflow discovers public metadata; it never signs or installs an unknown ROM.
The reviewed job runner reuses the existing offline native builders.

The full recovery catalog currently pins mica R2. The separately reviewed
incremental OTA baseline is mica R5. A catalog match to R2 does not mean the
installed R5 base is out of date. Discovery failure is reported as incomplete.
New versions require signature verification and a reviewed source/profile change.
Existing image, method, policy, kernel and Product pins remain mandatory.

Export only reviewed source and sanitized evidence. Never copy the private
repository's Git directory, raw reports, signing material or device identifiers.
""",
    "native_install/README.md": """# Native installer source and private build inputs

Private native5/native6 rebase userspace onto mica R5/build 16693588.
Native5 preserved apps/accounts and passed layout and pen-service checks; its
15-minute probe captured one Diagnostics crash. Native6 addresses the absent
laptop vendor service and booted with all 15 live image hashes matching its
signed payload. Private native8 adds Photos-only framework compatibility and
metric corrections. It booted, matched all 15 target hashes, retained root and
enforcing SELinux, and passed installed framework scope probes. Photos and
Diagnostics app checks passed; the old Photos module is removed. A three-minute
probe had no errors or new crashes. Diagnostics still requires its scoped adapter.
Schema 2 composes clean R5
images with the reviewed tablet graft; see [donor-extractor](donor-extractor/README.md).
The public binary feed remains native3.

Native3 has been installed through the maintainer's built-in updater and completed
its snapshot merge. This qualifies that exact update path, not a public first
installation or restore procedure. See PUBLIC_RELEASE.md and LAUNCH_READINESS.md.
Native3 has a reboot/sign-in rotation issue. Sequence 4's hash-bound tablet-state
patch changes only the donor provider's OPEN fallback to TABLET. The private
maintainer candidate passed reboot/user startup and owner-confirmed rotation;
see PUBLIC_RELEASE.md. It is not a public first-install or stable release.

The source includes the reviewed image/payload, AVB, layout and fstab helpers,
the pinned AOSP avbtool, source pins, filtered kernel-layout baseline and example
plan, tools and review documents. The capture manifest and captured images remain
private. The examples contain nonmaterial placeholders and false review flags;
they cannot authorize an installation or replace current hardware evidence.

The parent repository is `thekozugroup/googlebook-pad3-os`. The updater feed is
`https://raw.githubusercontent.com/thekozugroup/googlebook-pad3-os/refs/heads/main/updates/erhai/stable.json`,
with a detached `stable.json.sig`. No feed or release artifact is published by
the source exporter. Preserve existing signature, signer and firmware pins.

Run `python3 build_native_rom.py --help` from the checkout root. Keep release
keys, certificates, feed verification inputs, captured images and the completed
plan/tools/review documents in external private locations. Use existing local
SDK/JDK tools and a task-owned CleanOS output directory. The tools example uses
`/ABSOLUTE/SOURCE/native_install/tools/avbtool.py`; replace it with the reviewed
absolute checkout path while retaining its SHA-256 pin. The plan example names
the parent's public repository, but all capture, image, capacity, fingerprint,
snapshot and review inputs still require deliberate completion and validation.

For the pinned native engine, run `python3 -B -m native_install.engine_libraries
--help`. Its capture-to-bundle producer derives an absolute DT_RUNPATH for the
engine and 44 private libraries at `/system_ext/lib64/googlebook-update-engine`.
Pin the engine, original RC and bundle manifest in the userspace recipe and native
plan. Keep the global libraries intact and validate the init service with
AT_SECURE enabled. Supply JAVA_HOME when verifying signed APK inputs.

Build the Task Manager stat service with `build_taskmanager_metrics.py` and the
shared NDK named by that builder. Its UID1000/readproc service returns only fixed
per-PID counters. Merge its dedicated CIL and file contexts, including the
system_server read rule, and strictly compile the final assembled policy.
See `components/taskmanager-compat/native/README.md` for the socket contract.

Public follow-up plans copy unchanged partitions with signed source size/hash
checks. The reviewed root migration transports init_boot. The bounded Product
delta physically removes the three Dell APKs while copying unchanged blocks
from the pinned native-2 baseline; its changed bytes require a publication audit.
Build it with native_install.product_cleanup and provide tools.product_source.
Later updates can copy the cleaned Product unchanged. System, system_ext and
production recovery use REPLACE. These packages require the matching installed
baseline and cannot provision a fresh tablet.

Set plan source_slot and target_slot to opposite A/B slots. The signed feed's
source_slot is `_a` or `_b` and is checked immediately before apply, together with
the allowed fingerprint, increasing sequence and protected native boot state.
Follow-up installation preserves userdata. Validate source hashes, reconstruct
transported images, verify all signatures and audit public bytes before release.
The Settings updater needs its own SukiSU grant: enable Show system apps on the
Superuser page and allow System update. Root grants remain under owner control.

Native trust integration, UpdateEngine, AVB chain/rollback rules, fstab support,
platform signing and headless-user behavior require the parent's separate review.
Do not substitute the laptop updater for the captured Android native service.
Never bypass strict policy checks or treat a successful offline build as proof
of boot, recovery, manager recognition, OTA success, migration or rollback.

The boot-control getter probe is source-only here; see bootcontrol/README.md.
Keep all probe output and native device evidence out of the public source tree.
""",
    "native_install/bootcontrol/README.md": """# Boot-control getter probe source

The Java probe, build helper and frozen AOSP boot AIDL sources are included.
No compiled DEX/JAR or device capture is exported. The source checks the frozen
getter transaction declarations and packages the getter probe only. Inspect the
retained AIDL license headers and review the parent native instructions.

Use an existing SDK through `ANDROID_HOME` and an existing JDK through `JAVA_HOME`.
From the checkout root, use `python3 -B -m native_install.bootcontrol.build_probe
--help` to inspect its output argument. Supply a new output in an active local
CleanOS task. Build intermediates remain under that task and are removed by the
helper. The exporter does not build, transfer or execute the probe on a device.

The parent owns any hardware execution and capture cleanup. Only the pinned
getter calls are permitted. An idle snapshot result still needs comparison with
native layout/COW evidence; the source export grants no installation approval.
""",
    "native_install/INITIAL_INSTALL.md": """# Initial installation review

Historical offline planning guidance only. This is not a validated public first-
install procedure for a current stock tablet. Do not run generated example
commands as installation instructions. See LAUNCH_READINESS.md.

`python3 -B -m native_install.initial_install --help` describes the offline
five-image plan generator. It checks local candidate and rollback images and
emits standard fastboot commands; it does not execute them. The first installation
replaces current B through fastbootd, shrinking system_ext and product before
growing system. The kernel, rooted init_boot, hardware partitions and native
disabled-AVB configuration remain unchanged. It does not create slot A, delete
COW partitions, flash super or relock the bootloader.

Review the exact procedure, image hashes, trust inputs and explicit reset
authorization before device operations. Source export grants no device access.
Keep current rollback images, private captures and backup/waiver evidence outside
the public source tree. This document contains no local capture inventory or
claim that an existing device has satisfied the installation requirements.

Virtual A/B can retain target blocks in userdata-backed COW storage. Applying a
payload, selecting a slot or observing a ready snapshot state does not prove that
formatting userdata or metadata preserves that target. A recovery route requires
review of the exact recovery build, payload trust, snapshot-aware wipe ordering,
supported merge or cancellation behavior, target selection and completed merge
evidence. Unknown or inaccessible state requires stopping with data preserved.

A separate raw-image/fastbootd route needs a complete current allocation plan,
partition/group capacities, protected-partition preservation, firmware/boot-chain
compatibility, idle snapshot evidence and verified image hashes. Do not infer
space from alternative metadata slots or remove a COW group because it looks old.
Rollback after repartitioning or reset requires its own explicit recovery plan.

Review source/target platform signers, native UpdateEngine integration, headless
and foreground-user setup, root-manager recognition and the new updater trust
together. A host build, source test or DSU diagnostic bundle does not establish a
working or approved first installation. See PUBLIC_RELEASE.md in the repository
root for the parent's remaining source, license, artifact and hardware review.
""",
    "native_install/manager/README.md": """# Manager checker and bootstrap source

The Java decision/checker sources, build helper and shell bootstrap are included.
The official APK and compiled checker JAR are external build inputs, not files
shipped by this source export. Preserve the current certificate, version, path
and artifact hash checks recorded in source and source-pins.json.

The checker queries the fixed package's current signer, canonical install path
and version. The bootstrap skips an acceptable existing official manager, permits
only its reviewed install route and refuses foreign or unsupported state. It
does not uninstall packages or copy application data, modules or grants.

Build the checker in a new active local CleanOS scratch task with
`python3 -B -m native_install.manager.build_checker --output "$TASK_SCRATCH/SukiSUManagerCheck.jar"`.
Set `ANDROID_HOME` and `JAVA_HOME` to verified existing installations. Supply the
result to the native builder through `GOOGLEBOOK_MANAGER_CHECKER`; its existing
artifact hash validation still applies. Toolchain/source changes need a reviewed
rebuild and coordinated pin updates, not bypassing the checks.

The parent must separately verify native shell/SELinux behavior, manager
recognition and user setup. Host tests do not establish an Android runtime pass.
""",
    "components/updater/README.md": """# Native updater source

Version 1.3 (code 4) adds a Window layout Quick Settings tile: Tablet layout sets
internal display 0's default to fullscreen; Desktop layout selects freeform.
Existing windows may retain their layout. Physical tablet posture remains
independent, and external displays are untouched. Add the tile through Edit.
It reuses the owner's System update SukiSU grant and verifies native boot,
current-user ownership, enforcing ksu context and the canonical system APK.
Only fixed display 0 commands run, with readback; no polling service is added.

The source, compile-only Android API declarations, host tests, manifest, donor API
pins and integration requirements are included. No APK or release key is copied.
The feed targets the parent's public repository and `refs/heads/main/updates/erhai/stable.json`.
`feed-empty.json` is a local empty fixture, not a published or signed update feed.

Run `python3 build_updater.py --help` from the checkout root. The portable toolchain
lock refers to ignored `build-inputs/android-sdk` and `build-inputs/jdk-21` paths;
reuse verified existing installations and preserve every hash. `GOOGLEBOOK_INPUTS`
selects the private donor-image input root, defaulting to `build-inputs`.
Use an active CleanOS scratch directory. A verification key is an explicit external
public SPKI DER input; omission keeps update verification unprovisioned and closed.
Signing private keys and owner certificate files stay external.

The exported builder creates its own fresh build report instead of reading private
integration evidence. Native UpdateEngine integration, enforcing policy, platform
signer grants, active/full-user installation and Settings behavior need the parent's
review and hardware validation. Source/host tests do not establish successful OTA.
""",
    COMPONENT + "README.md": """# OplusPen component source

The `upstream-manifest.json` records the reviewed upstream commit and exact source
hashes. `upstream/`, `patches/googlebook.patch`, `LICENSE`, and
`tests/ProtocolSelfTest.kt` are retained. The upstream license and source bytes
are unchanged. Local toolchain and donor locks use generic ignored input paths
while retaining their verification hashes.

Build from the repository root with `build_oplus_pen.py` and an active local
CleanOS scratch task. See the root BUILDING.md. The integration files describe
package-scoped permissions and policy. Strict linkage and neverallow checks remain
required. Functional pen tests, refresh-rate behavior and sleep/wake need hardware
validation. Do not infer a working release from a successful source export.
""",
    PROFILE + "README.md": """# Native policy compilation inputs

These files are the reviewed crDroid policy inputs used for strict offline policy
compilation. `profile.json` retains their original hashes and provenance.
This directory contains policy text, not raw device captures or authorization keys.
Review policy licensing, provenance and compatibility before redistribution.
""",
    "profiles/pad3-components/README.md": """# External signer input

The owner's complete DER certificate and signing profile are excluded from public
source. Supply a matching public verification certificate as a private build input
through `GOOGLEBOOK_CERTIFICATE`. Existing verification hashes remain unchanged.
No private signing key belongs in this tree. A signed APK inherently includes its
public verification certificate; that certificate is not a private signing key.
""",
}


class ExportError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_relative(name):
    if not isinstance(name, str):
        return False
    path = PurePosixPath(name)
    return (bool(name) and not path.is_absolute()
            and ".." not in path.parts and "\\" not in name
            and ":" not in name and name != "."
            and name == path.as_posix() and all(ord(c) >= 32 for c in name))


def no_symlinks(path):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ExportError("symlink_refused")


def read_regular(path, limit=MAX_FILE):
    no_symlinks(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ExportError("nonregular_or_oversized_file")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns) or len(data) > limit:
            raise ExportError("source_changed_during_read")
        return data
    except OSError:
        raise ExportError("file_unreadable") from None


class Scanner:
    """Do not retain secret bytes in findings, logs, hashes, or exceptions."""

    def __init__(self):
        self.patterns = []
        self.derived_device_pattern_count = 0

    def add_secret(self, value, classification="known_secret"):
        if not value:
            raise ExportError("empty_secret_pattern")
        if len(value) < 4:
            raise ExportError("secret_pattern_too_short")
        bounded = value.isalnum() or value.isdigit()
        pattern = ((rb"(?<![A-Za-z0-9])" if bounded else b"") + re.escape(value)
                   + (rb"(?![A-Za-z0-9])" if bounded else b""))
        self.patterns.append((re.compile(pattern, re.I if classification == "known_device_identifier" else 0), classification))

    def load_secrets(self, path):
        data = read_regular(path, 1024 * 1024)
        if not data:
            raise ExportError("empty_secret_file")
        if path.suffix.lower() == ".der" and "cert" in path.name.lower():
            self.add_secret(data, "owner_certificate")
            self.add_secret(data.hex().encode(), "owner_certificate")
            self.add_secret(data.hex().upper().encode(), "owner_certificate")
            self.add_secret(base64.b64encode(data), "owner_certificate")
            return
        data = data.strip()
        try:
            values = json.loads(data)
        except (ValueError, UnicodeError):
            values = None
        if values is not None:
            count = len(self.patterns)

            def visit(value, key=""):
                if isinstance(value, dict):
                    for k, v in value.items():
                        visit(v, k)
                elif isinstance(value, list):
                    for item in value:
                        visit(item, key or "patterns")
                elif isinstance(value, (str, int)) and not isinstance(value, bool):
                    if re.search(r"pin|password|passphrase|token|secret|pattern|serial", key, re.I):
                        kind = ("known_pin" if "pin" in key.lower() or str(value).isdigit()
                                else "known_device_identifier" if "serial" in key.lower()
                                else "known_secret")
                        self.add_secret(str(value).encode(), kind)

            visit(values, "patterns")
            if len(self.patterns) == count:
                raise ExportError("secret_json_has_no_patterns")
            return
        self.add_secret(data, "known_private_key" if b"PRIVATE KEY" in data else "known_secret")
        if b"PRIVATE KEY" in data:
            body = b"".join(line.strip() for line in data.splitlines() if not line.startswith(b"-----"))
            try:
                decoded = base64.b64decode(body, validate=True)
                self.add_secret(decoded, "known_private_key")
                self.add_secret(decoded.hex().encode(), "known_private_key")
                self.add_secret(decoded.hex().upper().encode(), "known_private_key")
                self.add_secret(body, "known_private_key")
            except ValueError:
                raise ExportError("secret_private_key_invalid") from None
            for line in data.splitlines():
                if len(line) >= 32 and not line.startswith(b"-----"):
                    self.add_secret(line, "known_private_key")
        elif len(data.split()[0]) >= 600:
            try:
                raw = base64.b64decode(data.split()[0], validate=True)
                if len(raw) == 524 and struct.unpack_from("<I", raw)[0] == 64:
                    self.add_secret(data.split()[0], "known_adb_key")
                    self.add_secret(raw, "known_adb_key")
            except (ValueError, struct.error):
                pass
        elif b"\n" in data:
            for line in data.splitlines():
                if line.strip():
                    self.add_secret(line.strip(), "known_secret")

    def scan(self, data, path, *, artifact=False):
        findings = []

        def record(kind, offset, view):
            finding = {"path": path, "classification": kind,
                       "line": view[:offset].count(b"\n") + 1}
            if finding not in findings:
                findings.append(finding)

        views = [data]
        # Android strings may be UTF-16; do not miss a known value in binary payloads.
        if b"\x00" in data:
            for encoding in ("utf-16le", "utf-16be"):
                views.append(data[:len(data) - len(data) % 2].decode(encoding, "ignore").encode("utf-8"))
        rules = {
            "private_key": (rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----|-----BEGIN PGP "
                            rb"PRIVATE KEY BLOCK-----"),
            "personal_path": rb"/(?:Users|home)/[A-Za-z0-9_.-]+|[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z0-9_.-]+",
            "email": rb"[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "token": rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|AIza[A-Za-z0-9_-]{35}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})",
            "credential_literal": rb"(?i)\b(?:owner[_ -]?pin|password|passwd|api[_ -]?key|access[_ -]?token|client[_ -]?secret)\b[\"']?\s*[:=]\s*[\"']([^\"'\r\n]{4,})[\"']",
        }
        placeholders = {b"example", b"placeholder", b"test-only", b"not-a-secret", b"<pin>", b"<token>"}
        for view in views:
            for kind, pattern in rules.items():
                for match in re.finditer(pattern, view):
                    if kind == "email" and match.group().lower().endswith((b"@example.com", b"@example.invalid")):
                        continue
                    if kind == "email" and re.fullmatch(rb"android\.(?:hardware|hidl)\.[A-Za-z0-9_.]+@[0-9]+\.[0-9]+\.so", match.group()):
                        continue  # Versioned Android libraries; known-secret scans still run below.
                    if kind == "email" and path == "components/photos-native/boot-paths.json":
                        start = view.rfind(b"\n", 0, match.start()) + 1
                        end = view.find(b"\n", match.end())
                        line = view[start:end if end != -1 else len(view)].strip()
                        if re.fullmatch(rb'"/system/framework/oat/arm64/apex@com\.android\.[a-z0-9_.]+@javalib@[A-Za-z0-9_.-]+\.jar@classes\.(?:art|odex|vdex)(?:\.fsv_meta)?",?', line):
                            continue  # Encoded APEX preopt paths; known-secret scans still run below.
                    if kind == "credential_literal" and match.group(1).lower() in placeholders:
                        continue
                    record(kind, match.start(), view)
            for pattern, kind in self.patterns:
                for match in pattern.finditer(view):
                    if not (artifact and kind == "owner_certificate"):
                        record(kind, match.start(), view)
            for match in re.finditer(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{699,704}={0,2}(?![A-Za-z0-9+/])", view):
                try:
                    raw = base64.b64decode(match.group(), validate=True)
                    if len(raw) == 524 and struct.unpack_from("<I", raw)[0] == 64:
                        record("adb_authorization_key", match.start(), view)
                except (ValueError, struct.error):
                    pass
        if path == "test_port_changes.py":
            # This established negative test contains only a bare, nonmaterial header.
            try:
                tree = ast.parse(data.decode())
                lines = set()
                header = b"-" * 5 + b"BEGIN " + b"PRIVATE KEY" + b"-" * 5
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name == "test_only_one_android_public_key_is_accepted":
                        for value in ast.walk(node):
                            if isinstance(value, ast.Constant) and isinstance(value.value, bytes) and value.value in (header, header + b"\n"):
                                lines.update(range(value.lineno, value.end_lineno + 1))
                findings = [f for f in findings if not (f["classification"] == "private_key" and f["line"] in lines)]
            except (ValueError, UnicodeError, SyntaxError):
                pass
        if path == "components/updater/tests/UpdateCoreTest.java":
            # Exact dummy credentials in a URL rejection test, never a login/email.
            fixture = "https://owner:" + "token" + "@github.com/ota"
            expected = 'fails(() -> UpdateCore.httpsUrl("' + fixture + '"));'
            lines = {i for i, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1)
                     if line.strip() == expected}
            findings = [f for f in findings if not (f["classification"] == "email" and f["line"] in lines)]
        return findings

    def scan_artifact(self, path):
        findings, budget = [], [0, 0]

        def walk(data, label, depth):
            budget[0] += len(data)
            if budget[0] > MAX_TOTAL or depth > MAX_DEPTH:
                raise ExportError("archive_limit_exceeded")
            findings.extend(self.scan(data, label, artifact=True))
            if zipfile.is_zipfile(io.BytesIO(data)):
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    names = set()
                    for index, entry in enumerate(archive.infolist()):
                        budget[1] += 1
                        if budget[1] > MAX_ENTRIES:
                            raise ExportError("archive_limit_exceeded")
                        name = entry.filename.rstrip("/")
                        member = label + "!member[" + str(index) + "]"
                        if (not safe_relative(name) or name in names or entry.flag_bits & 1
                                or stat.S_ISLNK(entry.external_attr >> 16)):
                            raise ExportError("unsafe_archive_member")
                        names.add(name)
                        findings.extend(self.scan(entry.filename.encode(), member, artifact=True))
                        if entry.is_dir():
                            continue
                        if (entry.file_size > MAX_FILE or budget[0] + entry.file_size > MAX_TOTAL
                                or budget[1] > MAX_ENTRIES):
                            raise ExportError("archive_limit_exceeded")
                        payload = archive.read(entry)
                        if name.lower().endswith((".img", ".gz", ".xz", ".zst", ".7z", ".tar", ".bz2", ".br", ".lz4")):
                            findings.append({"path": member, "classification": "unscanned_container"})
                        walk(payload, member, depth + 1)
            elif depth == 0 or data.startswith((b"PK\x03\x04", b"\x1f\x8b", b"\xfd7zXZ", b"\x28\xb5\x2f\xfd")):
                findings.append({"path": label, "classification": "unscanned_container"})

        try:
            walk(read_regular(path), "release-artifact", 0)
        except (ExportError, OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
            findings.append({"path": "release-artifact", "classification": "artifact_not_fully_scanned"})
        return findings


def portable_source(name, data):
    """Only named configuration nodes change; do not redact arbitrary source."""
    text = data.decode("utf-8")
    changes, approved = [], []

    def replace_node(node, replacement, reason):
        lines = text.splitlines(keepends=True)
        start = sum(len(line) for line in lines[:node.lineno - 1]) + node.col_offset
        end = sum(len(line) for line in lines[:node.end_lineno - 1]) + node.end_col_offset
        changes.append((start, end, replacement, reason))
        approved.extend(range(node.lineno, node.end_lineno + 1))

    assignments = {
        "build_dsu_diagnostic.py": ("PUBLIC_KEY", 'Path(os.environ.get("GOOGLEBOOK_ADB_PUBLIC_KEY", "build-inputs/adb-public-key")).absolute()'),
        "build_pen_dsu.py": ("CACHE", 'Path(os.environ.get("GOOGLEBOOK_INPUTS", "build-inputs"))'),
    }
    if name in assignments:
        variable, replacement = assignments[name]
        nodes = [n for n in ast.parse(text).body if isinstance(n, ast.Assign)
                 and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == variable]
        if len(nodes) != 1 or not isinstance(nodes[0].value, ast.Call):
            raise ExportError("portability_precondition_changed")
        replace_node(nodes[0].value, replacement, "external_" + variable.lower())
    if name == "patch_taskmanager.py":
        replacements = {
            "SDK": 'Path(os.environ.get("ANDROID_HOME", "build-inputs/android-sdk"))',
            "JAVA": 'Path(os.environ.get("JAVA_HOME", "build-inputs/jdk-21"))',
            "JADX": 'Path(os.environ.get("GOOGLEBOOK_JADX_JAR", "build-inputs/jadx/jadx-1.5.6-all.jar"))',
        }
        for variable, replacement in replacements.items():
            nodes = [n for n in ast.parse(text).body if isinstance(n, ast.Assign) and len(n.targets) == 1
                     and isinstance(n.targets[0], ast.Name) and n.targets[0].id == variable]
            if len(nodes) != 1 or not isinstance(nodes[0].value, ast.Call):
                raise ExportError("portability_precondition_changed")
            replace_node(nodes[0].value, replacement, "portable_taskmanager_" + variable.lower())
    if name == "test_pen_policy.py":
        tests = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.FunctionDef)
                 and n.name == "test_actual_baseline_and_augmented_strict_compile"]
        nodes = [n for t in tests for n in ast.walk(t) if isinstance(n, ast.Assign)
                 and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "cache"]
        if len(nodes) != 1:
            raise ExportError("portability_precondition_changed")
        replace_node(nodes[0].value, 'Path("build-inputs/donor-images")', "portable_optional_test_inputs")
    if name == "stability_probe.py":
        nodes = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and n.func.attr == "add_argument"
                 and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == "--serial"]
        if len(nodes) != 1:
            raise ExportError("portability_precondition_changed")
        replace_node(nodes[0], 'parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"), required=not os.environ.get("ANDROID_SERIAL"))', "explicit_device_selection")
    if name == "build_pen_dsu.py":
        nodes = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div)
                 and isinstance(n.left, ast.Name) and n.left.id == "ROOT"
                 and isinstance(n.right, ast.Constant) and n.right.value == "profiles/pad3-components/certificate.der"]
        if len(nodes) != 1:
            raise ExportError("portability_precondition_changed")
        replace_node(nodes[0], 'Path(os.environ.get("GOOGLEBOOK_CERTIFICATE", "build-inputs/component-certificate.der"))', "external_public_certificate")
    if name == "build_native_rom.py":
        nodes = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div)
                 and isinstance(n.left, ast.Name) and n.left.id == "ROOT" and isinstance(n.right, ast.Constant)
                 and n.right.value == "native_install/manager/SukiSUManagerCheck.jar"]
        if len(nodes) not in (1, 2):
            raise ExportError("portability_precondition_changed")
        for node in nodes:
            replace_node(node, 'Path(os.environ.get("GOOGLEBOOK_MANAGER_CHECKER", "build-inputs/SukiSUManagerCheck.jar"))',
                         "external_manager_checker_input")
    report_paths = {
        "build_dsu_diagnostic.py": ("reports/dsu-staging-report.json", "profiles/build-seed.json"),
        "cold_build_dsu.py": ("reports/dsu-staging-report.json", "profiles/build-seed.json"),
        "check_updates.py": ("reports/lineage-source-review.json", "profiles/lineage-sources.json"),
    }
    if name in report_paths:
        previous, portable = report_paths[name]
        nodes = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Constant) and n.value == previous]
        if len(nodes) != 1:
            raise ExportError("portability_precondition_changed")
        replace_node(nodes[0], repr(portable), "public_pin_configuration")
    if name == "test_stability_probe.py":
        functions = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.FunctionDef)
                     and n.name == "test_mocked_cli_and_rotation_keep_output_private_and_bounded"]
        nodes = [n.args[0] for f in functions for n in ast.walk(f) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                 and n.func.value.id == "probe" and n.func.attr == "main" and len(n.args) == 1
                 and isinstance(n.args[0], ast.List)]
        if len(nodes) != 1 or any(isinstance(n, ast.Constant) and n.value == "--serial" for n in ast.walk(nodes[0])):
            raise ExportError("portability_precondition_changed")
        original = ast.get_source_segment(text, nodes[0])
        replace_node(nodes[0], '["--serial", "test", ' + original[1:], "explicit_mock_device_serial")
    if name == "test_build_updater.py":
        functions = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.FunctionDef)
                     and n.name == "test_actual_native_writer_zip32_and_zip64_match_consumer"]
        nodes = [n for f in functions for n in ast.walk(f) if isinstance(n, ast.Assign) and len(n.targets) == 1
                 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "java"]
        if len(nodes) != 1:
            raise ExportError("portability_precondition_changed")
        node = nodes[0]
        indent = " " * node.col_offset
        replace_node(node, 'java = Path(os.environ.get("JAVA_HOME", lock["java_home"])) / "bin"\n' + indent
                     + 'if not all((java / tool).is_file() for tool in ("java", "javac")):\n' + indent
                     + '    self.skipTest("set JAVA_HOME or configure the portable JDK input")', "portable_updater_format_test_jdk")
    if name == "test_build_oplus_pen.py":
        nodes = [n for n in ast.parse(text).body if isinstance(n, ast.ClassDef) and n.name == "PenBuildTests"]
        if len(nodes) != 1:
            raise ExportError("portability_precondition_changed")
        start = sum(len(line) for line in text.splitlines(keepends=True)[:nodes[0].lineno - 1])
        changes.append((start, start, "@unittest.skipUnless(os.environ.get('OPLUS_PEN_TEST_SCRATCH'), 'active local CleanOS task required')\n",
                        "optional_pen_scratch_tests"))
        functions = [n for n in ast.walk(nodes[0]) if isinstance(n, ast.FunctionDef)
                     and n.name in ("run_kotlin_check", "test_kotlin_runtime_lifecycle_and_permission_races")
                     and any(isinstance(c, ast.Call) and ast.unparse(c.func) == "pen.verify_toolchain" for c in ast.walk(n))]
        for function in functions:
            locks = [n for n in ast.walk(function) if isinstance(n, ast.Assign) and len(n.targets) == 1
                     and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "lock"]
            if len(locks) != 1 or not isinstance(locks[0].value, ast.Call) or ast.unparse(locks[0].value.func) != "pen.verify_toolchain":
                raise ExportError("portability_precondition_changed")
            node = locks[0]
            indent = " " * node.col_offset
            replace_node(node, 'config = pen.load(pen.COMPONENT / "toolchain.json")\n' + indent
                         + 'inputs = [*config["dependencies"].values(), *config["tools"].values()]\n' + indent
                         + 'if not (Path(config["java_home"]) / "bin/java").is_file() or not all(Path(item["path"]).is_file() for item in inputs):\n'
                         + indent + '    self.skipTest("configure the pinned local pen toolchain inputs")\n' + indent
                         + 'lock = pen.verify_toolchain()', "optional_pinned_pen_runtime_toolchain")
    if name in ("build_updater.py", "native_install/bootcontrol/build_probe.py", "native_install/manager/build_checker.py"):
        tree = ast.parse(text)
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "build"]
        variables = ("image", "report") if name == "build_updater.py" else ("sdk", "jdk")
        for variable in variables:
            nodes = [n for f in functions for n in ast.walk(f) if isinstance(n, ast.Assign)
                     and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == variable]
            if len(nodes) != 1:
                raise ExportError("portability_precondition_changed")
            node = nodes[0]
            if variable == "report":
                if not isinstance(node.value, ast.Call) or ast.unparse(node.value.func) != "json.loads":
                    raise ExportError("portability_precondition_changed")
                indent = " " * node.col_offset
                replace_node(node, 'report_path.parent.mkdir(parents=True, exist_ok=True)\n' + indent
                             + 'report = {"component": "native-updater", "source_candidate": True}',
                             "fresh_updater_build_report")
            else:
                replacement = {
                    "image": 'Path(os.environ.get("GOOGLEBOOK_INPUTS", "build-inputs")) / "donor-images/system_a.img"',
                    "sdk": 'Path(os.environ["ANDROID_HOME"])',
                    "jdk": 'Path(os.environ["JAVA_HOME"]) / "bin"',
                }[variable]
                if not isinstance(node.value, (ast.Call, ast.BinOp)):
                    raise ExportError("portability_precondition_changed")
                replace_node(node.value, replacement, "portable_" + variable + "_input")
        if name != "build_updater.py" and not any(
                isinstance(n, ast.Import) and any(a.name == "os" and a.asname is None for a in n.names) for n in tree.body):
            first = next(n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)))
            start = sum(len(line) for line in text.splitlines(keepends=True)[:first.lineno - 1])
            changes.append((start, start, "import os\n", "probe_environment_import"))
    if name == "build.sh":
        lines = text.splitlines(keepends=True)
        nodes = [i for i, line in enumerate(lines) if line.startswith('[[ "$SOURCE" == ') and "Keep this source outside cloud sync." in line]
        if len(nodes) != 1:
            raise ExportError("portability_precondition_changed")
        index = nodes[0]
        start = sum(map(len, lines[:index]))
        changes.append((start, start + len(lines[index]),
                        'case "$SOURCE" in "$HOME"/Developer/*) ;; *) echo \'Keep source in a verified local Developer folder.\' >&2; exit 2;; esac\n',
                        "portable_local_workspace_guard"))
        approved.append(index + 1)
    for start, end, replacement, _ in sorted(changes, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text.encode(), [reason for _, _, _, reason in changes], approved


def portable_json(name, data):
    value = json.loads(data)
    if name in (COMPONENT + "toolchain.json", "components/updater/toolchain.json"):
        value["java_home"] = "build-inputs/jdk-21"
        for entry in value.get("dependencies", {}).values():
            entry["path"] = "build-inputs/kotlin/" + Path(entry["path"]).name
        for key, entry in value["tools"].items():
            relative = ("platforms/" + value["sdk_platform"] + "/android.jar" if key == "android_jar"
                        else "build-tools/" + value["build_tools"] + "/"
                        + ("lib/" if key == "r8_jar" else "") + Path(entry["path"]).name)
            entry["path"] = "build-inputs/android-sdk/" + relative
    elif name == COMPONENT + "donor-inputs.json":
        for entry in value["images"]:
            entry["path"] = "build-inputs/donor-images/" + Path(entry["path"]).name
        for entry in value["files"]:
            entry["image"] = "build-inputs/donor-images/" + Path(entry["image"]).name
    elif name == COMPONENT + "integration/requirements.json":
        value["policy_source"]["image"] = "build-inputs/pad3-base-images/system_ext.img"
    elif name == "native_install/tools.example.json":
        value["avbtool"]["path"] = "/ABSOLUTE/SOURCE/native_install/tools/avbtool.py"
    elif name == "native_install/plan.example.json":
        if value["repository"] not in ("OWNER/PUBLIC_REPO", PUBLIC_REPOSITORY):
            raise ExportError("unexpected_public_example_repository")
        value["repository"] = PUBLIC_REPOSITORY
    else:
        raise ExportError("unreviewed_json_transform")
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def metadata_files(source):
    files, snapshots = {}, {}
    for name, selection in METADATA_SELECTION.items():
        data = read_regular(source / name)
        value = json.loads(data)
        result = {}
        for field in selection["fields"]:
            keys = field.split(".")
            current, target = value, result
            for key in keys[:-1]:
                current = current[key]
                target = target.setdefault(key, {})
            item = current[keys[-1]]
            pattern = (r"lineage-[0-9]+\.[0-9]+" if field == "branch"
                       else r"[a-f0-9]{64}" if field.startswith("image_sha256.") else r"[a-f0-9]{40}")
            if not isinstance(item, str) or not re.fullmatch(pattern, item):
                raise ExportError("invalid_public_metadata_pin")
            target[keys[-1]] = item
        files[selection["output"]] = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
        snapshots[name] = digest(data)
    return files, snapshots


def verify_upstream(files):
    manifest = json.loads(files[COMPONENT + "upstream-manifest.json"])
    expected = {entry["path"]: entry for entry in manifest["files"]}
    actual = {n.removeprefix(COMPONENT + "upstream/") for n in files if n.startswith(COMPONENT + "upstream/")}
    if set(expected) != actual or len(expected) != len(manifest["files"]):
        raise ExportError("upstream_inventory_changed")
    for entry, prefix in ([(e, COMPONENT + "upstream/") for e in expected.values()]
                          + [(manifest["license_text"], COMPONENT), (manifest["patch"], COMPONENT)]):
        name = prefix + entry["path"]
        if name not in files or digest(files[name]) != entry["sha256"]:
            raise ExportError("upstream_pin_mismatch")


def verify_integration(files):
    pins = json.loads(files["native_install/source-pins.json"])
    local = [entry for entry in pins["sources"] if "local" in entry]
    if {entry["local"] for entry in local} != {"native_install/tools/avbtool.py"}:
        raise ExportError("unreviewed_native_source_pin")
    for entry in local:
        if digest(files[entry["local"]]) != entry["sha256"]:
            raise ExportError("native_source_pin_mismatch")
    if digest(files["native_install/sukisu-layout-baseline.json"]) != pins["filtered_layout_baseline_sha256"]:
        raise ExportError("native_layout_pin_mismatch")
    for name, fields in {"build_updater.py": {"FEED": PUBLIC_FEED},
                         "build_native_rom.py": {"PUBLIC_REPO": PUBLIC_REPOSITORY, "FEED_URL": PUBLIC_FEED}}.items():
        assignments = {n.targets[0].id: n.value for n in ast.parse(files[name]).body
                       if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)}
        for key, expected in fields.items():
            if key not in assignments or not isinstance(assignments[key], ast.Constant) or assignments[key].value != expected:
                raise ExportError("public_updater_feed_contract_mismatch")


def pending_integration(source, scanner):
    """Inventory announced source only; future files never enter the allowlist automatically."""
    missing, pending = [], []
    reviewed = set(ALLOWLIST) | set(GENERATED) | {PRIVATE_CAPTURE, COMPONENT + "build-result.json", COMPONENT + "component-manifest.json"}

    def add(path):
        name = path.relative_to(source).as_posix()
        if name not in reviewed:
            # An unknown filename can itself contain a private value.
            pending.append(name if not scanner.scan(name.encode(), "unreviewed-source-name")
                           else "unreviewed-source-name-with-private-value")

    for name in INTEGRATION_DIRS:
        path = source / name
        if not path.exists():
            missing.append(name + "/")
            continue
        no_symlinks(path)
        for current, directories, filenames in os.walk(path, followlinks=False):
            for directory in directories:
                if (Path(current) / directory).is_symlink():
                    add(Path(current) / directory)
            directories[:] = [d for d in directories if d not in ("__pycache__", ".git")
                              and (Path(current) / d).relative_to(source).as_posix() != "components/taskmanager-compat/candidate"
                              and not (Path(current) / d).is_symlink()]
            for filename in filenames:
                candidate = Path(current) / filename
                if candidate.suffix.lower() in (".py", ".java", ".kt", ".aidl", ".xml", ".json", ".md", ".txt", ".te", ".cil", ".patch", ".sh") or filename in ("LICENSE", "NOTICE"):
                    add(candidate)
    for name in (*ANNOUNCED_BUILDERS, *ANNOUNCED_TESTS):
        path = source / name
        if path.exists():
            add(path)
        else:
            missing.append(name)
    for path in source.glob("*.py"):
        if path.name != "test_owner_pin.py":
            add(path)
    return {"pending_missing_paths": sorted(missing), "pending_review_paths": sorted(set(pending)),
            "integration_complete": not missing and not pending}


def inspect_destination(destination):
    no_symlinks(destination)
    if not destination.exists():
        if not destination.parent.is_dir():
            raise ExportError("destination_parent_missing")
        return None
    if not destination.is_dir() or destination.stat().st_uid != os.getuid():
        raise ExportError("destination_not_owned")
    try:
        manifest = json.loads(read_regular(destination / MANIFEST))
    except (ValueError, ExportError):
        raise ExportError("destination_has_no_valid_manifest") from None
    if manifest.get("exporter") != OWNER or manifest.get("schema") != 1 or not isinstance(manifest.get("files"), dict):
        raise ExportError("destination_has_no_valid_manifest")
    old = manifest["files"]
    if not all(safe_relative(n) and n != MANIFEST
               and not set(PurePosixPath(n).parts) & {".git", "artifacts", "backups", "reports", "build-inputs"}
               and isinstance(v, dict)
               and re.fullmatch(r"[a-f0-9]{64}", v.get("sha256", "")) for n, v in old.items()):
        raise ExportError("destination_has_no_valid_manifest")
    dirs = {str(parent) for n in old for parent in PurePosixPath(n).parents if str(parent) != "."}
    actual = set()
    for current, directories, filenames in os.walk(destination, followlinks=False):
        for name in directories + filenames:
            path = Path(current) / name
            relative = path.relative_to(destination).as_posix()
            no_symlinks(path)
            if path.stat().st_uid != os.getuid() or (path.is_file() and path.stat().st_nlink != 1):
                raise ExportError("destination_has_foreign_or_linked_file")
            if path.is_dir():
                if relative not in dirs:
                    raise ExportError("destination_has_unknown_directory")
            else:
                actual.add(relative)
                if relative != MANIFEST and (relative not in old or digest(read_regular(path)) != old[relative]["sha256"]):
                    raise ExportError("destination_has_unknown_or_modified_file")
    if actual != set(old) | {MANIFEST}:
        raise ExportError("destination_missing_managed_file")
    return manifest


def publish(destination, files, executable, scanner):
    old = inspect_destination(destination)
    manifest = {"exporter": OWNER, "schema": 1,
                "files": {name: {"sha256": digest(data), "bytes": len(data), "executable": name in executable}
                          for name, data in sorted(files.items())}, "history_copied": False}
    payloads = dict(files)
    payloads[MANIFEST] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    if scanner.scan(payloads[MANIFEST], MANIFEST):
        raise ExportError("manifest_privacy_finding")
    # Stage only in the caller's local task TMPDIR; never copy SDKs or source history.
    with tempfile.TemporaryDirectory(prefix="public-export-stage-") as temporary:
        stage = Path(temporary)
        if stage.stat().st_dev != destination.parent.stat().st_dev:
            raise ExportError("scratch_and_destination_must_share_filesystem")
        for index, (name, data) in enumerate(payloads.items()):
            path = stage / str(index)
            path.write_bytes(data)
            path.chmod(0o755 if name in executable else 0o644)
        if inspect_destination(destination) != old:
            raise ExportError("destination_changed")
        if old is None:
            destination.mkdir()
        for index, (name, data) in enumerate(payloads.items()):
            path = destination / name
            no_symlinks(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                if name != MANIFEST and (old is None or name not in old["files"]
                                         or digest(read_regular(path)) != old["files"][name]["sha256"]):
                    raise ExportError("destination_changed")
                if name == MANIFEST and json.loads(read_regular(path)) != old:
                    raise ExportError("destination_changed")
                if read_regular(path) == data:
                    path.chmod(0o755 if name in executable else 0o644)
                    continue
                os.replace(stage / str(index), path)
            else:
                # Exclusive creation protects an unknown file appearing after inspection.
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                             0o755 if name in executable else 0o644)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
        for name in sorted(set(old["files"] if old else ()) - set(files)):
            path = destination / name
            if digest(read_regular(path)) != old["files"][name]["sha256"]:
                raise ExportError("destination_changed")
            path.unlink()
        # Remove only now-empty directories listed by the prior managed files.
        for parent in sorted({destination / p for n in old["files"] if old
                              for p in PurePosixPath(n).parents if str(p) != "."},
                             key=lambda p: len(p.parts), reverse=True) if old else ():
            if parent.is_dir() and not any(parent.iterdir()):
                parent.rmdir()
    inspect_destination(destination)
    return manifest


def inspect_audit(path):
    no_symlinks(path)
    if path.name != "public-export-review.json":
        raise ExportError("audit_filename_refused")
    if path.exists():
        try:
            previous = json.loads(read_regular(path))
        except (ExportError, ValueError):
            raise ExportError("unknown_audit_file_refused") from None
        if previous.get("exporter") != OWNER or path.stat().st_uid != os.getuid() or path.stat().st_nlink != 1:
            raise ExportError("unknown_audit_file_refused")


def write_audit(path, report):
    inspect_audit(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w" if path.exists() else "x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def export(source, destination, scanner, artifacts=()):
    no_symlinks(source)
    source, destination = source.absolute(), destination.absolute()
    if (source == destination or source in destination.parents or destination in source.parents
            or destination.name in (".git", "artifacts", "backups")):
        raise ExportError("source_destination_overlap")
    inspect_destination(destination)
    provided_patterns = len(scanner.patterns) - scanner.derived_device_pattern_count
    # Remember the old device default in memory so copies elsewhere also block export.
    try:
        tree = ast.parse(read_regular(source / "stability_probe.py").decode())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_argument" and node.args
                    and isinstance(node.args[0], ast.Constant) and node.args[0].value == "--serial"):
                for keyword in node.keywords:
                    if keyword.arg == "default" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str) and keyword.value.value:
                        pattern = keyword.value.value.encode()
                        if not any(kind == "known_device_identifier" and regex.search(pattern)
                                   for regex, kind in scanner.patterns):
                            scanner.add_secret(pattern, "known_device_identifier")
                            scanner.derived_device_pattern_count += 1
    except (ExportError, ValueError, UnicodeError, SyntaxError):
        pass  # The complete selected-file scan below reports an unreadable/invalid source.
    report = {"exporter": OWNER, "schema": 1, "status": "blocked", "allowlist": list(ALLOWLIST),
              "generated_files": sorted(set(GENERATED) | {v["output"] for v in METADATA_SELECTION.values()}),
              "metadata_field_allowlist": METADATA_SELECTION, "findings": [], "source_findings": [],
              "public_repository": PUBLIC_REPOSITORY, "public_feed": PUBLIC_FEED,
              "remaining_manual_review": MANUAL_REVIEW,
              "transformations": [], "known_secret_pattern_count": len(scanner.patterns),
              "provided_pattern_count": provided_patterns,
              "derived_device_pattern_count": scanner.derived_device_pattern_count,
              "nonmaterial_exceptions": [{"path": "test_port_changes.py", "classification": "private_key",
                                          "scope": "bare bytes header only in test_only_one_android_public_key_is_accepted"},
                                         {"path": "components/updater/tests/UpdateCoreTest.java", "classification": "email",
                                          "scope": "exact dummy credential URL in the HTTPS rejection assertion only"}],
              "known_secret_scan": "supplied" if provided_patterns else "not_supplied",
              "history_scanned": False, "history_copied": False, "artifacts_copied": False,
              "release_artifacts_checked": len(artifacts),
              "excluded": {".git/": "all private history and remotes",
                           "artifacts/": "all binaries, runtime data and private inputs",
                           "backups/": "all backups", "reports/": "all raw device/runtime reports",
                           "profiles/pad3-components/": "owner DER certificate and private signer profile",
                           "native_install/capture-manifest.json": "private native device capture metadata",
                           "components/taskmanager-compat/candidate/": "generated binary and private verification receipts",
                           "unlisted_files": "default deny, including owner PIN tests and new agent files"},
              "limitations": ["Private Git history and excluded files are not scanned or copied.",
                              "No artifact assurance unless each final artifact is separately fully scanned.",
                              "Filesystem images and unsupported/encrypted/oversized archives block artifact approval.",
                              "Pattern scanning is not a proof against unknown secrets or encoded/obfuscated data.",
                              "Source and hardware validation must be repeated after active agents finish."]}
    files, executable, snapshots = {}, set(), {}
    json_names = JSON_TRANSFORMS
    total = 0
    for name in ALLOWLIST:
        try:
            data = read_regular(source / name)
            snapshots[name] = digest(data)
            total += len(data)
            if total > MAX_TOTAL:
                raise ExportError("source_size_limit")
            original = scanner.scan(data, name)
            report["source_findings"].extend(original)
            if name in json_names:
                clean = portable_json(name, data)
                # Only the schema's named local path fields may account for a source finding.
                restored = json.loads(data)
                converted = json.loads(clean)

                def differences(a, b, path=()):
                    if isinstance(a, dict) and isinstance(b, dict) and a.keys() == b.keys():
                        return [d for k in a for d in differences(a[k], b[k], path + (str(k),))]
                    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
                        return [d for i, (x, y) in enumerate(zip(a, b)) for d in differences(x, y, path + (str(i),))]
                    return [(path, a)] if a != b else []

                diff = differences(restored, converted)
                path_findings = [f for _, value in diff if isinstance(value, str)
                                 for f in scanner.scan(value.encode(), name)]
                if any(f["classification"] != "personal_path" for f in path_findings):
                    raise ExportError("secret_in_portability_field")
                report["transformations"].append({"path": name, "rule": "portable_json_input_paths",
                                                  "fields": [".".join(keys) for keys, _ in diff]})
                # Re-scan unchanged fields below; hashes and other values are never redacted.
                rejected = [f for f in original if f["classification"] != "personal_path"]
            else:
                clean, rules, approved_lines = portable_source(name, data)
                report["transformations"].extend({"path": name, "rule": r} for r in rules)
                rejected = [f for f in original if not (f["line"] in approved_lines and
                            f["classification"] in ("personal_path", "known_device_identifier"))]
            report["findings"].extend(rejected)
            report["findings"].extend(scanner.scan(clean, name))
            if name.endswith(".py"):
                ast.parse(clean, filename=name)
            files[name] = clean
            if (source / name).stat().st_mode & 0o111:
                executable.add(name)
        except (ExportError, ValueError, UnicodeError, KeyError, TypeError, SyntaxError) as error:
            code = str(error) if isinstance(error, ExportError) else "invalid_selected_source"
            report["findings"].append({"path": name, "classification": code})
    for name, text in GENERATED.items():
        files[name] = text.encode()
        report["findings"].extend(scanner.scan(files[name], name))
    metadata_snapshots = {}
    try:
        metadata, metadata_snapshots = metadata_files(source)
        for name, data in metadata.items():
            files[name] = data
            report["findings"].extend(scanner.scan(data, name))
    except (ExportError, ValueError, KeyError, TypeError) as error:
        report["findings"].append({"path": "public-metadata-fields", "classification":
                                   str(error) if isinstance(error, ExportError) else "invalid_public_metadata_pin"})
    for artifact in artifacts:
        report["findings"].extend(scanner.scan_artifact(artifact))
    if not report["findings"]:
        for name, check in ((COMPONENT + "upstream-manifest.json", verify_upstream),
                            ("native_install/source-pins.json", verify_integration)):
            try:
                check(files)
            except (ExportError, ValueError, KeyError, TypeError, SyntaxError) as error:
                report["findings"].append({"path": name, "classification":
                                           str(error) if isinstance(error, ExportError) else "invalid_source_pins_or_contract"})
    report.update(pending_integration(source, scanner))
    report["selected_files_scanned"] = len(snapshots)
    report["output_files_scanned"] = len(files)
    if not report["findings"]:
        # Recheck the complete source snapshot so concurrent agent writes cause a rejection.
        for name, expected_digest in {**snapshots, **metadata_snapshots}.items():
            try:
                unchanged = digest(read_regular(source / name)) == expected_digest
            except ExportError:
                unchanged = False
            if not unchanged:
                report["findings"].append({"path": name, "classification": "source_changed_during_export"})
    if not report["findings"]:
        manifest = publish(destination, files, executable, scanner)
        report.update(status="candidate_exported_requires_manual_review", manifest=manifest,
                      manifest_scanned=True, output_bytes=sum(len(b) for b in files.values()))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=Path.home() / "Developer/googlebook-pad3-public")
    parser.add_argument("--audit", type=Path, default=ROOT / "reports/public-export-review.json")
    parser.add_argument("--secret-file", action="append", type=Path, default=[],
                        help="external private JSON patterns, newline patterns, PEM, ADB public key, or certificate DER; repeatable")
    parser.add_argument("--scan-artifact", action="append", type=Path, default=[],
                        help="scan a final ZIP/APK and nested ZIP members without copying it")
    args = parser.parse_args(argv)
    audit_valid = False
    try:
        audit = args.audit.absolute()
        if audit == args.output.absolute() or args.output.absolute() in audit.parents:
            raise ExportError("audit_must_be_outside_public_output")
        # Check audit ownership before any candidate write.
        inspect_audit(audit)
        audit_valid = True
        scanner = Scanner()
        for path in args.secret_file:
            scanner.load_secrets(path)
        report = export(args.source, args.output, scanner, args.scan_artifact)
        write_audit(audit, report)
        print(json.dumps({"status": report["status"], "findings": len(report["findings"]),
                          "selected_files_scanned": report["selected_files_scanned"],
                          "integration_complete": report["integration_complete"],
                          "pending_missing": len(report["pending_missing_paths"]),
                          "pending_review": len(report["pending_review_paths"])}))
        return 2 if report["findings"] else 0
    except (ExportError, OSError, ValueError, TypeError) as error:
        # Never interpolate filesystem/JSON/subprocess exceptions containing private input.
        code = str(error) if isinstance(error, ExportError) else "export_io_or_input_error"
        if audit_valid:
            try:
                write_audit(audit, {"exporter": OWNER, "schema": 1, "status": "blocked",
                                   "allowlist": list(ALLOWLIST), "metadata_field_allowlist": METADATA_SELECTION,
                                   "remaining_manual_review": MANUAL_REVIEW,
                                   "findings": [{"path": "export", "classification": code}],
                                   "history_scanned": False, "history_copied": False,
                                   "complete_source_scan": False})
            except (ExportError, OSError, ValueError, TypeError):
                pass
        print(json.dumps({"status": "blocked", "classification": code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
