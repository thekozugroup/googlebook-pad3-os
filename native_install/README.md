# Native installer source and private build inputs

The private native5 candidate rebases userspace onto mica R5/build 16693588.
It has passed host checks but has not been installed. Schema 2 composes clean R5
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
