# Native installer source and private build inputs

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

Native trust integration, UpdateEngine, AVB chain/rollback rules, fstab support,
platform signing and headless-user behavior require the parent's separate review.
Do not substitute the laptop updater for the captured Android native service.
Never bypass strict policy checks or treat a successful offline build as proof
of boot, recovery, manager recognition, OTA success, migration or rollback.

The boot-control getter probe is source-only here; see bootcontrol/README.md.
Keep all probe output and native device evidence out of the public source tree.
