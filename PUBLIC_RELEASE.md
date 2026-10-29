# Public source export review

The public candidate is a new source tree. The private repository, its history,
remotes and GitHub visibility must remain private. This tool never invokes Git or
GitHub. The public target is `thekozugroup/googlebook-pad3-os`; the parent publishes
reviewed source there using fresh history. Do not copy the private `.git` directory.
The exporter never changes Git identity, initializes a repository or publishes.

## Native3 runtime record and one-time root migration

The parent reported the following observations after the built-in Settings
updater staged, downloaded and applied native3. After apply completed, the parent
separately ran `ksud install` using the pinned official SukiSU 41100 daemon, then
ran `adb reboot`. This was the one-time shared-daemon migration from UAPI 5 to
UAPI 6; the build2 updater did not perform that migration automatically.

- Build fingerprint: `Googlebook/erhai/erhai:17/GBOS/3:user/release-keys`.
- Slot B was successful and bootable; snapshot state was `NONE`. Postboot native
  UpdateEngine reported `CleanupPreviousUpdateAction kSuccess` and `MergeCompleted`.
- SukiSU kernel interface 41100/UAPI 6 and `ksud` 4.3.0 were observed with SELinux
  `Enforcing`.
- The boot bootstrap upgraded the normal `com.sukisu.ultra` manager to 41100
  using the same package. This manager upgrade is separate from daemon migration.
  A read-only `SukiSUManagerCheck` run as shell returned 0, verifying the current
  official signer, canonical data path and version.
- All three Dell APKs were physically absent. The remaining installed
  SupportAssist update was separately uninstalled; all three packages were then
  absent even from `pm list packages -u` listings.
- After sign-in, user 10 was `RUNNING_UNLOCKED`. Following `BOOT_COMPLETED`,
  `org.lineageos.pen/.PenService` reported `isForeground=true`, `foregroundId=1001`
  and a non-cached process. OnePlus Stylo2 BLE was connected, encrypted and bonded.
  Dedicated sysfs labels were verified; no relevant pen AVC/EACCES appeared in
  the available log. The user previously confirmed physical lines and pressure
  with the same pen version 40. No fresh physical strokes were tested in native3;
  the service and connection evidence does not establish that physical result.

For a build2-to-native3 update, prepare the reviewed UAPI 6 `init_boot` and pinned
official 41100 daemon, and preserve the old shared daemon/assets before apply.
After the updater finishes applying native3, install the matching daemon before
the first reboot into native3. Slot rollback alone does not restore `/data/adb`.
The observed boot-time manager upgrade does not establish automatic migration
for future SukiSU versions. Future kernel, module, daemon or UAPI changes need
their own compatibility review and migration procedure. This record describes
the reported native3 run, not a new device test or an artifact approval.

## Run and review

Run from the private checkout in a verified local development folder. Use a
task-owned CleanOS scratch directory for temporary files and tests; set `TMPDIR`
to that resolved directory. No SDK installation or full image build is needed.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_export_public
PYTHONDONTWRITEBYTECODE=1 python3 export_public.py \
  --output "$HOME/Developer/googlebook-pad3-public" \
  --secret-file /private/local-inputs/patterns.json
```

The secret-file example is a generic external location. Supply established private
credential, ADB key and signing-key files locally, or a parent-prepared JSON file.
`--secret-file` is repeatable. JSON supports a `patterns` array, or nested fields
named for PINs, passwords, passphrases, secrets, tokens and device serials. Use
`{"patterns": ["<nonmaterial-example>"], "serial": "<device-serial>"}` as a format
example, never as a substitute for the real private patterns during release review.
PEM, ADB public authorization files, newline-separated patterns, and certificate
DER files whose names contain `cert` are also supported. Plaintext patterns stay
in process memory. Reports contain classifications and relative paths, never
matched values, secret-file paths or secret fingerprints. Known numeric PINs match
bounded values so random hexadecimal hash substrings are not treated as PINs.

The audit is written to `reports/public-export-review.json` in the private project.
It records the exact allowlist, generated paths, documented transformations,
source findings, rejected findings, scan limits and candidate SHA-256 manifest.
It is deliberately excluded from the public tree. The candidate contains its own
`.public-export-manifest.json` with exact public paths and hashes. A successful
scan means a review candidate was produced; it does not authorize publication.

The audit also records `integration_complete`, `pending_missing_paths` and
`pending_review_paths`. A successful exit means the selected source candidate was
written. It does not mean future worker source is complete. Resolve all pending
entries and rerun before the parent publishes. Announced component directories,
builders and related new tests are inventoried for pending review; new files never
enter the export automatically. Capture metadata and generated binaries stay
excluded even when they are beside source files in a component directory.

Rerunning requires an exporter-owned manifest and unchanged managed files.
Unknown files, unknown empty directories, symlinks, hardlinks, missing managed
files, manual edits and a new `.git` directory block updates before writing.
Review or preserve those files yourself; the exporter does not delete them.
Per-file updates are staged in local `TMPDIR` on the same filesystem. An
interrupted update may require manual comparison against the old manifest; the
next run fails closed instead of discarding conflicting work. Finish exporting
before the parent initializes the new public Git repository.

## Exact source selection

`export_public.py:ALLOWLIST` is the fixed, exact input allowlist. It contains no
directory globs. `reports/public-export-review.json:allowlist` expands every path
for review. New files created by other agents remain excluded until explicitly
added after review. The selection consists of:

- The named root builders, disk/image/policy helpers, updater and diagnostic
  sources; their named tests; two Java image utilities; `inputs.json`; this guide;
  the exporter and its tests.
- `erofs_sanitize.py` and `test_erofs_sanitize.py`, reviewed parent source for a
  complete EROFS rewrite. Incremental replacement can retain removed key bytes in
  unreachable blocks. The sanitizer rebuilds reachable files with verified inode
  metadata, content hashes, symlink targets and hardlink groups, preserving its
  source image. Its tests use tiny synthetic images in owned scratch; no release
  image is processed by this export task.
- `qa/serve_probe.py`, `qa/test_serve_probe.py`, and `qa/tablet-probe.html`.
- `build_native_rom.py`, `test_build_native_rom.py`, the named native installer
  Python/shell sources, pinned `tools/avbtool.py`, `source-pins.json`, filtered
  `sukisu-layout-baseline.json`, and the reviewed example/schema JSON documents,
  including the slot-state template with unverified/false approvals and
  nonmaterial firmware-hash placeholders.
  The boot-control Java probe, build helper and two frozen AIDL source files are
  included. The capture manifest, compiled probe DEX/JAR and captured data remain
  private. Local AVB-tool and layout-baseline hashes are checked before export.
- `build_updater.py`, `test_build_updater.py`, and the exact named updater Java
  sources, compile-only API declarations, host tests, manifest, donor API/toolchain
  pins, empty feed fixture and native integration text. No updater APK or key
  asset is copied. There are no additional updater resource files in this reviewed
  inventory; new resources will appear as pending review.
- `build_face_overlay.py`, `test_build_face_overlay.py`, and the five reviewed
  face-overlay manifest, README, admission and XML resource inputs. Existing
  resource/admission checks and external certificate requirements are preserved.
- The exact taskmanager compatibility Java helper, compile/test API, graft helper
  and metrics test sources currently listed in `TASKMANAGER_FILES`, together with
  `patch_taskmanager.py` and `test_patch_taskmanager.py`. The generated candidate
  JAR and verification receipts are excluded. Binary preservation tests require
  an explicit external original JAR and task scratch; host metric fixtures use
  synthetic proc/sysfs data.
  Its source README and component ignore file are included; the entire generated
  `candidate/` directory is omitted from both source copying and pending-source
  inventory, and remains owned by the parent.
- The six named native policy/profile inputs under
  `profiles/erhai-crdroid-20261025`, with their original verification hashes.
- The named pen build-support, integration, patch and protocol-test sources;
  `donor-inputs.json`, `toolchain.json`, `upstream-manifest.json`, and `LICENSE`.
  The reviewed `tests/PenRuntimeSelfTest.kt` lifecycle/permission fixture and
  `tests/PeakCapSelfTest.kt` save/restore/owner-override fixture are included.
  `integration/write-settings-contract.json` contains the reviewed static
  permission/API contract; its source excerpts still require attribution review.
  Generated pen build results and derived component manifests stay private.
- The exact pinned upstream pen source, resource, AIDL and SELinux files listed
  in the exporter. Their inventory and SHA-256 hashes, license and patch are
  checked against the retained upstream manifest before writing.

The exporter generates `.gitignore`, the public `README.md`, `BUILDING.md`,
`TESTING.md`, `UPDATING.md`, and the component and profile README files. These
documents use generic local paths. Private manual docs are not copied or
string-redacted. See `GENERATED` and the audit for their exact paths.
Native installer, boot-control and updater README documents are generated with
generic inputs and the current feed contract. Private native command transcripts
and obsolete private/manual paths are not copied.
`native_install/INITIAL_INSTALL.md` is also generated as generic review guidance;
the private notes' local capture inventory, allocation measurements and backup/
waiver observations are omitted. No installer or device operation is authorized.

All unlisted inputs are excluded. In particular, the exporter excludes all
`artifacts/`, `backups/`, `reports/`, `.git/`, raw device/runtime captures,
owner PIN tests, build results, derived component manifests, credentials, private
PKI, ADB host authorization keys, and the entire owner signer profile directory.
It generates only a README in `profiles/pad3-components`; the complete owner
`certificate.der` and its private signing profile are never copied.

Two public configuration files are generated from an exact field allowlist:
`profiles/build-seed.json` contains only the three `image_sha256` partition pins
from the private staging report. `profiles/lineage-sources.json` contains only
`branch`, `current_kernel_source`, and the five named `heads` commit pins from the
private source review. No raw report, reviewer identity, runtime observation,
device authorization, credential or personal path is copied. The audit expands
every selected metadata field under `metadata_field_allowlist`.

## Reviewed portability changes

The exporter records each named change. It never replaces arbitrary source
strings, token-like values, or hash substrings to make a privacy check pass.

- `build_dsu_diagnostic.py:PUBLIC_KEY` uses the external
  `GOOGLEBOOK_ADB_PUBLIC_KEY` input, with an ignored generic default.
- `build_pen_dsu.py:CACHE` uses `GOOGLEBOOK_INPUTS`; its certificate input uses
  `GOOGLEBOOK_CERTIFICATE`. The owner DER file remains external.
- `stability_probe.py` uses `--serial` or `ANDROID_SERIAL`. There is no owner
  device serial default, and omitting both fails argument validation.
- The optional real-image test in `test_pen_policy.py` uses
  `build-inputs/donor-images`.
- Builder seed lookups and updater source lookups use the generated public pin
  configurations. The mocked diagnostic CLI test supplies a synthetic serial.
  Pen builder tests skip when no active `OPLUS_PEN_TEST_SCRATCH` is supplied;
  supply a task owned by the public checkout to run those tests.
  The Kotlin runtime test also requires the pinned local toolchain paths. Missing
  inputs produce an explicit skip; present inputs still undergo exact hash checks.
- `build.sh` accepts a verified local checkout under `$HOME/Developer`.
  Verify sync status yourself; a directory name alone cannot prove this.
- Only the named path fields in the toolchain, donor-input and integration JSON
  files become portable `build-inputs/...` paths. Dependency, firmware, upstream,
  patch, APK, signer and policy verification hashes remain unchanged.
- The native tools example changes only `avbtool.path` to
  `/ABSOLUTE/SOURCE/native_install/tools/avbtool.py`; the user completes that
  absolute checkout path without changing its pin. The plan example's
  `repository` is set to `thekozugroup/googlebook-pad3-os`. All other example
  placeholders, false approvals and verification hashes remain unchanged.
- The probe helper uses explicit `ANDROID_HOME` and `JAVA_HOME` inputs.
- The native manager checker uses the same explicit SDK/JDK environment inputs.
  Its Java sources and the updater's active-profile helper are included.
  The native builder reads the separately built checker through
  `GOOGLEBOOK_MANAGER_CHECKER`, defaulting to ignored
  `build-inputs/SukiSUManagerCheck.jar`. The checker binary is not in source.
- The taskmanager patch helper uses `ANDROID_HOME`, `JAVA_HOME` and
  `GOOGLEBOOK_JADX_JAR`, with generic ignored build-input defaults. Its exact
  original-client, DEX and JADX verification pins are unchanged. The local SDK
  needs the helper's declared platform version; do not silently substitute one.
  Its binary tests skip unless both `TASKMANAGER_TEST_SCRATCH` and
  `TASKMANAGER_INPUT_JAR` are supplied. No donor JAR is copied into public source.
- The updater builder uses `GOOGLEBOOK_INPUTS` for donor images and creates a
  fresh report directory/report rather than reading private integration evidence.
  The native and updater source constants must both match
  `https://raw.githubusercontent.com/thekozugroup/googlebook-pad3-os/refs/heads/main/updates/erhai/stable.json`.
  A mismatched source feed is rejected, not silently rewritten. No feed is
  created or published by the exporter.
  The keyless ZIP32/ZIP64 producer/consumer test uses `JAVA_HOME` or the portable
  toolchain input, and skips with an explicit reason when the JDK is unavailable.

The reviewed `build_native_userspace.py` and `test_build_native_userspace.py` are
included with the builder's explicit external
recipe inputs. It assembles EROFS userspace images and uses a complete sanitizer
rewrite after overlay changes. It has no hardcoded personal paths or embedded ADB
keys. The tests use synthetic tiny images and fake component inputs; they do not
establish the safety of a release image. Changes to the selected EROFS
implementation and tests are picked up by the next complete snapshot. The
exporter never copies provisioned DSU images
or ADB authorization files into the public source tree. The updater's producer/
consumer format test source is included; a keyless format fixture is not a
cryptographic or release-artifact approval.

Unexpected source shapes, remaining personal paths/emails, recognized keys/tokens,
known private values and invalid/nontext selected files block export. Python syntax
is validated after the reviewed transformations; an unfinished or invalid edit
blocks a new candidate. The source snapshot is checked again before writing
because other agents may still edit it.
The existing public-key rejection test has one documented nonmaterial exception:
its exact bare private-key header sentinel is permitted in that named test only.
Adding a key body or using the sentinel elsewhere still triggers a finding.
The updater's exact dummy-credential URL rejection assertion has a separate
nonmaterial email-pattern exception. Changing that fixture, moving it to another
file or matching a supplied private pattern still causes a finding. Key-related
CLI flags and variable names are source code, not key material.

## Artifacts and certificates

No release artifact is copied or approved by a source export. To check a final
ZIP or APK separately, pass `--scan-artifact /private/local-inputs/candidate.apk`
with the actual private patterns. Nested ZIP/APK members are scanned in memory,
including binary strings and UTF-16 representations. Encryption, unsafe archive
members, unsupported compression, size/depth/count limits, malformed archives,
and opaque filesystem-image members block complete artifact approval. Image
files need a separate format-aware extraction and privacy review. Do not call
unscanned compressed images clean because the surrounding ZIP was inspected.
The parent owns the release-artifact scan for this integration. This work checks
source and host tests only and does not repeat an actual release-artifact scan.

An APK inherently contains public verification certificates. They do not disclose
the private signing key. The scanner permits a supplied public certificate when
checking an artifact and still detects private-key bytes. The source export
excludes the full owner certificate at the owner's request. Certificate hashes
remain verification pins. Public certificates can carry identifying metadata;
review that metadata before releasing a signed artifact.

## Parent's remaining review

1. Wait for native, updater and pen edits to settle. Rerun the exporter with the
   complete established private-pattern inputs, review every selected path,
   transformation and finding, and inspect the final public diff and manifest.
2. Run the relevant source tests in the candidate. Record skipped checks and
   missing local inputs. A source scan is not hardware, boot, pen or power testing.
3. Review proprietary donor redistribution rights, the root project's license,
   retained upstream licenses, policy provenance and attribution. This exporter
   does not grant licenses or publish firmware.
4. Review all final release artifacts independently. Existing private diagnostic
   bundles intentionally contain host authorization material and are unsuitable
   for public release without a separate removal and format-aware audit.
5. Only then have the parent initialize fresh Git history, inspect its initial
   staged contents and publish to the public target. Use a project identity and
   noreply address in that repository's local configuration. Never change the
   existing private repository's visibility, history or remote.

The private Git history and excluded files are neither scanned nor copied.
Known-pattern and syntax checks cannot prove absence of unknown, fragmented,
encoded or obfuscated secrets. No general claim that the private project or its
history is leak-free follows from this audit.
