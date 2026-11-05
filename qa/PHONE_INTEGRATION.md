# Phone integration QA

`PhoneFileRoundtrip.java` exercises the existing Quick Access DocumentsProvider.
It creates one randomly named synthetic file in the selected phone's **Download**
directory, reads it back, and deletes only that proven task-owned file. Image
mode also requests a 32×32 thumbnail and checks its center pixel against RGB
(0, 140, 220), allowing at most 4 per channel for JPEG rounding. It does not install an app,
change accounts, repair pairing, or qualify AppCast, handoff, or general sync.
Run only with the device owner's authorization and an already working pairing.

## Measured qualification

Maintainer tests passed exact 89-byte text and 98-byte synthetic PNG roundtrips
through the paired-phone provider. The 32×32 thumbnail center pixel was
`0xff008cdc`, matching RGB (0, 140, 220). All test files were deleted with deletion
verified, and temporary phone-file probes were removed. This finite coverage does
not qualify general file/media sync.

Native Chrome task handoff passed end to end with an isolated public test URL.
Using existing AppCast, the test created a separate phone tab. The native task
list advertised Chrome, and clicking its new badged taskbar item produced a
correlated request, phone result and successful tablet-local Chrome launch. The
local URL bar matched the exact expected URL including its test fragment, and
the actual page was visible. No phone USB, fixture APK, new flags or direct local
URL launch was used. Handoff requires opt-in apps; arbitrary apps and broader
app-state restoration remain unqualified. Both test tabs were closed, preserving
the original phone tab and tab count.

See [GOOGLE_SERVICES.md](../GOOGLE_SERVICES.md) for separate AppCast/config checks
and rooted-module trust limits. Private native10 was installed through System
update without a reset and passed two complete OS reboots. The automatic check
succeeded on both boots before opening the updater; read-only inspection found
the original four Ambient and two receiver state links. Accounts, installed apps,
SukiSU and SELinux enforcing were retained. Native AppCast video and remote input
passed after the first boot, and the finite text/PNG/thumbnail/deletion checks
passed after the second. Fresh server sync and future GMS/module versions remain
unqualified. The public update feed has not been promoted to native10.
Native Chrome handoff was measured on native9. Native10 received real phone
task advertisements, but a new handoff launch was not completed in this pass;
its owned phone test tab was closed and the original tab count restored.

## OTA and reboot qualification

Use the signed, data-preserving update through the built-in System update app.
Do not factory reset, install an updater APK over the built-in app, or change
slots manually to qualify the OTA. Preserve the source release as rollback
evidence. Before submission, record the actual build, current and active slots,
boot-success state, snapshot-merge state, inactive logical-partition capacity,
free space, battery, root and SELinux state. The updater refuses an unsuccessful
source slot, a queued slot switch, an active snapshot merge, or unavailable boot
state. Its signed native10 payload preserves the existing rooted init_boot.
The reviewed SystemExt image is slightly larger; verify current inactive-slot
metadata and dynamic-group headroom rather than relying on the previous plan.

Capture private before/after account and installed-app inventories, the reviewed
module DEX hash and target scope, and the GMS version/hash. Never publish account
names, association IDs, device serials, credentials, keyboxes or raw device logs.
The startup check verifies the owner's existing module; it does not install a
module, provision a keybox, grant root, or adapt unknown GMS/module versions.

After installation, qualify **two complete OS reboots**, unlocking the paired
user after each. Before opening System update or running any manual repair,
inspect its private `phone-compat` preferences and boot log. Require a check from
the current boot/build with `configuration_checked=true`. Opening System update
also schedules the job and would conceal a failed boot trigger. A successful
configuration call alone does not prove snapshot contents, phone connectivity,
or a working video stream.

For each boot, verify the effective native flags and snapshot ownership/labels
read-only, retained accounts/apps, SukiSU root and SELinux enforcing. After the
final boot, exercise AppCast with visible frames and a remote input response;
repeat the finite file
roundtrip and a native opt-in Chrome handoff with test-tab cleanup. Confirm the
layout tile, rotation and pen remain functional. Wait for boot success and any
snapshot merge to finish before the second reboot. Record durations, results
and bounded private failure evidence. Do not run manual ensure/publish commands
to turn a failed persistence test into a pass.

If a check fails, retain the exact version and failure evidence, fix the shared
source, and repeat qualification. Do not clear GMS/account data, replace native
pairing with synthetic records, loosen attestation verification, or publish the
candidate as stable. A subsequent GMS update and a fresh native server refresh
are separate compatibility tests; passing two reboots does not qualify every
future upstream release.

## Local compile and self-test

Reuse a verified local Android SDK and JDK 21. Set `SOURCE_ROOT`,
`ANDROID_SDK_ROOT`, and `JAVA_HOME` for this host. Keep source outside cloud sync.
Use a new, private, task-owned `TASK_SCRATCH` outside the checkout and sync roots;
on macOS use the host maintenance/CleanOS task lifecycle and check backup-copy
exclusion. Keep all compiler outputs and temporary files there. No Gradle,
dependency installation, APK, emulator, or builder is needed.

```sh
: "${SOURCE_ROOT:?local checkout}" "${ANDROID_SDK_ROOT:?existing SDK}" \
  "${JAVA_HOME:?existing JDK 21}" "${TASK_SCRATCH:?owned external task scratch}"
ANDROID_JAR="$ANDROID_SDK_ROOT/platforms/android-37.2/android.jar"
D8="$ANDROID_SDK_ROOT/build-tools/36.0.0/d8"
umask 077
mkdir "$TASK_SCRATCH/classes" "$TASK_SCRATCH/dex" "$TASK_SCRATCH/tmp"
"$JAVA_HOME/bin/javac" -J-Xmx256m -J-XX:ActiveProcessorCount=2 \
  -J-Djava.io.tmpdir="$TASK_SCRATCH/tmp" --release 8 -classpath "$ANDROID_JAR" \
  -d "$TASK_SCRATCH/classes" "$SOURCE_ROOT/qa/PhoneFileRoundtrip.java"
"$JAVA_HOME/bin/java" -Xmx128m -XX:ActiveProcessorCount=2 \
  -Djava.io.tmpdir="$TASK_SCRATCH/tmp" \
  -classpath "$TASK_SCRATCH/classes:$ANDROID_JAR" PhoneFileRoundtrip --self-test
JAVA_HOME="$JAVA_HOME" JAVA_TOOL_OPTIONS="-Xmx512m -XX:ActiveProcessorCount=2 -Djava.io.tmpdir=$TASK_SCRATCH/tmp" \
  "$D8" --min-api 29 --lib "$ANDROID_JAR" --output "$TASK_SCRATCH/dex" \
  "$TASK_SCRATCH"/classes/*.class
```

Expected self-test output: `PHONE_FILE_SELF_TEST_PASS`. The self-test checks
argument, user, root-ID, receipt-path, fixture, read-size, and deletion-ownership
boundaries and thumbnail color tolerance using Java alone. `android.jar` supplies class definitions; the test
does not initialize Android SDK stubs or contact a device. It does not validate
Binder, filesystem ownership, the live provider, pairing, or thumbnail decoding.

## Explicit device inputs

Pass exactly four positional arguments, in this order:

| Shell variable | Required value |
| --- | --- |
| `ANDROID_USER` | Existing paired Android user, decimal 1–21474; user 0 is rejected. No automatic user discovery. |
| `SELECTED_PAIRED_ROOT_ID` | Exact `root_id` from the owner-selected phone in this user's provider roots. This is not the root's `document_id`, an account ID, a display name, or a guessed first row. |
| `OWNED_RECEIPT_DIRECTORY` | Existing physical directory `/data/local/tmp/googlebook-phone-probe-<suffix>`. Suffix: 1–64 ASCII letters, digits, `_`, or `-`, starting with a letter or digit. |
| `MODE` | Exactly `text` or `image`. |

The root must match exactly once. Only a direct directory named `Download` with
create support is eligible; missing, ambiguous, or read-only directories fail.
The probe never creates a directory or selects another phone as a fallback.
Text mode uses an 89-byte UTF-8 synthetic message with a random nonce. Image mode uses the
98-byte synthetic 32×32 RGB (0, 140, 220) PNG from the working probe, with no personal media.
Both readbacks must equal the submitted bytes and stay within 4096 bytes.

The root controller must create a **fresh receipt directory**, verify its exact
physical path, and assign UID/GID **1000:1000**, mode **0700**, before launch.
The probe rejects missing directories, symlinks, wrong owners, broader modes,
and existing `receipt.properties` or `receipt.properties.next` files. It writes
0600 receipts atomically and syncs them. Keep the directory private throughout
the run. Do not use app data, shared storage, an existing test's directory, or an
arbitrary writable path. Do not repurpose another process to run the probe.

Use a separate, root-controlled scratch location for `classes.dex`, readable by
UID 1000 and inaccessible to untrusted writers. A root controller must launch a
dedicated `app_process`; its first Android operations set this process's GID and
UID to 1000, before creating a Looper or ActivityThread. This grants broad
privilege: keep these finite tests opt-in. Do not change the provider's UID or
an existing app's identity, permissions, installation, or account data.

The controller can stage the DEX and create the directory with its existing,
reviewed root mechanism. The resulting device-side invocation is:

```sh
: "${DEVICE_DEX:?staged DEX}" "${ANDROID_USER:?paired nonzero user}" \
  "${SELECTED_PAIRED_ROOT_ID:?explicit root_id}" \
  "${OWNED_RECEIPT_DIRECTORY:?fresh private system-owned directory}" "${MODE:?text or image}"
CLASSPATH="$DEVICE_DEX" /system/bin/app_process /system/bin PhoneFileRoundtrip \
  "$ANDROID_USER" "$SELECTED_PAIRED_ROOT_ID" "$OWNED_RECEIPT_DIRECTORY" "$MODE"
```

This is a device root-shell example, not authorization to run ADB or change a
live device. Quote inputs; do not interpolate private IDs into an unquoted shell
command. Run modes sequentially with separate fresh receipt directories. Capture
framework stdout/stderr in private controller scratch. The probe's own output
contains only a fixed pass/fail result and the mode; exception messages and
resource IDs are not printed. Success requires `deletion_verified=true` and exit
code 0. Any nonzero exit requires receipt review.

The resolver acquires `IActivityManager.getContentProviderExternal` with the
explicit user, Binder token and tag, constructs the platform
`ContentProviderClient`, and calls SDK `ContentResolver.wrap(client)`. A regular
system-context resolver fails because this `app_process` has no registered app
thread. Client closure and `removeContentProviderExternalAsUser` run in `finally`,
including failures during acquisition setup. Hidden API layout changes fail
closed; review against the target OS instead of bypassing validation.

## Cleanup, rollback, and interrupted runs

Before creation, the private receipt records the selected root/document,
Download parent, MIME type, random filename, and every baseline child ID.
Immediately after creation it records the returned URI, before any write stream
opens. Normal cleanup re-lists Download, requires exactly one matching random
name/MIME with a non-baseline ID, checks any returned document ID and document
metadata, deletes that document only, and verifies a fresh completed listing
contains neither its ID nor name. The receipt records the actual thumbnail
center pixel when image verification succeeds. Each listing is capped at 10,000 rows and
24 loading polls. Accounts and pre-existing files are preserved.

The receipt contains private phone/resource IDs. Keep it outside the public
checkout, issue attachments, and shared logs. Preserve it until cleanup is
verified. If creation loses its response, cleanup can identify the file by the
saved random name, MIME, selected parent and baseline. If listing, validation,
receipt persistence, or deletion fails, the process fails and may leave its file
for review. It never guesses another file to delete.

A crash, controller timeout, killed process, or disconnected phone can prevent
`finally` cleanup. There is no automatic recovery mode. Do not rerun with a used
directory or delete its receipt to bypass the guard. The root controller must:

1. Stop and verify only the recorded task-owned process, if it still runs. A
   loading poll limit does not bound a stalled Binder call or stream operation.
2. Read the private receipt and, if present, its `.next` file. Preserve both;
   `.next` can contain the newer URI. A `planned` receipt still contains recovery
   evidence for a create whose response was lost.
3. Reacquire the same external provider for the recorded nonzero user. Re-match
   the explicit `root_id`, its recorded root document, and direct Download
   parent. Validate the receipt against the controller's recorded inputs.
4. Re-list that parent. Require exactly one row with the recorded random name
   and MIME, an ID absent from **all** baseline IDs, and equality to the recorded
   created/cleanup document ID when available. Require matching document metadata
   and the same user-qualified authority. If any evidence disagrees, preserve
   the file and receipt for owner review. Never delete by filename alone.
5. Delete only that verified document through `DocumentsContract.deleteDocument`
   using the externally acquired resolver. Verify a new completed listing has
   neither its ID nor name, then release the client and external provider token.
   If already absent, record that evidence without touching other files.
6. Preserve the needed private verification evidence. Remove only this task's
   staged DEX, controller logs, and receipt directory after verifying ownership
   and remote cleanup. Remove local intermediate classes, DEX, and temporary
   files when no longer needed, using the owning task's cleanup lifecycle.

Rollback consists of this one-file cleanup and removal of task-owned scratch.
There is no app installation, persistent service, account change, or OS change
to roll back. Retain requested class/DEX/verification receipts only for the
owner's optional verification; report their exact external location and size.
