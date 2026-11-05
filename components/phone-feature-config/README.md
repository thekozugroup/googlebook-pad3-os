# Anonymous phone feature configuration

This one-shot helper stages an explicitly selected profile through the installed,
unchanged GMS Phenotype implementation and publishes its native snapshot. Both
profiles use the anonymous Phenotype account, source 0, and integer boolean values.
It does not enable a debug service, poll, edit committed configuration pointers,
or change registrations, other accounts, or existing wildcard overrides.

| Profile | Exact configuration namespace | Registered Android owner | Flags set true |
| --- | --- | --- | --- |
| `ambient` | `com.google.ambient.streaming#com.google.ambient.streaming` | `com.google.ambient.streaming` | `45788784`, `45726908`, `45794909`, `45805241` |
| `receiver-settings` | `com.google.android.gms.multidevice#com.google.android.gms` | `com.google.android.gms` | `45742359`, `45784133` |

The Ambient profile preserves the original four-flag mapping. The receiver profile
carries both the Continue activity category entry (`45742359`) and basic
notification switch (`45784133`). Its existing entry was a manual snapshot
metadata override plus an unlinked wildcard database row; publishing only the
notification flag would lose that category entry. The native publisher must
therefore carry both profile flags together.

Neither profile enables diagnostic `45811904`, notification subpage `45815974`,
role-1 AppCast/handoff/file-access row gates, DND, or clipboard flags. The profile
only selects these exact flag IDs; unrelated existing values are preserved.
The receiver's desktop role 2 is correct. This component changes no role,
desktop feature, transport preference, or native permission. Basic-switch
visibility does not establish notification transport or permission readiness.

The maintainer's Ambient path passed rollback rehearsal, native anonymous
source-0 publication, the installed parser's four-flag check, and a publish-only
run whose exact leaf label matched the DB without restorecon. The real client
committed the configuration and retained it overnight and through a cold app
restart. The source `receiver-settings` profile is also deployed with both flags;
Continue activity shows the native enabled Notifications switch. An actual off/on
test passed and restored its original on state. Tablet role 2 is preserved;
source-only controls remain on the phone.

Separate native chooser, AV1 AppCast video and remote `7+5=12` checks passed,
including cold-launch `5+6=11`, without an explicit diagnostic service start.
Private native10 embeds this helper in System update and was installed through
the A/B updater without a reset. Its automatic startup check passed two OS
reboots before opening the updater; read-only inspection confirmed the original
four Ambient and two receiver state links, with accounts, apps, root and SELinux
enforcing preserved. Fresh server sync and future GMS/module versions remain
unqualified. The public update feed has not been promoted to native10. Separate native Chrome task handoff passed
through task advertisement, request, phone result and exact local URL restoration.
Handoff requires opt-in apps; arbitrary apps remain unqualified. See
[phone integration](../../GOOGLE_SERVICES.md) for the bounded pass and
rooted-module trust limits.

## Supported input

Both the builder and runtime require this exact GMS base APK digest:

```
8395c70a5e4ffbe2712aea7e1045d700b282f0a67d19b80686c595c991f12112
```

Runtime also requires GMS version code **264330035** and Phenotype schema **1036**.
Changed versions fail closed and require source review. No GMS APK, DEX, native
library, decompiled implementation, registered secret, or device capture is
included here. The runtime loads the device's own installed classes.

## Offline build

Use Python 3.11+, an installed JDK 21, Android SDK platform `android.jar`, and D8.
The reviewed build used platform 37.2 and build-tools 36.0.0. No dependency
installation, Gradle build, device connection, or SDK copy is needed.

Create an owned external task using the repository's `MAINTAINING.md` procedure:
CleanOS on macOS, `maintenance_workspace.py init` on Linux. The builder reuses
`maintenance_workspace.local_path` and `task_root`, including the macOS backup
exclusion check. `TASK_SCRATCH` must be its canonical physical path. The output
child must not exist and must be outside source and cloud-sync roots.

```sh
python3 -B components/phone-feature-config/build.py \
  --gms-base "$PRIVATE_INPUT/gms-base.apk" \
  --java-home "$JAVA_HOME" \
  --android-jar "$ANDROID_JAR" \
  --d8 "$D8" \
  --scratch "$TASK_SCRATCH/config-profiles-review"
```

The external output contains `classes.dex`, `validation.json`, and `build.log`.
The receipt records the DEX, source, and tool hashes and explicitly records that
device deployment and SELinux qualification have not occurred. Compiler classes,
host-test files, and temporary DEX directories are removed after success. On a
failed build, retain the owned output only while diagnosing it; never overwrite
an existing output directory. Remove only that task's verified disposable files
after preserving the requested result. All JVMs use bounded heaps and two active
processors. Host tests execute no Android device or native GMS operations.

## Controller interface

The class entry point takes exactly four positional arguments:

```
NativeConfigRepair ANDROID_USER ACTUAL_GMS_UID PROFILE MODE
```

The parent may compile this default-package class and its `UserContext` class
directly into the built-in updater APK. No helper code depends on a separate
DEX file or its path. The root controller can launch the embedded entry point as:

```sh
CLASSPATH="$ACTUAL_PINNED_GMS_BASE:$CANONICAL_BUILTIN_UPDATER_APK" \
  /system/bin/app_process /system/bin NativeConfigRepair \
  "$ANDROID_USER" "$ACTUAL_GMS_UID" ambient ensure
```

Run `receiver-settings ensure` separately with the same verified identity.
The parent owns canonical APK selection, launch context, timeout and boot/OTA
scheduling. The helper independently retains its installed GMS/context guards.
`main` explicitly calls `System.exit(0)` after completion or `System.exit(1)` on
failure; it does not rely on returning from an `app_process` main method. The
standalone offline DEX recipe above remains an optional build/host-check route.

The controller supplies the actual installed GMS UID for the explicitly selected
Android user. The helper drops its own GID/UID before Looper or framework
initialization, then creates the real user-specific GMS package context. It checks
that the context's application UID matches its actual process UID and supplied
UID, and validates the exact credential-encrypted database path. It initializes
the installed `hjmc.d` source using the tested application-context wrapper.

Android user **10** is the runtime-tested user. Other explicitly selected
secondary users are unqualified and still require every pin and context check.
User 0, root/system/isolated application IDs, mismatched user/UID pairs, missing
arguments, unknown profiles, and unknown modes are rejected before changing the
process identity. There is no default Android user, no implicit profile, and no
embedded device UID. Android users and Phenotype account 0 are separate.

For repeated controller invocations select `ambient ensure` and
`receiver-settings ensure` separately. These are the last two arguments, after
the explicit Android user and actual GMS UID. Each invocation validates only its
selected profile. An unstaged profile can still use `rehearse` for rollback
review before its first persistent staging.

- `rehearse`: execute the selected profile's native transaction, validate its scope and
  effective values, then roll back and require unchanged state/override hashes.
- `stage-publish`: require no existing active anonymous overrides in scope,
  stage its flags through `fyvs.a`, validate old tables and pointers, commit,
  and publish through `fyxs.b/c`. The SQLite booleans must be INTEGER 1, not text.
- `publish`: validate already staged effective values and rebuild the snapshot
  without staging another transaction.
- `ensure`: in a native write transaction, inspect active anonymous overrides
  for the selected exact flag names. With none present, use the same guarded
  native staging and commit as `stage-publish`. With a complete profile, require
  exactly one active row per flag, type 2, source 0 and SQLite INTEGER 1, then
  validate the selected native state's effective values without calling the
  setter or committing a new state. Partial profiles, duplicate rows, wrong
  types/values/sources and missing effective links fail closed. Recheck the
  scoped rows and effective values in the publication read transaction before
  using the existing native writer. Repeated valid invocations republish the
  snapshot without adding overrides or states. Inactive historical rows,
  wildcard rows, other names, namespaces and accounts remain outside this check.

`NATIVE_PROFILE_STAGE_COMMITTED flags=N` is emitted only after successful
transaction close, when a newly staged profile has actually committed.
`NATIVE_PROFILE_ALREADY_STAGED flags=N` means an existing profile passed the
transaction checks without staging. Neither marker establishes publication
success. Errors still exit 1 with the exception class; completed calls exit 0.
`ensure` is a bounded synchronous operation. This component adds no boot/OTA
trigger, receiver, service or scheduling; the parent controller owns invocation.

The helper validates foreign keys, the selected profile's registered config owner
and secret existence in every mode,
existing anonymous state, unchanged registrations/accounts/config pointers/old
override rows, scoped new rows, and native effective flag contents. Preflight and
insert checks bind the selected profile's exact flag names as SQL parameters;
insert counts must equal its flag count (four or two). The metadata request,
snapshot lookup, effective-value check, native staging and publication owner all
use that same selected profile. It does not
print secrets or SELinux labels. Native implementation failures are reported by
exception class without printing private exception messages or stack traces.

The build recipe performs no device installation or invocation. The controller
owns transfer, the existing root launcher and SELinux process context, execution,
rollback evidence, and live verification. It must not treat a fabricated context
or package-name string as the real GMS identity.

## Publication file context

The tested launcher retained its root SELinux process context after changing UID.
Its newly created snapshot leaf lacked GMS's MCS categories until the controller
restored that exact leaf's label. The source now reflects
`android.os.SELinux.getFileContext(databasePath)` and
`setFSCreateContext(String)`, whose Java declarations and JNI registration exist
in [AOSP SELinux.java](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/SELinux.java)
and [android_os_SELinux.cpp](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/jni/android_os_SELinux.cpp).
These are hidden platform APIs, not public SDK guarantees.

Immediately around synchronous `writer.c()` only, the helper requires an existing
GMS `privapp_data_file` object label containing MCS categories, applies that exact
database label as the calling thread's file-creation context, and checks the
returned boolean. It always attempts to reset the context to null in `finally`
and checks that boolean too. A writer failure remains an error; a simultaneous
reset failure is attached as a suppressed error. Missing APIs, invalid labels,
rejected context setup, and failed reset all fail the helper. There is no silent
unlabelled publication fallback and no global SELinux or permission change.

The Ambient run verified that the target policy permitted this guard
and produced the correct final label without restorecon. For each publication,
the controller must compare the exact published leaf's label with the existing
DB label without exposing either, parse the resulting snapshot with the unchanged
native parser, and verify client restart/reconnection and AppCast. Existing
mislabelled files or directories are not repaired by changing
creation context. If target API/policy validation fails, the controller must
retain its explicit exact-leaf `restorecon -F` requirement; do not claim that the
new guard protected the file. No automatic restorecon command is included.

## Remaining limits

Staging and file publication are separate phases. A publication or label failure
can occur after the database transaction committed. Preserve that status and use
`ensure` to revalidate and retry, or a reviewed publish-only retry. Repeating
`stage-publish` is deliberately rejected. `ensure` does not treat a partial or
conflicting profile as an interrupted operation that it can silently repair.
`NATIVE_PUBLISH_CALL_COMPLETED_VERIFY_SNAPSHOT_SEPARATELY` means precisely that:
the native writer can catch its own IO errors, so success requires the actual
snapshot and final-label checks. The creation-context guard also requires the
writer to remain synchronous on the calling thread in this pinned version.

The helper preserves old wildcard rows. It does not promote the anonymous flags
to other accounts, rewrite configuration tokens, or force a committed pointer.
The native client owns its genuine snapshot commit. Client commit, cold app
restart and overnight persistence passed. A legitimate fresh server sync generated
after staging and a tablet reboot still require separate qualification. An external
process does not share the resident GMS operation queue; a response captured before
staging remains a concurrency boundary for controller qualification. In this
pinned implementation refresh carries active override links from the state
captured by the request, rather than from every active override row. A pre-stage
request can therefore omit the staged links in a later state. When active rows
survive but their effective links are missing, `ensure` refuses: the native
setter deduplicates identical active rows and is not a proven link repair. No
row deletion, link reconstruction, token invention or forced commit is attempted.
Fresh replacement-state refresh, reboot and OTA invocation still need runtime
qualification; an idempotent helper alone does not establish durability. Future GMS
updates, account changes, data clearing, and full feature durability are not
qualified by the current finite tests. No broader phone-integration claim follows.
