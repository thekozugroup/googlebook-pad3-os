# TaskManager per-PID stat provider

This replaces only the unavailable privileged per-PID stat backend. The existing
app identity can enumerate Chrome and SukiSU through ActivityManager, but hidepid
hides their stat files from its UID. No `READ_CPU_USAGE` permission exists on this
build. The daemon runs as UID/GID system (1000), with supplemental readproc (3009),
and refuses startup with any effective, permitted or inheritable capability or
additional group. It sets no-new-privileges and disables its own dumpability.

Only `/proc/<positive int32 PID>/stat` can be opened. The proc root is fixed in
`main.c`; numeric directory and final stat opens use `openat` and `O_NOFOLLOW`.
Nonregular files and records reaching 4096 bytes are rejected. The parser handles
parentheses/newlines in comm and returns only actual unsigned user/system/start
ticks (fields 14, 15, 22), bounded to Java's nonnegative signed-long range.
There are no commands, arbitrary paths, writes, enumeration, PSS, logging of proc
content, Internet sockets, capabilities, ptrace or counter substitutions.

## Wire contract

All integers are big endian; no native structs or variable-length payloads.
One connection carries exactly one request. Client half-closes its write side;
server sends one reply and closes. Extra or truncated requests are closed.

| Message | Fields |
| --- | --- |
| Request: 12 bytes | u32 magic `0x47544d31` (`GTM1`), u32 operation `1`, u32 PID |
| Reply: 40 bytes | u32 magic, u32 status, u32 echoed PID, u32 reserved `0`, u64 userTicks, u64 systemTicks, u64 startTicks |

Statuses: `0` success, `1` ENOENT/ESRCH, `2` EACCES/EPERM, `3` bad request,
`4` unavailable/malformed/oversized stat. Failed replies have no valid counters;
Java throws, rather than returning their zero-filled fields. A missing PID still
needs the existing ActivityManager liveness check: an inaccessible live PID must
not be treated as exited. No retry conceals a real failure.

The server checks Linux `SO_PEERCRED` before reading any request, allowing only
`uid % 100000 == 1000`, including secondary users. Root, shell and regular app
UIDs are rejected. Java checks the server's exact UID is 1000. The init socket
uses mode 0666 because user10's UID is 1001000 and has no group system; SELinux
allows only system_app to connect, in addition to the kernel peer UID check.
One sequential worker, backlog 8, and an absolute 500-ms transaction deadline
bound connection work. Java uses nonblocking I/O and a 1000-ms absolute deadline.
Nonblocking AF_UNIX connect fails immediately on an unavailable/full listener.

## Parent integration

No existing source, JAR, APK, image, manifest or device has been changed here.

1. Install the built arm64 PIE at `/system_ext/bin/googlebook_taskmanager_metrics`,
   root:root 0755, without file capabilities. Install the supplied RC at
   `/system_ext/etc/init/googlebook_taskmanager_metrics.rc`, root:root 0644.
   Keep `socket ... stream`, with no `+listen` or explicit socket seclabel. The
   daemon must call listen as UID1000 so client peer credentials identify it,
   rather than init. [AOSP init socket contract](https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/README.md).
2. Append `taskmanager_metrics.cil` to system_ext policy. Merge the two supplied
   `file_contexts` entries into the active platform context lookup and label the
   executable accordingly. Merely placing this fragment next to the binary does
   not activate it. Recompute the existing system_ext CIL+mapping hash and rerun
   `check_policy.check` against the final combined policy, including parent engine
   changes. Do not substitute an earlier baseline hash.
3. The dedicated coredomain needs appdomain **file read/open/getattr** and directory
   search: per-PID proc files use their process label, not a separate stat type.
   ActivityManager also lists system_server; the same exact read/search rules
   cover that concrete type. Linux PID directories use O_PATH handles, so the
   service never requests directory enumeration. The Android kernel fixture
   verifies this path separately from the Mac host tests.
   Existing MLS read constraints also require this daemon's `mlstrustedsubject`
   attribute for app categories across users. This is confined to the daemon;
   TaskManager gains only socket connect access. The policy grants neither generic
   proc file access nor domain-wide file reads, ptrace, capabilities or Internet
   sockets. The C path restriction supplies the stat-only boundary that SELinux's
   shared per-process labels cannot express. Its trust requirement must remain
   visible in review. [AOSP read-only proc consumer](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/storaged.te).
4. Expand the parent's `TASKMANAGER_SOURCES`, javac/D8 inputs, helper-class graft
   selection and helper integrity checks to include `NativeProcStats` (and any
   generated inner classes). Compile/graft it alongside `TaskManagerCompat`. Parent changes
   the existing `process(Path,int)` real-proc branch to call
   `NativeProcStats.read(pid)` only for its exact canonical `/proc` path. Preserve
   the fixture parser and all live-PID/starttime assertions. This also routes
   existing PSS identity checks through the stat provider; **PSS values stay in
   ActivityManager**. Aggregate CPU and CPU topology stay unchanged. Preserve the
   package/context/appId identity gate and graft integrity checks.

## Offline build and tests

Use an active owned CleanOS task for all generated output. No installs/downloads
are performed. The builder accepts `--ndk`, then `ANDROID_NDK_HOME`/
`ANDROID_NDK_ROOT`, then `ANDROID_SDK_ROOT`/`ANDROID_HOME` or the home-relative SDK.
It detects the installed host subdirectory. NDK 30.0.16248370 is pinned; arm64 API35
PIE requires only the existing libc.so. Output must be a new owned scratch path.

```sh
python3 build_taskmanager_metrics.py --ndk "$NDK" --output "$TASKROOT/metrics-build"

NATIVE=components/taskmanager-compat/native
cc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer "$NATIVE/metrics.c" "$NATIVE/host_tests.c" -o "$TASKROOT/host-tests"
mkdir "$TASKROOT/fixtures"
"$TASKROOT/host-tests" "$TASKROOT/fixtures" "$TASKROOT/golden-response.bin"

SRC=components/taskmanager-compat
PACKAGE=vendor/google/libraries/desktop/serviceability
mkdir "$TASKROOT/classes"
"$JAVA_HOME/bin/javac" --release 8 -classpath "$SDK/platforms/android-36/android.jar" \
  -d "$TASKROOT/classes" "$SRC/compile-api/$PACKAGE/ServiceabilityManager.java" \
  "$SRC/src/$PACKAGE/TaskManagerCompat.java" "$SRC/src/$PACKAGE/NativeProcStats.java" \
  "$NATIVE/NativeProcStatsSelfTest.java"
"$JAVA_HOME/bin/java" -Djava.io.tmpdir="$TASKROOT" \
  -classpath "$TASKROOT/classes:$SDK/platforms/android-36/android.jar" \
  vendor.google.libraries.desktop.serviceability.NativeProcStatsSelfTest "$TASKROOT/golden-response.bin"
```

Host tests exercise the actual C socket handler with simulated Android peer UIDs,
the host's real peer-credential query, parser/error bounds, PID path symlink/FIFO
rejection, framing, and timeout. Java independently checks the C-generated reply
and error/identity semantics. Host fixtures are not Android runtime proof.

Parent runtime gates remain: correct init domain/UID/groups/CapEff0; actual socket
file label and server peer UID1000; rejected non-system-app callers; real counters
for live Chrome/SukiSU PIDs, matching starttime and changing process CPU; enforcing
with no relevant AVCs; visible rows after graft and boot. PSS is a separate parent
check. No runtime pass is claimed here.
