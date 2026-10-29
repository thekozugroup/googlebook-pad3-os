# Task Manager shared-client fallback

This offline builder grafts the constructor and four metrics methods in the exact
GoogleBook client JAR. It keeps every original class, public declaration, DTO and
untouched method. The Google-signed Task Manager APK is not an input to the
transform and is not modified.

Original JAR SHA-256:
`5e4d4c6336e18a3228b4ac4960ea5ecddcc556865d530db7a7094903f62695ba`.
The audited client is Task Manager `1.0.943140883` / versionCode `2`.

The constructor initializes its original fields, then sets one private per-instance
flag. Local mode requires the exact application package
`com.google.android.factory.taskmanager`, the existing system appId in the current
user, a matching context UID, and `NameNotFoundException` from the explicit vendor
service lookup. Disabled and uninstalled components are included in the lookup;
their presence does not enable fallback. Other packages return to the original
constructor without the service lookup. Security exceptions are not caught.

Local metrics use cumulative `/proc/stat` counters, per-PID `stat` counters, actual
CPU topology/frequency files, and ActivityManager PSS in KiB. Clock ticks are
converted to the original client's 10-ms unit using actual `_SC_CLK_TCK`.
Missing PID files are checked against ActivityManager: an apparently live but
hidden PID fails explicitly. PSS sampling also checks PID starttime before and
after the request. A genuinely exited PID uses the original `-1` PSS sentinel;
inaccessible live data never becomes successful zero metrics. Zero current
frequency is used only for a CPU explicitly reported offline. The original
four-int topology DTO legitimately omits optional cpuidle telemetry.

## Build and test

Reuse an active owned CleanOS task rooted in `/private/tmp/ai-development`, with
this repository recorded as its project and backup copying excluded. Put the
verified original JAR there. No tool installation or network access is needed.

```sh
python3 patch_taskmanager.py \
  --input /absolute/owned-scratch/vendor.google.libraries.desktop.serviceability.jar \
  --scratch /private/tmp/ai-development/ACTIVE-TASK-ID
```

The default outputs are the single retained candidate and its verification receipt
in `components/taskmanager-compat/candidate/`. Existing outputs are never
overwritten. To rebuild or compare, pass `--output` pointing inside the same owned
scratch. The candidate directory is ignored by Git and must not be published.

```sh
TASKMANAGER_INPUT_JAR=/absolute/owned-scratch/vendor.google.libraries.desktop.serviceability.jar \
TASKMANAGER_TEST_SCRATCH=/private/tmp/ai-development/ACTIVE-TASK-ID \
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_patch_taskmanager
```

Ordinary repository discovery skips this integration class when these two inputs
are absent. The recorded candidate checks run the full class with both inputs set.

The installed JDK, SDK 36 and pinned JADX 1.5.6 fat JAR provide javac, D8 and
`com.android.tools.smali.dexlib2`. Compiler outputs, Java temporary files, fixtures,
DEX files and disassembly all use disposable subdirectories of that task root and
are removed after each build. The builder verifies the original input hash before
compiling, inserts structured dexlib2 instructions, and reserializes with DexPool.
It does not rename classes or edit DEX strings. Compile-only DTO stubs are excluded
from the production DEX; the helper's references resolve against original public
DTO declarations.

Verification compares all other class disassemblies exactly. In the five targets,
it removes only the specified guard instructions and compares original
instructions, branch targets, try ranges and debug locations. Method sets,
declarations, annotations, parameters, registers and all fields remain unchanged
except for the one private flag. Identifier order and DEX SHA-1/Adler-32 are checked.
Tests reject input drift, already-patched input, identifier reordering, guard or
ABI corruption, unrelated changes and unsafe output paths; independent rebuilds
must be byte-identical.

## Parent integration limits

The candidate is not installed or ART-verified. Parent must confirm the actual
shared-library classloader and Task Manager's existing proc/sysfs/PSS authority,
including user 10 and user switching. No new privilege, policy bypass, shell/root
process or writer operation is supplied. Strict topology/frequency reads can fail
when a tablet driver does not expose the required files; that is a failure to fix
with real evidence, not a reason to substitute numbers.

The original client JAR has an 8,192-byte `.fsv_meta` sidecar. Parent must handle
matching verity metadata, dexpreopt and image integrity through its normal build
process. This builder creates only the client JAR candidate and a receipt.

ActivityManager may legitimately return cached PSS. PID generation is checked
around PSS, but the unchanged CPU DTO cannot communicate a PID epoch to the app's
existing inter-sample baseline. Process enumeration, total-memory display and
selected-package force-stop stay in the signed app. A crash-free UI is insufficient:
compare genuine changing CPU, per-process CPU, PSS and real thread count.
