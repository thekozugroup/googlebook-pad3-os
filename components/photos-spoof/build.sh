#!/bin/sh
# Caller supplies existing tools and signing identity; no SDK/NDK installation.
set -eu
COMPONENT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
: "${1:?Pass a verified local disposable workspace outside cloud sync}"
: "${ANDROID_SDK_ROOT:?Set the existing Android SDK root}"
: "${JAVA_HOME:?Set JDK17 home}"
: "${CMAKE_HOME:?Set the existing CMake3.22.1 directory}"
: "${GRADLE_BIN:?Set the existing Gradle8.11.1 executable}"
: "${PHOTOS_DEBUG_KEYSTORE:?Set an existing debug keystore; keep its path and key private}"
WORK=$(python3 -B -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$1")
case "$WORK/" in "$COMPONENT/"*) echo 'Use a separate disposable workspace' >&2; exit 2;; esac
export ANDROID_HOME="$ANDROID_SDK_ROOT"
export ANDROID_USER_HOME="$WORK/android-user"
unset ANDROID_PREFS_ROOT
export ANDROID_AVD_HOME="$WORK/avd"
export GRADLE_USER_HOME="$WORK/gradle-user-home"
if [ -n "${PHOTOS_READ_ONLY_GRADLE_CACHE:-}" ]; then
    export GRADLE_RO_DEP_CACHE="$PHOTOS_READ_ONLY_GRADLE_CACHE"
else
    unset GRADLE_RO_DEP_CACHE
fi
export TMPDIR="$WORK/tmp"
export PHOTOS_OUTPUT_ROOT="$WORK/outputs"
export KOTLIN_DAEMON_RUN_FILES_PATH="$WORK/kotlin-daemon"
export JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$TMPDIR -XX:-UsePerfData"
for file in "$ANDROID_SDK_ROOT/ndk/30.0.16248370/source.properties" "$ANDROID_SDK_ROOT/platforms/android-36/android.jar" "$ANDROID_SDK_ROOT/build-tools/35.0.0/aapt2" "$CMAKE_HOME/bin/cmake" "$CMAKE_HOME/bin/ninja" "$JAVA_HOME/bin/java" "$GRADLE_BIN" "$PHOTOS_DEBUG_KEYSTORE"; do
    test -f "$file" || { echo "Missing supplied prerequisite: $file" >&2; exit 2; }
done
mkdir -p "$TMPDIR"
"$GRADLE_BIN" --version > "$WORK/gradle-version.txt"
grep -q '^Gradle 8.11.1$' "$WORK/gradle-version.txt" || { echo 'Gradle8.11.1 required' >&2; exit 2; }
if [ -n "${PHOTOS_SOURCE_ARCHIVE:-}" ]; then
    python3 -B "$COMPONENT/prepare.py" "$WORK" --archive "$PHOTOS_SOURCE_ARCHIVE"
else
    python3 -B "$COMPONENT/prepare.py" "$WORK"
fi
python3 -B "$COMPONENT/verify.py" "$WORK/source"
printf 'sdk.dir=%s\ncmake.dir=%s\n' "$ANDROID_SDK_ROOT" "$CMAKE_HOME" > "$WORK/source/local.properties"
set --
if [ "${PHOTOS_OFFLINE:-0}" = 1 ]; then set -- --offline; fi
cd "$WORK/source"
exec "$GRADLE_BIN" "$@" --console=plain --no-daemon --max-workers=2 \
    --project-cache-dir "$WORK/gradle-project-cache" --init-script "$COMPONENT/build-support.gradle" \
    -Dorg.gradle.jvmargs="-Xmx1536m -XX:MaxMetaspaceSize=384m -XX:-UsePerfData -Djava.io.tmpdir=$TMPDIR" \
    -Dorg.gradle.vfs.watch=false -Pandroid.builder.sdkDownload=false \
    -Pkotlin.compiler.execution.strategy=in-process -Pkotlin.project.persistent.dir="$WORK/kotlin" \
    :app:testDebugUnitTest :app:assembleDebug
