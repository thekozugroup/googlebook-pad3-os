#!/bin/bash
# Native Apple Silicon secilc from unmodified AOSP Android 17 sources.
set -euo pipefail

REV=a8c5e74f85f869bf236a01ba24181b78f5e39a52
SOURCE=https://android.googlesource.com/platform/external/selinux
usage() { echo "Usage: $0 /tmp/ai-development/TASK/secilc-tools"; }
die() { echo "$*" >&2; exit 1; }
if [[ $# == 1 && $1 == --help ]]; then usage; exit 0; fi
[[ $# == 1 ]] || { usage >&2; exit 1; }
ROOT=${1%/}
case "$ROOT" in /tmp/*) ROOT=/private$ROOT ;; esac
case "$ROOT" in
    /private/tmp/ai-development/*/secilc-tools) ;;
    *) die 'Work directory must be inside a task under /tmp/ai-development and end in /secilc-tools.' ;;
esac
case "$ROOT/" in *'/../'*|*'/./'*|*'//'*) die 'Refusing noncanonical path components.' ;; esac
PARENT=${ROOT%/*}
[[ -d "$PARENT" && $(cd "$PARENT" && pwd -P) == "$PARENT" ]] || die 'Task directory must exist without symlink components.'
[[ ! -L "$ROOT" && ( ! -e "$ROOT" || -d "$ROOT" ) ]] || die 'Refusing symlink or non-directory work root.'
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || {
    echo 'Requires native macOS ARM64.' >&2; exit 1;
}
mkdir -p "$ROOT"
ROOT=$(cd "$ROOT" && pwd -P)
MARKER="$ROOT/owned-resources.json"
shopt -s nullglob dotglob
entries=("$ROOT"/*)
shopt -u nullglob dotglob
if (( ${#entries[@]} )); then
    [[ -f "$MARKER" && ! -L "$MARKER" ]] || die 'Refusing nonempty foreign work root: ownership marker missing.'
    [[ $(/usr/bin/plutil -extract owner raw -o - "$MARKER") == 'native secilc compiler sidecar' &&
       $(/usr/bin/plutil -extract root raw -o - "$MARKER") == "$ROOT" ]] || die 'Work root ownership marker does not match.'
else
    python3 - "$MARKER" "$ROOT" <<'PY'
import json
import sys
with open(sys.argv[1], "x") as marker:
    json.dump({"owner": "native secilc compiler sidecar", "root": sys.argv[2]}, marker)
PY
fi
[[ -z $(/usr/bin/find "$ROOT" -type l -print -quit) ]] || die 'Refusing symlinks inside compiler work root.'
if [[ -x "$ROOT/bin/secilc" && -f "$ROOT/provenance.txt" ]] &&
   grep -Fxq "source=$SOURCE" "$ROOT/provenance.txt" &&
   grep -Fxq "revision=$REV" "$ROOT/provenance.txt" &&
   grep -Fxq "$(/usr/bin/shasum -a 256 "$ROOT/bin/secilc")" "$ROOT/provenance.txt" &&
   /usr/bin/file "$ROOT/bin/secilc" | grep -q 'Mach-O 64-bit executable arm64'; then
    echo "Reusing verified compiler: $ROOT/bin/secilc"
    exit 0
fi
created_dirs=()
BIN_NEW=
cleanup() {
    [[ -d "$ROOT" && ! -L "$ROOT" && $(cd "$ROOT" && pwd -P) == "$ROOT" ]] || return 0
    local dir
    if (( ${#created_dirs[@]} )); then
        for dir in "${created_dirs[@]}"; do rm -rf "$dir"; done
    fi
    [[ -z "$BIN_NEW" ]] || rm -f "$BIN_NEW"
}
trap cleanup EXIT
for dir in downloads src stage tmp; do
    mkdir "$ROOT/$dir" || die "Refusing existing build directory: $ROOT/$dir"
    created_dirs+=("$ROOT/$dir")
done
mkdir -p "$ROOT"/{src/libsepol,src/secilc,bin,checks}
BIN_NEW=$(mktemp "$ROOT/bin/.secilc.XXXXXX")
export TMPDIR="$ROOT/tmp"

fetch_source() {
    local name=$1 archive="$ROOT/downloads/$1.tar.gz"
    if [[ ! -f "$archive" ]]; then
        /usr/bin/curl --fail --location --retry 2 \
            "$SOURCE/+archive/$REV/$name.tar.gz" -o "$archive.part"
        mv "$archive.part" "$archive"
    fi
    /usr/bin/tar -xzf "$archive" -C "$ROOT/src/$name"
}
fetch_source libsepol
fetch_source secilc
# Gitiles archive metadata varies; verify complete paths, modes, and file contents.
/usr/bin/git init -q "$ROOT/src"
/usr/bin/git -C "$ROOT/src" -c core.autocrlf=false -c core.filemode=true \
    -c core.attributesfile=/dev/null add -f -- libsepol secilc
TREE=$(/usr/bin/git -C "$ROOT/src" write-tree)
[[ $(/usr/bin/git -C "$ROOT/src" rev-parse "$TREE:libsepol") == 5bceeeff34731ecc7d9b900e88e2e3e73f20ccc7 ]]
[[ $(/usr/bin/git -C "$ROOT/src" rev-parse "$TREE:secilc") == a563428e92c0867df968aeff98bdf684faa59f8a ]]

{
    /usr/bin/clang --version
    /usr/bin/make -j2 -C "$ROOT/src/libsepol/src" \
        CC=/usr/bin/clang AR=/usr/bin/ar RANLIB=/usr/bin/ranlib \
        CFLAGS='-O2 -arch arm64' libsepol.a
    /usr/bin/make -j2 -C "$ROOT/src/libsepol/include" PREFIX="$ROOT/stage" install
    /usr/bin/clang -O2 -arch arm64 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
        -I"$ROOT/stage/include" "$ROOT/src/secilc/secilc.c" \
        "$ROOT/src/libsepol/src/libsepol.a" -o "$BIN_NEW"
} > "$ROOT/build.log" 2>&1 || {
    tail -40 "$ROOT/build.log" >&2; exit 1;
}

cat > "$ROOT/checks/valid.cil" <<'CIL'
(handleunknown deny)
(class file (read write))
(classorder (file))
(sid kernel)
(sidorder (kernel))
(user system_u)
(role system_r)
(type kernel_t)
(roletype system_r kernel_t)
(userrole system_u system_r)
(sensitivity s0)
(sensitivityorder (s0))
(level systemlow (s0))
(levelrange systemlow_range (systemlow systemlow))
(userlevel system_u systemlow)
(userrange system_u systemlow_range)
(context kernel_context (system_u system_r kernel_t systemlow_range))
(sidcontext kernel kernel_context)
(allow kernel_t self (file (read)))
(policycap functionfs_seclabel)
(policycap memfd_class)
CIL
cp "$ROOT/checks/valid.cil" "$ROOT/checks/invalid.cil"
printf '(neverallow kernel_t self (file (read)))\n' >> "$ROOT/checks/invalid.cil"
rm -f "$ROOT/checks/valid.policy" "$ROOT/checks/invalid.policy"
{
    /usr/bin/file "$BIN_NEW" | grep 'Mach-O 64-bit executable arm64'
    /usr/bin/otool -L "$BIN_NEW"
    help_rc=0
    "$BIN_NEW" --help > "$ROOT/checks/help.txt" || help_rc=$?
    # AOSP usage() exits 1, including for --help; there is no --version option.
    [[ $help_rc == 1 ]]
    grep -q 'Usage:' "$ROOT/checks/help.txt"
    "$BIN_NEW" -M true -c 30 -o "$ROOT/checks/valid.policy" \
        -f "$ROOT/checks/file_contexts" "$ROOT/checks/valid.cil" \
        > "$ROOT/checks/valid.log" 2>&1
    [[ -s "$ROOT/checks/valid.policy" ]]
    if "$BIN_NEW" -M true -c 30 -o "$ROOT/checks/invalid.policy" \
        -f "$ROOT/checks/invalid.file_contexts" "$ROOT/checks/invalid.cil" \
        > "$ROOT/checks/invalid.log" 2>&1; then
        echo 'ERROR: conflicting neverallow policy accepted.' >&2; exit 1
    fi
    grep 'neverallow check failed' "$ROOT/checks/invalid.log"
    [[ ! -e "$ROOT/checks/invalid.policy" ]]
    echo 'PASS: ARM64, help, Android 17 capabilities, valid CIL, invalid CIL rejection.'
} > "$ROOT/verify.log" 2>&1 || {
    cat "$ROOT/verify.log" >&2; exit 1;
}
mv "$BIN_NEW" "$ROOT/bin/secilc"
{
    printf 'source=%s\nrevision=%s\nlibsepol_version=' "$SOURCE" "$REV"
    cat "$ROOT/src/libsepol/VERSION"
    printf 'libsepol_tree=5bceeeff34731ecc7d9b900e88e2e3e73f20ccc7\n'
    printf 'secilc_tree=a563428e92c0867df968aeff98bdf684faa59f8a\n'
    /usr/bin/shasum -a 256 "$ROOT/downloads/"*.tar.gz
    /usr/bin/shasum -a 256 "$ROOT/bin/secilc"
} > "$ROOT/provenance.txt"
cat "$ROOT/verify.log" "$ROOT/provenance.txt"
