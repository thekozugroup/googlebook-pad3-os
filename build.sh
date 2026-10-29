#!/bin/bash
# Build locally inside one tracked scratch directory; never flash a device.
set -euo pipefail
[[ $# == 1 ]] || { echo "Usage: bash build.sh /private/tmp/ai-development/CLEANOS_TASK" >&2; exit 2; }
WORK=$(cd "$1" && pwd -P)
case "$WORK" in /private/tmp/ai-development/*) ;; *) echo 'Use a CleanOS task scratch directory.' >&2; exit 2;; esac
[[ -f "$WORK/.cleanos-task.json" ]] || { echo 'Missing task ownership manifest.' >&2; exit 2; }
SOURCE=$(cd "$(dirname "$0")" && pwd -P)
case "$SOURCE" in "$HOME"/Developer/*) ;; *) echo 'Keep source in a verified local Developer folder.' >&2; exit 2;; esac
for tool in python3 curl payload-dumper-go mkfs.erofs dump.erofs fsck.erofs; do
    command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 2; }
done
[[ -x /opt/homebrew/opt/e2fsprogs/sbin/debugfs ]] || { echo 'Install native e2fsprogs first.' >&2; exit 2; }
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$WORK/python-tmp"
export TMPDIR="$WORK/python-tmp"
cd "$SOURCE"
python3 -m unittest test_build_dsu_diagnostic test_cold_build_dsu test_port_changes test_prepare_inputs
python3 cold_build_dsu.py --work "$WORK"
echo "Cold V9 build complete: $WORK/diagnostic/Googlebook-erhai-dsu-diagnostic-v2.zip"
