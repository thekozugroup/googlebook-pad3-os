"""Remove the three pinned Dell APKs while preserving every other Product file."""
import argparse
from pathlib import Path

from erofs_sanitize import rewrite
from native_install.payload import require, sha256

SOURCE_SHA = "0aa9d298d39ae416f6b7ab0569b440b080ff9c63d9d79c8db80ea40519d17c6f"
TARGET_SHA = "41313b3bcd00fe8a2d4f4919f8a21feed33b35dc02f5ddbd7758eb5cdf8d86e9"
REMOVALS = frozenset({
    "/priv-app/DellDiagnosticsStub/DellDiagnosticsStub.apk",
    "/priv-app/DellRepairStub/DellRepairStub.apk",
    "/priv-app/DellSupportAssistStub/DellSupportAssistStub.apk",
})


def validate(source, target):
    require(sha256(source) == SOURCE_SHA, "Product cleanup requires the exact installed native-2 baseline")
    require(sha256(target) == TARGET_SHA, "Product cleanup target differs from the reviewed three-APK removal")


def build(source, output, scratch):
    require(sha256(source) == SOURCE_SHA, "Product cleanup requires the exact installed native-2 baseline")
    result = rewrite(source, output, set(REMOVALS), scratch)
    try:
        validate(source, output)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "scratch"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    print(build(args.source, args.output, args.scratch))
