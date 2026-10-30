"""Remove the three pinned Dell APKs while preserving every other Product file."""
import argparse
from pathlib import Path

from erofs_sanitize import rewrite
from native_install.payload import require, sha256

SOURCE_SHA = "0aa9d298d39ae416f6b7ab0569b440b080ff9c63d9d79c8db80ea40519d17c6f"
TARGET_SHA = "41313b3bcd00fe8a2d4f4919f8a21feed33b35dc02f5ddbd7758eb5cdf8d86e9"
R5_TARGET_SHA = "53e7e09eec141acd876d4fa773daeddb541684fff64f7ba2488f28d6132728bc"
R5_DIAGNOSTICS_TARGET_SHA = "d607b85a21e7f375fff46b12ecdac9986d5e614f0ea323022016675505cbd9bf"
R5_METRICS_TARGET_SHA = "72d0d40877d132377671478436ff33cb3114fa04b0357eb1c0b45f221f540f61"
REMOVALS = frozenset({
    "/priv-app/DellDiagnosticsStub/DellDiagnosticsStub.apk",
    "/priv-app/DellRepairStub/DellRepairStub.apk",
    "/priv-app/DellSupportAssistStub/DellSupportAssistStub.apk",
})


def validate(source, target):
    require(sha256(source) == SOURCE_SHA, "Product cleanup requires the exact installed native-2 baseline")
    require(sha256(target) == TARGET_SHA, "Product cleanup target differs from the reviewed three-APK removal")


def validate_release(target, source=None):
    """Accept only audited native3/4 through native7 Product and exact delta baselines."""
    target_sha = sha256(target)
    require(target_sha in {TARGET_SHA, R5_TARGET_SHA, R5_DIAGNOSTICS_TARGET_SHA, R5_METRICS_TARGET_SHA},
            "Product must contain a reviewed physical Dell APK removal")
    if source is not None:
        if target_sha == TARGET_SHA:
            validate(source, target)
        elif target_sha == R5_TARGET_SHA:
            require(sha256(source) == TARGET_SHA,
                    "R5 Product delta requires the exact installed native4 Product")
        elif target_sha == R5_DIAGNOSTICS_TARGET_SHA:
            require(sha256(source) == R5_TARGET_SHA,
                    "Diagnostics Product delta requires the exact installed native5 Product")
        else:
            require(sha256(source) == R5_DIAGNOSTICS_TARGET_SHA,
                    "Metrics Product delta requires the exact installed native6 Product")


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
