#!/usr/bin/env python3
"""Build the stat-only arm64 init daemon offline with the shared NDK; never install it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from build_native_rom import scratch_output

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "components/taskmanager-compat/native"
NDK_VERSION = "30.0.16248370"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def find_ndk(explicit=None):
    sdk = Path(os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
               or Path.home() / "Library/Android/sdk")
    path = Path(explicit or os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
                or sdk / "ndk" / NDK_VERSION).expanduser().resolve()
    properties = path / "source.properties"
    if not properties.is_file() or not re.search(r"^Pkg.Revision\s*=\s*" + re.escape(NDK_VERSION) + r"\s*$",
                                                properties.read_text(), re.M):
        raise ValueError("Shared Android NDK " + NDK_VERSION + " is required; pass --ndk. No download is performed.")
    compilers = list(path.glob("toolchains/llvm/prebuilt/*/bin/aarch64-linux-android35-clang"))
    if len(compilers) != 1:
        raise ValueError("Expected one installed NDK host toolchain")
    return path, compilers[0]


def build(ndk, output):
    ndk, compiler = find_ndk(ndk)
    output = scratch_output(output)
    output.mkdir(parents=True)
    binary = output / "googlebook_taskmanager_metrics"
    sources = {str(p.relative_to(ROOT)): digest(p) for p in
               [SOURCE / "main.c", SOURCE / "metrics.c", SOURCE / "metrics.h"]}
    try:
        with tempfile.TemporaryDirectory(prefix="compiler-", dir=output) as temp:
            environment = dict(os.environ, TMPDIR=temp)
            command = [str(compiler), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                       "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-fPIE", "-pie",
                       "-Wl,--as-needed,-z,relro,-z,now,-z,noexecstack,-z,max-page-size=16384", "-Wl,--build-id=sha1",
                       str(SOURCE / "main.c"), str(SOURCE / "metrics.c"), "-o", str(binary)]
            subprocess.run(command, env=environment, check=True, timeout=60, capture_output=True, text=True)
            elf = subprocess.check_output([str(compiler.parent / "llvm-readelf"), "-h", "-l", "-d", str(binary)],
                                          text=True, timeout=15)
        if "AArch64" not in elf or not re.search(r"Type:\s+DYN", elf):
            raise ValueError("Expected arm64 PIE")
        needed = re.findall(r"\(NEEDED\).*?\[(.*?)\]", elf)
        if needed != ["libc.so"]:
            raise ValueError("Unexpected native dependencies: " + repr(needed))
        if any(digest(ROOT / name) != sha for name, sha in sources.items()):
            raise ValueError("Source changed during compilation")
        report = {"status": "BUILT_NOT_INSTALLED", "ndk_version": NDK_VERSION,
                  "ndk_path": str(ndk), "host_toolchain": compiler.parent.parent.name,
                  "compiler_sha256": digest(compiler.resolve()), "source_sha256": sources,
                  "abi": "arm64-v8a", "api": 35, "needed": needed,
                  "binary": {"path": str(binary), "bytes": binary.stat().st_size, "sha256": digest(binary)},
                  "runtime_verified": False}
        (output / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
        return report
    except BaseException:
        shutil.rmtree(output)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path)
    parser.add_argument("--output", required=True, type=Path, help="New directory inside active owned CleanOS scratch")
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.ndk, args.output), indent=2))
    except subprocess.CalledProcessError as error:
        raise SystemExit((error.stdout or "") + (error.stderr or ""))
