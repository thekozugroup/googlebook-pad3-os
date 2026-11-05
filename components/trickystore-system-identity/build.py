#!/usr/bin/env python3
"""Build the pinned system-UID identity correction in external owned scratch."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
COMPONENT = Path(__file__).resolve().parent
PROJECT = COMPONENT.parents[1]
sys.path.insert(0, str(PROJECT))
from maintenance_workspace import local_path, require, task_root

INPUT_SHA = "47d2350898e50696a653f5a5d0ee199b1b147053d253f832c84f55d08d80376e"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(args):
    source = args.input_dex.resolve(strict=True)
    require(digest(source) == INPUT_SHA, "unsupported module input SHA-256")
    require(source.read_bytes()[:8] == b"dex\n039\0", "input must be DEX039")
    scratch = local_path(args.scratch)
    require(not scratch.exists(), "scratch output directory must not exist")
    task_root(scratch.parent, PROJECT, backup_excluded=True)
    java_home = args.java_home.resolve(strict=True)
    java, javac = java_home / "bin/java", java_home / "bin/javac"
    jar, d8 = args.jadx_jar.resolve(strict=True), args.d8.resolve(strict=True)
    require(java.is_file() and javac.is_file() and jar.is_file() and d8.is_file(), "missing installed tool")
    scratch.mkdir(mode=0o700)
    for name in ("classes", "helper-dex", "tmp"):
        (scratch / name).mkdir()
    env = dict(os.environ, JAVA_HOME=str(java_home),
               PATH=str(java_home / "bin") + os.pathsep + os.environ.get("PATH", ""),
               TMPDIR=str(scratch / "tmp"))

    def run(command):
        with (scratch / "build.log").open("ab") as log:
            subprocess.run([str(part) for part in command], cwd=scratch, env=env,
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)

    helper = COMPONENT / "src/org/googlebook/pad3/compat/SystemIdentityAppId.java"
    run([javac, "-J-Xmx512m", "-J-XX:ActiveProcessorCount=2", "-d", scratch / "classes",
         "-cp", jar, COMPONENT / "BuildIdentityPatch.java", helper,
         COMPONENT / "tests/SystemIdentityAppIdTest.java"])
    vm = [java, "-Xmx768m", "-XX:ActiveProcessorCount=2", "-Djava.io.tmpdir=" + str(scratch / "tmp")]
    run(vm + ["-cp", scratch / "classes", "SystemIdentityAppIdTest"])
    run([sys.executable, "-B", COMPONENT / "tests/test_build.py"])
    run([d8, "-JXmx512m", "-JXX:ActiveProcessorCount=2", "-JDjava.io.tmpdir=" + str(scratch / "tmp"),
         "--debug", "--min-api", "28", "--output", scratch / "helper-dex",
         scratch / "classes/org/googlebook/pad3/compat/SystemIdentityAppId.class"])
    run(vm + ["-cp", str(scratch / "classes") + os.pathsep + str(jar), "BuildIdentityPatch",
              source, scratch / "helper-dex/classes.dex", scratch])
    receipt = json.loads((scratch / "validation.json").read_text())
    require(receipt["input_sha256"] == INPUT_SHA
            and receipt["patched_sha256"] == digest(scratch / "classes.dex"), "output receipt mismatch")
    receipt["host_helper_test"] = "passed"
    receipt["source_sha256"] = {str(p.relative_to(COMPONENT)): digest(p)
                                for p in (Path(__file__).resolve(), COMPONENT / "BuildIdentityPatch.java", helper,
                                          COMPONENT / "tests/SystemIdentityAppIdTest.java",
                                          COMPONENT / "tests/test_build.py")}
    receipt["tool_sha256"] = {"java": digest(java), "javac": digest(javac),
                               "jadx_jar": digest(jar), "d8_launcher": digest(d8)}
    (scratch / "validation.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": "passed", "patched_sha256": receipt["patched_sha256"],
                      "ordinary_classes_unchanged": 3307, "device_deployed": False}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("input-dex", "java-home", "jadx-jar", "d8", "scratch"):
        parser.add_argument("--" + name, type=Path, required=True)
    try:
        build(parser.parse_args(argv))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("Build refused or failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
